//! # nxc — NetExec-RS CLI Entry Point
//!
//! Pure Rust reimplementation of the NetExec (nxc) CLI.
//! Usage: `nxc <protocol> <targets> [options]`

mod cli;
mod handlers;
mod output;
mod profiling;
mod relay;

use crate::profiling::{log_memory_usage, ScopedTimer};
use anyhow::Result;
use chrono::Utc;
use cli::{build_cli, build_credentials, get_protocol_handler, CODENAME, VERSION};
use colored::Colorize;
use handlers::handle_ai_mode;
use nxc_db::NxcDb;
use nxc_modules::ModuleRegistry;
use nxc_protocols::Protocol;
use nxc_targets::{parse_targets, ExecutionEngine, ExecutionOpts};
use output::{NxcGlobalOutput, NxcOutput};
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    std::panic::set_hook(Box::new(|info| {
        let msg = if let Some(s) = info.payload().downcast_ref::<&str>() {
            *s
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.as_str()
        } else {
            "Unknown panic"
        };

        let loc = if let Some(l) = info.location() {
            format!("{}:{}", l.file(), l.line())
        } else {
            "unknown location".to_string()
        };

        eprintln!(
            "\n{} NetExec-RS encountered a fatal error (panic) at {loc}: {msg}",
            colored::Colorize::red(colored::Colorize::bold("CRITICAL:"))
        );
        eprintln!(
            "{} This is a bug. Please report this to the repository issue tracker.",
            colored::Colorize::red(colored::Colorize::bold("CRITICAL:"))
        );
    }));

    // Load .env file at the very beginning and warn if permissions are unsafe
    if let Ok(path) = dotenvy::dotenv() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(&path) {
                let mode = meta.permissions().mode();
                if mode & 0o077 != 0 {
                    eprintln!("{} WARNING: Your {} file has unsafe permissions ({:o}). It should not be readable by other users.", colored::Colorize::yellow("!"), path.display(), mode);
                }
            }
        }
    }

    let app = build_cli();
    let matches = app.get_matches();

    // ── Setup logging ──
    let log_level = if matches.get_flag("debug") {
        tracing::Level::DEBUG
    } else if matches.get_flag("verbose") {
        tracing::Level::INFO
    } else {
        tracing::Level::WARN
    };

    let json_log = matches.get_flag("json-log");
    let mut _log_guard = None;
    if let Some(log_path) = matches.get_one::<String>("log") {
        let file = std::fs::OpenOptions::new().create(true).append(true).open(log_path)?;
        let (non_blocking, guard) = tracing_appender::non_blocking(file);
        _log_guard = Some(guard);

        use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
        if json_log {
            let file_layer =
                tracing_subscriber::fmt::layer().with_writer(non_blocking).with_ansi(false);
            let json_stdout = tracing_subscriber::fmt::layer().json();
            tracing_subscriber::registry()
                .with(tracing_subscriber::filter::LevelFilter::from(log_level))
                .with(json_stdout)
                .with(file_layer)
                .init();
        } else {
            let file_layer =
                tracing_subscriber::fmt::layer().with_writer(non_blocking).with_ansi(false);
            let stdout_layer = tracing_subscriber::fmt::layer().with_target(false);
            tracing_subscriber::registry()
                .with(tracing_subscriber::filter::LevelFilter::from(log_level))
                .with(stdout_layer)
                .with(file_layer)
                .init();
        }
    } else if json_log {
        tracing_subscriber::fmt().json().with_max_level(log_level).init();
    } else {
        tracing_subscriber::fmt().with_max_level(log_level).with_target(false).init();
    }

    // ── Get the protocol subcommand ──
    let (protocol_name, sub_matches) = match matches.subcommand() {
        Some(("ai", ai_matches)) => {
            let initial_prompt = ai_matches.get_one::<String>("prompt").cloned();
            let provider_name = ai_matches.get_one::<String>("provider").cloned();
            let model = ai_matches.get_one::<String>("model").cloned();

            handle_ai_mode(initial_prompt, provider_name, model).await?;
            return Ok(());
        }
        Some(("relay", relay_matches)) => {
            let default_addr = "0.0.0.0:80".to_string();
            let bind_addr = relay_matches.get_one::<String>("bind-addr").unwrap_or(&default_addr);
            let target = relay_matches.get_one::<String>("target");

            let config = relay::RelayConfig {
                bind_addr: bind_addr.clone(),
                capture_only: target.is_none(),
                relay_target: target.cloned(),
            };

            let server = relay::RelayServer::new(config);
            server.start().await?;
            return Ok(());
        }
        Some((name, sub_m)) => (name, sub_m),
        None => {
            NxcGlobalOutput::banner(VERSION, CODENAME);
            NxcGlobalOutput::info("Use 'nxc <protocol> --help' for protocol-specific options");
            NxcGlobalOutput::info(
                "Available protocols: smb, ssh, ldap, winrm, mssql, rdp, ftp, vnc, wmi, nfs, adb, network",
            );
            return Ok(());
        }
    };

    // ── Handle --list-modules ──
    if sub_matches.try_get_one::<bool>("list-modules").unwrap_or(None).copied().unwrap_or(false) {
        let registry = ModuleRegistry::new();
        let modules = registry.list(Some(protocol_name));
        if modules.is_empty() {
            NxcGlobalOutput::info(&format!("No modules available for protocol '{protocol_name}'"));
        } else {
            NxcGlobalOutput::info(&format!(
                "Modules for '{}' protocol:",
                protocol_name.to_uppercase()
            ));
            for module in modules {
                println!("  {:<20} {}", module.name().bold().cyan(), module.description());
            }
        }
        return Ok(());
    }

    // ── Resolve protocol handler ──
    let protocol = match get_protocol_handler(protocol_name, sub_matches) {
        Some(p) => p,
        None => {
            NxcGlobalOutput::error(&format!("Protocol '{protocol_name}' is not yet implemented"));
            return Ok(());
        }
    };

    // ── Parse targets ──
    let target_specs: Vec<&str> = sub_matches
        .try_get_many::<String>("target")
        .unwrap_or(None)
        .map(|vals| vals.map(std::string::String::as_str).collect())
        .unwrap_or_default();

    let mut all_targets = Vec::new();
    for spec in target_specs {
        match parse_targets(spec) {
            Ok(targets) => all_targets.extend(targets),
            Err(e) => {
                NxcGlobalOutput::error(&format!("Failed to parse target '{spec}': {e}"));
            }
        }
    }

    if all_targets.is_empty() {
        if protocol_name == "network" || protocol_name == "ai" {
            // Provide a dummy target so the ExecutionEngine fires at least once
            all_targets.push(nxc_targets::Target::new(std::net::IpAddr::V4(
                std::net::Ipv4Addr::new(127, 0, 0, 1),
            )));
        } else {
            NxcGlobalOutput::error("No valid targets specified");
            return Ok(());
        }
    }

    // ── Build credentials ──
    // NOTE: --db-creds supplements (or replaces) CLI credentials; the emptiness
    // check is deferred until after the DB load below.
    let mut creds = build_credentials(sub_matches);

    // ── Build execution options ──
    let mut threads = matches.get_one::<usize>("threads").copied().unwrap_or(100);
    let timeout = matches.get_one::<u64>("timeout").copied().unwrap_or(30);
    let mut jitter = matches.get_one::<u64>("jitter").copied();
    let mut shuffle = matches.get_flag("shuffle");
    let proxy = matches.get_one::<String>("proxy").cloned();
    let stealth = matches.get_flag("stealth");
    let continue_on_success = sub_matches
        .try_get_one::<bool>("continue-on-success")
        .unwrap_or(None)
        .copied()
        .unwrap_or(false);
    let no_bruteforce =
        sub_matches.try_get_one::<bool>("no-bruteforce").unwrap_or(None).copied().unwrap_or(false);
    let profiling_enabled = matches.get_flag("profiling");
    let retries = matches.get_one::<u32>("retries").copied().unwrap_or(3);
    let cb_threshold = matches.get_one::<u32>("cb-threshold").copied().unwrap_or(5);

    if profiling_enabled {
        NxcGlobalOutput::info("Performance profiling enabled");
        log_memory_usage("Process Start");
    }

    // Apply stealth macro
    if stealth {
        threads = 1;
        jitter = Some(jitter.unwrap_or(500));
        shuffle = true;
    }

    // ── Build module list ──
    let mut modules: Vec<String> = sub_matches
        .get_many::<String>("module")
        .map(|vals| vals.cloned().collect())
        .unwrap_or_default();

    // Map protocol-specific flags to modules safely
    match protocol_name {
        "vnc" => {
            if sub_matches
                .try_get_one::<bool>("screenshot")
                .unwrap_or(None)
                .copied()
                .unwrap_or(false)
                && !modules.contains(&"screenshot".to_string())
            {
                modules.push("screenshot".to_string());
            }
        }
        "adb" => {
            if sub_matches
                .try_get_one::<bool>("screenshot")
                .unwrap_or(None)
                .copied()
                .unwrap_or(false)
                && !modules.contains(&"adb_screenshot".to_string())
            {
                modules.push("adb_screenshot".to_string());
            }
        }
        "rdp" => {
            // rdp screenshot module pending
        }
        "ldap" => {
            if sub_matches.try_get_one::<bool>("gmsa").unwrap_or(None).copied().unwrap_or(false)
                && !modules.contains(&"gmsa".to_string())
            {
                modules.push("gmsa".to_string());
            }
        }
        "redis" => {
            if sub_matches.try_get_one::<bool>("info").unwrap_or(None).copied().unwrap_or(false)
                && !modules.contains(&"redis_info".to_string())
            {
                modules.push("redis_info".to_string());
            }
        }
        "postgres" | "postgresql" => {
            if sub_matches.try_get_one::<bool>("dbs").unwrap_or(None).copied().unwrap_or(false)
                && !modules.contains(&"pg_enum".to_string())
            {
                modules.push("pg_enum".to_string());
            }
        }
        "mysql" => {
            if sub_matches.try_get_one::<bool>("dbs").unwrap_or(None).copied().unwrap_or(false)
                && !modules.contains(&"mysql_enum".to_string())
            {
                modules.push("mysql_enum".to_string());
            }
        }
        "snmp" => {
            if sub_matches.try_get_one::<bool>("enum").unwrap_or(None).copied().unwrap_or(false)
                && !modules.contains(&"snmp_enum".to_string())
            {
                modules.push("snmp_enum".to_string());
            }
        }
        "docker" => {
            if sub_matches.try_get_one::<bool>("enum").unwrap_or(None).copied().unwrap_or(false)
                && !modules.contains(&"docker_enum".to_string())
            {
                modules.push("docker_enum".to_string());
            }
        }
        "opcua" => {
            if sub_matches.try_get_one::<bool>("enum").unwrap_or(None).copied().unwrap_or(false)
                && !modules.contains(&"opcua_enum".to_string())
            {
                modules.push("opcua_enum".to_string());
            }
        }
        _ => {}
    }

    let mut module_opts = std::collections::HashMap::new();
    if let Some(opts) = sub_matches.try_get_many::<String>("module-options").unwrap_or(None) {
        for opt in opts {
            if let Some((k, v)) = opt.split_once('=') {
                module_opts.insert(k.to_string(), v.to_string());
            }
        }
    }

    let mut insecure = matches.get_flag("insecure")
        || sub_matches.try_get_one::<bool>("insecure").unwrap_or(None).copied().unwrap_or(false);

    // Explicit confirmation for insecure mode in interactive environments
    if insecure {
        use std::io::IsTerminal;
        if std::io::stdout().is_terminal() {
            println!("{} SECURITY WARNING: You have specified --insecure. This disables SSL certificate validation and exposes connections to MITM attacks.", colored::Colorize::yellow("!"));
            print!("Are you sure you want to proceed? [y/N]: ");
            use std::io::Write;
            let _ = std::io::stdout().flush();
            let mut input = String::new();
            if std::io::stdin().read_line(&mut input).is_ok() {
                if !input.trim().eq_ignore_ascii_case("y")
                    && !input.trim().eq_ignore_ascii_case("yes")
                {
                    println!("Aborting.");
                    std::process::exit(1);
                }
            } else {
                insecure = false;
            }
        }
    }
    let verify_ssl = !insecure;
    let explicit_port = sub_matches.try_get_one::<u16>("port").unwrap_or(None).copied();

    let exec_opts = ExecutionOpts {
        threads,
        timeout: Duration::from_secs(timeout),
        jitter_ms: jitter,
        shuffle,
        proxy,
        continue_on_success,
        no_bruteforce,
        modules,
        module_opts,
        verify_ssl,
        gfail_limit: sub_matches.try_get_one::<u32>("gfail-limit").unwrap_or(None).copied(),
        ufail_limit: sub_matches.try_get_one::<u32>("ufail-limit").unwrap_or(None).copied(),
        fail_limit: sub_matches.try_get_one::<u32>("fail-limit").unwrap_or(None).copied(),
        port: explicit_port,
        rate_limit_ms: None,
    };
    // ── Setup Database ──
    let workspace_raw = matches
        .get_one::<String>("workspace")
        .map(std::string::String::as_str)
        .unwrap_or("default");
    let workspace = nxc_reporting::sanitize_workspace_name(workspace_raw);

    // Ensure platform-appropriate .nxc directory exists
    let dot_nxc = if let Ok(custom) = std::env::var("NXC_HOME") {
        std::path::PathBuf::from(custom)
    } else if let Some(legacy) = dirs::home_dir().map(|h| h.join(".nxc")).filter(|p| p.exists()) {
        legacy
    } else if let Some(data_dir) = dirs::data_local_dir() {
        data_dir.join("nxc")
    } else if let Some(config_dir) = dirs::config_dir() {
        config_dir.join("nxc")
    } else {
        std::path::PathBuf::from(".nxc")
    };

    if !dot_nxc.exists() {
        if let Err(e) = std::fs::create_dir_all(&dot_nxc) {
            NxcGlobalOutput::warn(&format!("Failed to create nxc directory at {dot_nxc:?}: {e}"));
        } else {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(mut perms) = std::fs::metadata(&dot_nxc).map(|m| m.permissions()) {
                    perms.set_mode(0o700);
                    let _ = std::fs::set_permissions(&dot_nxc, perms);
                }
            }
        }
    }
    let db_path = dot_nxc.join("nxc.db");

    let db = match NxcDb::new(&db_path, &workspace) {
        Ok(d) => Some(Arc::new(d)),
        Err(e) => {
            NxcGlobalOutput::warn(&format!("Failed to initialize database: {e}"));
            None
        }
    };

    // ── Execution Header ──
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".dimmed()
    );
    NxcGlobalOutput::banner(VERSION, CODENAME);
    if let Some(ref d) = db {
        NxcGlobalOutput::info(&format!("Workspace: {}", d.current_workspace().bold().cyan()));
    }
    NxcGlobalOutput::info(&format!(
        "{} {} | {} {} | {} {} | {} {}",
        "Protocol:".bold().cyan(),
        protocol_name.green(),
        "Targets:".bold().cyan(),
        all_targets.len().to_string().yellow(),
        "Credentials:".bold().cyan(),
        creds.len().to_string().yellow(),
        "Threads:".bold().cyan(),
        threads.to_string().magenta()
    ));

    // ── Load Credentials from DB if requested ──
    if sub_matches.try_get_one::<bool>("db-creds").unwrap_or(None).copied().unwrap_or(false) {
        if let Some(ref d) = db {
            match d.list_credentials() {
                Ok(db_creds) => {
                    for c in db_creds {
                        let mut nxc_cred = nxc_auth::Credentials::default();
                        nxc_cred.domain = c.domain.clone();
                        nxc_cred.username = c.username.clone();
                        nxc_cred.password = c.password.clone();
                        nxc_cred.nt_hash = c.nt_hash.clone();
                        nxc_cred.lm_hash = c.lm_hash.clone();
                        nxc_cred.aes_128_key = c.aes_128.clone();
                        nxc_cred.aes_256_key = c.aes_256.clone();
                        creds.push(nxc_cred);
                    }
                    NxcGlobalOutput::info(&format!(
                        "Loaded {} credentials from database",
                        creds.len()
                    ));
                }
                Err(e) => {
                    NxcGlobalOutput::warn(&format!("Failed to load credentials from DB: {e}"))
                }
            }
        } else {
            NxcGlobalOutput::warn("Database not initialized, cannot load --db-creds");
        }
    }

    // ── Safe-mode guardrail ──
    let safe_mode = matches.get_flag("safe-mode")
        || sub_matches.try_get_one::<bool>("safe-mode").unwrap_or(None).copied().unwrap_or(false);
    if safe_mode {
        NxcGlobalOutput::warn(
            "Safe mode active: limiting execution to single credential pair (spray disabled)",
        );
        if creds.len() > 1 {
            creds.truncate(1);
        }
    }

    // Deferred credential check — must come after --db-creds load
    if creds.is_empty() {
        NxcGlobalOutput::error("No credentials specified");
        return Ok(());
    }

    // ── Run the execution engine ──
    let mut engine = ExecutionEngine::new(exec_opts);

    // Apply resilience settings
    if let Some(manager) = Arc::get_mut(engine.manager_mut()) {
        manager.set_failure_threshold(cb_threshold);
        manager.retry_policy_mut().max_retries = retries;
    }

    if let Some(d) = db {
        engine = engine.with_db(d);
    }

    let _timer =
        if profiling_enabled { Some(ScopedTimer::new("ExecutionEngine::run")) } else { None };

    let results = tokio::select! {
        res = engine.run(protocol, all_targets, creds) => res,
        _ = tokio::signal::ctrl_c() => {
            println!();
            NxcGlobalOutput::warn("Received interrupt signal (Ctrl+C). Finalizing and saving results collected so far...");
            Vec::new()
        }
    };

    if profiling_enabled {
        log_memory_usage("Process End");
    }

    // ── Display results ──
    let port = explicit_port.unwrap_or_else(|| {
        protocol_name.parse::<Protocol>().map(|p| p.default_port()).unwrap_or(0)
    });

    for result in &results {
        let output = NxcOutput::new(protocol_name, &result.target, port, None);

        if result.success {
            if result.admin {
                output.pwned(&format!("{} {}", result.username, result.message));
            } else {
                output.success(&format!("{} {}", result.username, result.message));
            }
        } else {
            output.fail(&format!("{} {}", result.username, result.message));
        }
    }

    // ── Summary ──
    let total = results.len();
    let successes = results.iter().filter(|r| r.success).count();
    let admins = results.iter().filter(|r| r.admin).count();

    println!();
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".dimmed()
    );
    NxcGlobalOutput::info(&format!(
        "🕷 {} {} total, {} successful, {} admin",
        "Mission Result:".bold().cyan(),
        total,
        successes.to_string().green().bold(),
        admins.to_string().yellow().bold()
    ));
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".dimmed()
    );

    // ── Handle Exports ──
    let report = nxc_reporting::Report {
        timestamp: Utc::now().to_rfc3339(),
        protocol: protocol_name.to_string(),
        results: results.clone(),
    };

    // 1. Automatic Workspace Reporting
    let ws_reports_dir = dot_nxc.join("workspaces").join(workspace).join("reports");
    match std::fs::create_dir_all(&ws_reports_dir) {
        Ok(_) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(mut perms) = std::fs::metadata(&ws_reports_dir).map(|m| m.permissions()) {
                    perms.set_mode(0o700);
                    let _ = std::fs::set_permissions(&ws_reports_dir, perms);
                }
            }
            let filename =
                format!("report_{}_{}.json", protocol_name, Utc::now().format("%Y%m%d_%H%M%S"));
            let report_path = ws_reports_dir.join(filename);
            if let Err(e) = nxc_reporting::export_json(report_path.to_str().unwrap_or(""), &report)
            {
                NxcGlobalOutput::warn(&format!("Failed to save workspace report: {e}"));
            }
        }
        Err(e) => {
            NxcGlobalOutput::warn(&format!("Failed to create reports directory: {e}"));
        }
    }

    // Automated raw result logging if requested
    if let Some(log_res_path) = sub_matches.try_get_one::<String>("log-results").unwrap_or(None) {
        if let Err(e) = nxc_reporting::export_ndjson(log_res_path, &results) {
            NxcGlobalOutput::warn(&format!("Failed to write results log: {e}"));
        }
    }

    // 2. User-requested Exports
    if let Some(format) = sub_matches.try_get_one::<String>("export").unwrap_or(None) {
        let mut path = sub_matches
            .get_one::<String>("export-path")
            .ok_or_else(|| anyhow::anyhow!("--export-path is required when using --export"))?
            .to_string();
        if !path.ends_with(format) {
            path = format!("{path}.{format}");
        }

        let res = match format.as_str() {
            "json" => nxc_reporting::export_json(&path, &report),
            "csv" => nxc_reporting::export_csv(&path, &results),
            "html" => nxc_reporting::export_html(&path, &report),
            "pdf" => nxc_reporting::export_pdf(&path, &report),
            "xml" => nxc_reporting::export_xml(&path, &report),
            "markdown" | "md" => nxc_reporting::export_markdown(&path, &report),
            "ndjson" => nxc_reporting::export_ndjson(&path, &results),
            unknown => anyhow::bail!("Unknown export format: {unknown}"),
        };

        match res {
            Ok(_) => NxcGlobalOutput::info(&format!("Results exported to {}", path.bold().green())),
            Err(e) => NxcGlobalOutput::warn(&format!("Failed to export results: {e}")),
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const TEST_MOCK_PASS_A: &str = "MOCK_SYNTHETIC_TEST_PW_ALPHA_123!";
    const TEST_MOCK_PASS_B: &str = "MOCK_SYNTHETIC_TEST_PW_BETA_456!";

    #[test]
    fn test_cli_parse_smb_basic() {
        let app = build_cli();
        let matches = app.get_matches_from(vec![
            "nxc",
            "smb",
            "192.168.1.0/24",
            "-u",
            "admin",
            "-p",
            TEST_MOCK_PASS_A,
        ]);
        let (proto, sub_m) = matches.subcommand().unwrap();
        assert_eq!(proto, "smb");
        let targets: Vec<&String> = sub_m.get_many::<String>("target").unwrap().collect();
        assert_eq!(targets, vec!["192.168.1.0/24"]);
        let users: Vec<&String> = sub_m.get_many::<String>("username").unwrap().collect();
        assert_eq!(users, vec!["admin"]);
    }

    #[test]
    fn test_cli_parse_ssh_with_key() {
        let app = build_cli();
        let matches = app.get_matches_from(vec![
            "nxc",
            "ssh",
            "10.0.0.1",
            "-u",
            "root",
            "--key-file",
            "/path/to/key",
        ]);
        let (proto, sub_m) = matches.subcommand().unwrap();
        assert_eq!(proto, "ssh");
        assert_eq!(sub_m.get_one::<String>("key-file").unwrap(), "/path/to/key");
    }

    #[test]
    fn test_cli_parse_multiple_targets() {
        let app = build_cli();
        let matches = app.get_matches_from(vec![
            "nxc",
            "smb",
            "192.168.1.10",
            "192.168.2.0/24",
            "-u",
            "admin",
            "-p",
            TEST_MOCK_PASS_A,
        ]);
        let (_, sub_m) = matches.subcommand().unwrap();
        let targets = sub_m.get_many::<String>("target").unwrap();
        assert_eq!(targets.count(), 2);
    }

    #[test]
    fn test_build_credentials_spray_mode() {
        let app = build_cli();
        let matches = app.get_matches_from(vec![
            "nxc",
            "smb",
            "10.0.0.1",
            "-u",
            "admin",
            "user",
            "-p",
            TEST_MOCK_PASS_A,
            TEST_MOCK_PASS_B,
        ]);
        let (_, sub_m) = matches.subcommand().unwrap();
        let creds = build_credentials(sub_m);
        // 2 users × 2 passwords = 4 creds
        assert_eq!(creds.len(), 4);
    }

    #[test]
    fn test_build_credentials_no_bruteforce() {
        let app = build_cli();
        let matches = app.get_matches_from(vec![
            "nxc",
            "smb",
            "10.0.0.1",
            "-u",
            "admin",
            "user",
            "-p",
            TEST_MOCK_PASS_A,
            TEST_MOCK_PASS_B,
            "--no-bruteforce",
        ]);
        let (_, sub_m) = matches.subcommand().unwrap();
        let creds = build_credentials(sub_m);
        // 1:1 pairing = 2 creds
        assert_eq!(creds.len(), 2);
    }

    #[test]
    fn test_build_credentials_null_session() {
        let app = build_cli();
        let matches = app.get_matches_from(vec!["nxc", "smb", "10.0.0.1"]);
        let (_, sub_m) = matches.subcommand().unwrap();
        let creds = build_credentials(sub_m);
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].username, "");
    }

    #[test]
    fn test_build_credentials_deduplication() {
        let app = build_cli();
        let matches = app.get_matches_from(vec![
            "nxc",
            "smb",
            "10.0.0.1",
            "-u",
            "admin",
            "admin",
            "-p",
            TEST_MOCK_PASS_A,
            TEST_MOCK_PASS_A,
        ]);
        let (_, sub_m) = matches.subcommand().unwrap();
        let creds = build_credentials(sub_m);
        // Duplicate user/pass should be collapsed to 1 credential pair
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].username, "admin");
    }
}
