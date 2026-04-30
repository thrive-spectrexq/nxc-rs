//! # nxc — NetExec-RS CLI Entry Point
//!
//! Pure Rust reimplementation of the NetExec (nxc) CLI.
//! Usage: `nxc <protocol> <targets> [options]`

mod cli;
mod handlers;
mod output;
mod profiling;
mod relay;
mod reporting;

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
    // Load .env file at the very beginning
    let _ = dotenvy::dotenv();

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

    tracing_subscriber::fmt().with_max_level(log_level).with_target(false).init();

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
            let bind_addr = relay_matches
                .get_one::<String>("bind-addr")
                .expect("clap ensures bind-addr is present via default_value");

            let config = relay::RelayConfig {
                bind_addr: bind_addr.clone(),
                relay_target: relay_matches.get_one::<String>("target").cloned(),
                capture_only: relay_matches.get_one::<String>("target").is_none(),
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
    if sub_matches.get_flag("list-modules") {
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
        .get_many::<String>("target")
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
        NxcGlobalOutput::error("No valid targets specified");
        return Ok(());
    }

    // ── Build credentials ──
    let mut creds = build_credentials(sub_matches);
    if creds.is_empty() {
        NxcGlobalOutput::error("No credentials specified");
        return Ok(());
    }

    // ── Build execution options ──
    let mut threads = matches.get_one::<usize>("threads").copied().unwrap_or(256);
    let timeout = matches.get_one::<u64>("timeout").copied().unwrap_or(30);
    let mut jitter = matches.get_one::<u64>("jitter").copied();
    let mut shuffle = matches.get_flag("shuffle");
    let proxy = matches.get_one::<String>("proxy").cloned();
    let stealth = matches.get_flag("stealth");
    let continue_on_success = sub_matches.get_flag("continue-on-success");
    let no_bruteforce = sub_matches.get_flag("no-bruteforce");
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
            if sub_matches.get_flag("screenshot") && !modules.contains(&"screenshot".to_string()) {
                modules.push("screenshot".to_string());
            }
        }
        "adb" => {
            if sub_matches.get_flag("screenshot")
                && !modules.contains(&"adb_screenshot".to_string())
            {
                modules.push("adb_screenshot".to_string());
            }
        }
        "rdp" => {
            // rdp screenshot module pending
        }
        "ldap" => {
            if sub_matches.get_flag("gmsa") && !modules.contains(&"gmsa".to_string()) {
                modules.push("gmsa".to_string());
            }
        }
        "redis" => {
            if sub_matches.get_flag("info") && !modules.contains(&"redis_info".to_string()) {
                modules.push("redis_info".to_string());
            }
        }
        "postgres" | "postgresql" => {
            if sub_matches.get_flag("dbs") && !modules.contains(&"pg_enum".to_string()) {
                modules.push("pg_enum".to_string());
            }
        }
        "mysql" => {
            if sub_matches.get_flag("dbs") && !modules.contains(&"mysql_enum".to_string()) {
                modules.push("mysql_enum".to_string());
            }
        }
        "snmp" => {
            if sub_matches.get_flag("enum") && !modules.contains(&"snmp_enum".to_string()) {
                modules.push("snmp_enum".to_string());
            }
        }
        "docker" => {
            if sub_matches.get_flag("enum") && !modules.contains(&"docker_enum".to_string()) {
                modules.push("docker_enum".to_string());
            }
        }
        "opcua" => {
            if sub_matches.get_flag("enum") && !modules.contains(&"opcua_enum".to_string()) {
                // For OPC-UA, we map 'enum' to a stub if we want module isolation,
                // but NxcEngine will call protocol.execute() by default?
                // Actually, let's just mark it.
            }
        }
        _ => {}
    }

    let mut module_opts = std::collections::HashMap::new();
    if let Some(opts) = sub_matches.get_many::<String>("module-options") {
        for opt in opts {
            if let Some((k, v)) = opt.split_once('=') {
                module_opts.insert(k.to_string(), v.to_string());
            }
        }
    }

    let verify_ssl = sub_matches.get_flag("verify-ssl");

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
        gfail_limit: sub_matches.get_one::<u32>("gfail-limit").copied(),
        ufail_limit: sub_matches.get_one::<u32>("ufail-limit").copied(),
        fail_limit: sub_matches.get_one::<u32>("fail-limit").copied(),
    };

    // ── Setup Database ──
    let workspace = matches
        .get_one::<String>("workspace")
        .map(std::string::String::as_str)
        .unwrap_or("default");

    // Ensure .nxc directory exists in home or current dir
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    let dot_nxc = std::path::PathBuf::from(home).join(".nxc");
    if !dot_nxc.exists() {
        if let Err(e) = std::fs::create_dir_all(&dot_nxc) {
            NxcGlobalOutput::warn(&format!("Failed to create .nxc directory: {e}"));
        }
    }
    let db_path = dot_nxc.join("nxc.db");

    let db = match NxcDb::new(&db_path, workspace) {
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
    if sub_matches.get_flag("db-creds") {
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

    let results = engine.run(protocol, all_targets, creds).await;

    if profiling_enabled {
        log_memory_usage("Process End");
    }

    // ── Display results ──
    let port = sub_matches.get_one::<u16>("port").copied().unwrap_or_else(|| {
        Protocol::from_str(protocol_name).map(|p| p.default_port()).unwrap_or(0)
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
    let report = reporting::Report {
        timestamp: Utc::now().to_rfc3339(),
        protocol: protocol_name.to_string(),
        results: results.clone(),
    };

    // 1. Automatic Workspace Reporting
    let ws_reports_dir = dot_nxc.join("workspaces").join(workspace).join("reports");
    match std::fs::create_dir_all(&ws_reports_dir) {
        Ok(_) => {
            let filename =
                format!("report_{}_{}.json", protocol_name, Utc::now().format("%Y%m%d_%H%M%S"));
            let report_path = ws_reports_dir.join(filename);
            if let Err(e) = reporting::export_json(
                report_path.to_str().unwrap_or_else(|| panic!("report_path is invalid utf-8")),
                &report,
            ) {
                NxcGlobalOutput::warn(&format!("Failed to save workspace report: {e}"));
            }
        }
        Err(e) => {
            NxcGlobalOutput::warn(&format!("Failed to create reports directory: {e}"));
        }
    }

    // 2. User-requested Exports
    if let Some(format) = sub_matches.get_one::<String>("export") {
        let mut path = sub_matches
            .get_one::<String>("export-path")
            .ok_or_else(|| anyhow::anyhow!("--export-path is required when using --export"))?
            .to_string();
        if !path.ends_with(format) {
            path = format!("{path}.{format}");
        }

        let res = match format.as_str() {
            "json" => reporting::export_json(&path, &report),
            "csv" => reporting::export_csv(&path, &results),
            "html" => reporting::export_html(&path, &report),
            "md" => reporting::export_markdown(&path, &report),
            "ndjson" => reporting::export_ndjson(&path, &results),
            "xml" => reporting::export_xml(&path, &report),
            _ => unreachable!(),
        };

        match res {
            Ok(_) => NxcGlobalOutput::info(&format!("Results exported to {}", path.bold().green())),
            Err(e) => NxcGlobalOutput::warn(&format!("Failed to export results: {e}")),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
            "Password123!",
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
            "pass",
        ]);
        let (_, sub_m) = matches.subcommand().unwrap();
        let targets = sub_m.get_many::<String>("target").unwrap();
        assert_eq!(targets.count(), 2);
    }

    #[test]
    fn test_build_credentials_spray_mode() {
        let app = build_cli();
        let matches = app.get_matches_from(vec![
            "nxc", "smb", "10.0.0.1", "-u", "admin", "user", "-p", "pass1", "pass2",
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
            "pass1",
            "pass2",
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
}
