//! # nxc — NetExec-RS CLI Entry Point
//!
//! Pure Rust reimplementation of the NetExec (nxc) CLI.
//! Usage: `nxc <protocol> <targets> [options]`

mod output;
mod telegram;

use anyhow::Result;
use clap::{Arg, ArgAction, Command};
use colored::Colorize;
use nxc_auth::Credentials;
use nxc_modules::ModuleRegistry;
use nxc_protocols::Protocol;
use nxc_targets::{parse_targets, ExecutionEngine, ExecutionOpts};
use output::{NxcGlobalOutput, NxcOutput};
use std::sync::Arc;
use std::time::Duration;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const CODENAME: &str = "Rusty-Reaper";

fn build_cli() -> Command {
    let banner = format!(
        r#"
     .   .
    .|   |.     _   _          _     _____
    ||   ||    | \ | |   ___  | |_  | ____| __  __   ___    ___
    \\( )//    |  \| |  / _ \ | __| |  _|   \ \/ /  / _ \  / __|
    .=[ ]=.    | |\  | |  __/ | |_  | |___   >  <  |  __/ | (__
   / /`-`\ \   |_| \_|  \___|  \__| |_____| /_/\_\  \___|  \___|
   ` \   / `
     `   `

    NetExec-RS — The Network Execution Tool (Pure Rust)

    Version : {}
    Codename: {}
"#,
        VERSION, CODENAME
    );

    // ── Standard auth arguments (shared across all protocols) ──
    let auth_args = vec![
        Arg::new("target")
            .help("Target IP(s), range(s), CIDR(s), hostname(s), or file(s)")
            .required(true)
            .num_args(1..)
            .index(1),
        Arg::new("username")
            .short('u')
            .long("username")
            .help("Username(s) or file(s) containing usernames")
            .num_args(1..),
        Arg::new("password")
            .short('p')
            .long("password")
            .help("Password(s) or file(s) containing passwords")
            .num_args(1..),
        Arg::new("hash")
            .short('H')
            .long("hash")
            .help("NTLM hash(es) for Pass-the-Hash")
            .num_args(1..),
        Arg::new("no-bruteforce")
            .long("no-bruteforce")
            .help("No spray when using files (user1 => pass1, user2 => pass2)")
            .action(ArgAction::SetTrue),
        Arg::new("continue-on-success")
            .long("continue-on-success")
            .help("Continue auth attempts even after successes")
            .action(ArgAction::SetTrue),
        Arg::new("gfail-limit")
            .long("gfail-limit")
            .help("Max global failed login attempts")
            .value_parser(clap::value_parser!(u32)),
        Arg::new("ufail-limit")
            .long("ufail-limit")
            .help("Max failed login attempts per username")
            .value_parser(clap::value_parser!(u32)),
        Arg::new("fail-limit")
            .long("fail-limit")
            .help("Max failed login attempts per host")
            .value_parser(clap::value_parser!(u32)),
    ];

    // ── Kerberos arguments ──
    let kerberos_args = vec![
        Arg::new("kerberos")
            .short('k')
            .long("kerberos")
            .help("Use Kerberos authentication")
            .action(ArgAction::SetTrue),
        Arg::new("use-kcache")
            .long("use-kcache")
            .help("Use Kerberos auth from ccache file (KRB5CCNAME)")
            .action(ArgAction::SetTrue),
        Arg::new("aes-key")
            .long("aes-key")
            .help("AES key for Kerberos authentication (128 or 256 bits)")
            .num_args(1),
        Arg::new("kdc-host")
            .long("kdc-host")
            .help("FQDN of the domain controller"),
    ];

    // ── Module arguments ──
    let module_args = vec![
        Arg::new("module")
            .short('M')
            .long("module")
            .help("Module to use")
            .num_args(1),
        Arg::new("module-options")
            .short('o')
            .help("Module options (KEY=VALUE)")
            .num_args(1..),
        Arg::new("list-modules")
            .short('L')
            .long("list-modules")
            .help("List available modules")
            .action(ArgAction::SetTrue),
        Arg::new("show-module-options")
            .long("options")
            .help("Display module options")
            .action(ArgAction::SetTrue),
    ];

    // ── Create protocol subcommands ──
    let smb_cmd = Command::new("smb")
        .about("SMB protocol (port 445)")
        .args(&auth_args)
        .args(&kerberos_args)
        .args(&module_args)
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("445")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("shares")
                .long("shares")
                .help("Enumerate shares and access")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("sessions")
                .long("sessions")
                .help("Enumerate active sessions")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("disks")
                .long("disks")
                .help("Enumerate disks")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("loggedon-users")
                .long("loggedon-users")
                .help("Enumerate logged-on users")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("users")
                .long("users")
                .help("Enumerate users")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("groups")
                .long("groups")
                .help("Enumerate groups")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("pass-pol")
                .long("pass-pol")
                .help("Dump password policy")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("exec-method")
                .long("exec-method")
                .help("Execution method (smbexec, atexec, wmiexec, mmcexec)")
                .value_parser(["smbexec", "atexec", "wmiexec", "mmcexec"])
                .default_value("wmiexec"),
        )
        .arg(
            Arg::new("exec-command")
                .short('x')
                .long("exec-command")
                .help("Execute command on target"),
        )
        .arg(
            Arg::new("exec-command-ps")
                .short('X')
                .long("exec-command-ps")
                .help("Execute PowerShell command on target"),
        );

    let ssh_cmd = Command::new("ssh")
        .about("SSH protocol (port 22)")
        .args(&auth_args)
        .args(&module_args)
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("22")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("key-file")
                .long("key-file")
                .help("SSH private key file for authentication"),
        )
        .arg(
            Arg::new("exec-command")
                .short('x')
                .long("exec-command")
                .help("Execute command on target"),
        )
        .arg(
            Arg::new("sudo-check")
                .long("sudo-check")
                .help("Check for sudo privileges")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("ssh-timeout")
                .long("ssh-timeout")
                .help("SSH connection timeout in seconds")
                .default_value("10")
                .value_parser(clap::value_parser!(u64)),
        );

    let ldap_cmd = Command::new("ldap")
        .about("LDAP protocol (port 389/636)")
        .args(&auth_args)
        .args(&kerberos_args)
        .args(&module_args)
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("389")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("ldaps")
                .long("ldaps")
                .help("Use LDAPS (port 636)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("kerberoasting")
                .long("kerberoasting")
                .help("Perform Kerberoasting and save output to file")
                .num_args(0..=1)
                .default_missing_value("kerberoast.txt"),
        )
        .arg(
            Arg::new("asreproasting")
                .long("asreproasting")
                .help("Perform ASREProasting and save output to file")
                .num_args(0..=1)
                .default_missing_value("asreproast.txt"),
        )
        .arg(
            Arg::new("users")
                .long("users")
                .help("Enumerate domain users")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("groups")
                .long("groups")
                .help("Enumerate domain groups")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("gmsa")
                .long("gmsa")
                .help("Enumerate gMSA passwords")
                .action(ArgAction::SetTrue),
        );

    let winrm_cmd = Command::new("winrm")
        .about("WinRM protocol (port 5985/5986)")
        .args(&auth_args)
        .args(&kerberos_args)
        .args(&module_args)
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("5985")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("ssl")
                .long("ssl")
                .help("Use HTTPS (port 5986)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("exec-command")
                .short('x')
                .long("exec-command")
                .help("Execute command on target"),
        )
        .arg(
            Arg::new("exec-command-ps")
                .short('X')
                .long("exec-command-ps")
                .help("Execute PowerShell command on target"),
        );

    let mssql_cmd = Command::new("mssql")
        .about("MSSQL protocol (port 1433)")
        .args(&auth_args)
        .args(&kerberos_args)
        .args(&module_args)
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("1433")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("query")
                .short('q')
                .long("query")
                .help("Execute SQL query"),
        )
        .arg(
            Arg::new("exec-command")
                .short('x')
                .long("exec-command")
                .help("Execute command via xp_cmdshell"),
        );

    let rdp_cmd = Command::new("rdp")
        .about("RDP protocol (port 3389)")
        .args(&auth_args)
        .args(&kerberos_args)
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("3389")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("screenshot")
                .long("screenshot")
                .help("Take screenshot of the RDP session")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("nla")
                .long("nla")
                .help("Use Network Level Authentication")
                .action(ArgAction::SetTrue),
        );

    let ftp_cmd = Command::new("ftp")
        .about("FTP protocol (port 21)")
        .args(&auth_args)
        .args(&module_args)
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("21")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("ls")
                .long("ls")
                .help("List directory contents")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("get")
                .long("get")
                .help("Download a file from FTP server"),
        )
        .arg(
            Arg::new("put")
                .long("put")
                .help("Upload a file to FTP server"),
        );

    let vnc_cmd = Command::new("vnc")
        .about("VNC protocol (port 5900)")
        .args(&auth_args)
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("5900")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("screenshot")
                .long("screenshot")
                .help("Take screenshot of the VNC session")
                .action(ArgAction::SetTrue),
        );

    let wmi_cmd = Command::new("wmi")
        .about("WMI protocol (port 135)")
        .args(&auth_args)
        .args(&kerberos_args)
        .args(&module_args)
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("135")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("exec-command")
                .short('x')
                .long("exec-command")
                .help("Execute command via WMI"),
        );

    let nfs_cmd = Command::new("nfs")
        .about("NFS protocol (port 2049)")
        .args(&auth_args)
        .args(&module_args)
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("2049")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("enum-shares")
                .long("enum-shares")
                .help("Enumerate NFS exports")
                .action(ArgAction::SetTrue),
        );

    let adb_cmd = Command::new("adb")
        .about("ADB protocol (Android Debug Bridge, port 5555)")
        .args(&auth_args)
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("5555")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("exec-command")
                .short('x')
                .long("exec-command")
                .help("Execute command on Android target"),
        );

    let http_cmd = Command::new("http")
        .about("HTTP protocol (Web Request & Auth Brute-force)")
        .args(&auth_args)
        .args(&module_args)
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("80")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("ssl")
                .long("ssl")
                .help("Connect via HTTPS instead of HTTP")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("verify-ssl")
                .long("verify-ssl")
                .help("Verify HTTPS certificates (default is to ignore cert errors)")
                .action(ArgAction::SetTrue),
        );

    let wifi_cmd = Command::new("wifi")
        .about("WiFi protocol (Network Discovery, Scanning, and Connection)")
        .args(&auth_args)
        .args(&module_args)
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("0")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("scan")
                .long("scan")
                .help("Scan for nearby WiFi networks")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("connect")
                .long("connect")
                .help("Connect to a specific SSID")
                .num_args(1),
        )
        .arg(
            Arg::new("devices")
                .long("devices")
                .help("Sweep local LAN for connected devices (ARP)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("profiles")
                .long("profiles")
                .help("List saved WiFi profiles")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("dump")
                .long("dump")
                .help("Dump cleartext passwords for all saved WiFi profiles")
                .action(ArgAction::SetTrue),
        );

    Command::new("nxc")
        .about(banner)
        .version(VERSION)
        .arg(
            Arg::new("threads")
                .short('t')
                .long("threads")
                .help("Number of concurrent threads")
                .default_value("256")
                .value_parser(clap::value_parser!(usize))
                .global(true),
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .help("Max timeout in seconds per thread")
                .default_value("30")
                .value_parser(clap::value_parser!(u64))
                .global(true),
        )
        .arg(
            Arg::new("jitter")
                .long("jitter")
                .help("Random delay between each authentication (ms)")
                .value_parser(clap::value_parser!(u64))
                .global(true),
        )
        .arg(
            Arg::new("verbose")
                .long("verbose")
                .help("Enable verbose output")
                .action(ArgAction::SetTrue)
                .global(true),
        )
        .arg(
            Arg::new("debug")
                .long("debug")
                .help("Enable debug level information")
                .action(ArgAction::SetTrue)
                .global(true),
        )
        .arg(
            Arg::new("no-progress")
                .long("no-progress")
                .help("Do not display progress bar during scan")
                .action(ArgAction::SetTrue)
                .global(true),
        )
        .arg(
            Arg::new("log")
                .long("log")
                .help("Export results to a custom file")
                .global(true),
        )
        .subcommand(smb_cmd)
        .subcommand(ssh_cmd)
        .subcommand(ldap_cmd)
        .subcommand(winrm_cmd)
        .subcommand(mssql_cmd)
        .subcommand(rdp_cmd)
        .subcommand(ftp_cmd)
        .subcommand(vnc_cmd)
        .subcommand(wmi_cmd)
        .subcommand(nfs_cmd)
        .subcommand(adb_cmd)
        .subcommand(wifi_cmd)
        .subcommand(http_cmd)
        .subcommand(
            Command::new("telegram")
                .about("Start the NetExec-RS Telegram bot server")
                .arg(
                    Arg::new("token")
                        .long("token")
                        .env("TELEGRAM_BOT_TOKEN")
                        .help("Telegram bot token")
                        .required(true),
                ),
        )
}

/// Build credentials from CLI arguments.
fn build_credentials(matches: &clap::ArgMatches) -> Vec<Credentials> {
    let mut creds = Vec::new();

    let usernames: Vec<&str> = matches
        .get_many::<String>("username")
        .map(|vals| vals.map(|s| s.as_str()).collect())
        .unwrap_or_default();

    let passwords: Vec<&str> = matches
        .get_many::<String>("password")
        .map(|vals| vals.map(|s| s.as_str()).collect())
        .unwrap_or_default();

    let hashes: Vec<&str> = matches
        .get_many::<String>("hash")
        .map(|vals| vals.map(|s| s.as_str()).collect())
        .unwrap_or_default();

    let no_bruteforce = matches.get_flag("no-bruteforce");

    // If no credentials provided, use null session
    if usernames.is_empty() && passwords.is_empty() && hashes.is_empty() {
        creds.push(Credentials::null_session());
        return creds;
    }

    if no_bruteforce {
        // Pair usernames with passwords 1:1
        let max_len = usernames.len().max(passwords.len()).max(hashes.len());
        for i in 0..max_len {
            let user = usernames.get(i).copied().unwrap_or("");
            if let Some(hash) = hashes.get(i) {
                creds.push(Credentials::nt_hash(user, hash, None));
            } else {
                let pass = passwords.get(i).copied().unwrap_or("");
                creds.push(Credentials::password(user, pass, None));
            }
        }
    } else {
        // Spray mode: every user × every password/hash
        for user in &usernames {
            if !hashes.is_empty() {
                for hash in &hashes {
                    creds.push(Credentials::nt_hash(user, hash, None));
                }
            }
            if !passwords.is_empty() {
                for pass in &passwords {
                    creds.push(Credentials::password(user, pass, None));
                }
            }
            // If only usernames given (no pass/hash), try empty password
            if passwords.is_empty() && hashes.is_empty() {
                creds.push(Credentials::password(user, "", None));
            }
        }
    }

    creds
}

/// Resolve the protocol handler from the subcommand name.
fn get_protocol_handler(
    protocol_name: &str,
    sub_matches: &clap::ArgMatches,
) -> Option<Arc<dyn nxc_protocols::NxcProtocol>> {
    match protocol_name {
        "smb" => Some(Arc::new(nxc_protocols::smb::SmbProtocol::new())),
        "ssh" => Some(Arc::new(nxc_protocols::ssh::SshProtocol::new())),
        "ldap" => Some(Arc::new(nxc_protocols::ldap::LdapProtocol::new())),
        "winrm" => Some(Arc::new(nxc_protocols::winrm::WinrmProtocol::new())),
        "mssql" => Some(Arc::new(nxc_protocols::mssql::MssqlProtocol::new())),
        "rdp" => Some(Arc::new(nxc_protocols::rdp::RdpProtocol::new())),
        "wmi" => Some(Arc::new(nxc_protocols::wmi::WmiProtocol::new())),
        "ftp" => Some(Arc::new(nxc_protocols::ftp::FtpProtocol::new())),
        "vnc" => Some(Arc::new(nxc_protocols::vnc::VncProtocol::new())),
        "nfs" => Some(Arc::new(nxc_protocols::nfs::NfsProtocol::new())),
        "adb" => Some(Arc::new(nxc_protocols::adb::AdbProtocol::new())),
        "wifi" => {
            let scan = sub_matches.get_flag("scan");
            let connect = sub_matches.get_one::<String>("connect").cloned();
            let devices = sub_matches.get_flag("devices");
            let profiles = sub_matches.get_flag("profiles");
            let dump = sub_matches.get_flag("dump");
            Some(Arc::new(nxc_protocols::wifi::WifiProtocol::new(
                scan, connect, devices, profiles, dump,
            )))
        }
        "http" => {
            let ssl = sub_matches.get_flag("ssl");
            let verify_ssl = sub_matches.get_flag("verify-ssl");
            Some(Arc::new(nxc_protocols::http::HttpProtocol::new(
                ssl, verify_ssl,
            )))
        }
        // Future protocols will be added here:
        _ => None,
    }
}

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

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(false)
        .init();

    // ── Get the protocol subcommand ──
    let (protocol_name, sub_matches) = match matches.subcommand() {
        Some(("telegram", sub_m)) => {
            // Set the token in env if provided via CLI override
            if let Some(token) = sub_m.get_one::<String>("token") {
                std::env::set_var("TELEGRAM_BOT_TOKEN", token);
            }
            
            telegram::start_bot().await?;
            return Ok(());
        }
        Some((name, sub_m)) => (name, sub_m),
        None => {
            NxcGlobalOutput::banner();
            NxcGlobalOutput::info(&format!("NetExec-RS v{} — {}", VERSION, CODENAME));
            NxcGlobalOutput::info("Use 'nxc <protocol> --help' for protocol-specific options");
            NxcGlobalOutput::info(
                "Available protocols: smb, ssh, ldap, winrm, mssql, rdp, ftp, vnc, wmi, nfs, adb",
            );
            return Ok(());
        }
    };

    // ── Handle --list-modules ──
    if sub_matches.get_flag("list-modules") {
        let registry = ModuleRegistry::new();
        let modules = registry.list(Some(protocol_name));
        if modules.is_empty() {
            NxcGlobalOutput::info(&format!(
                "No modules available for protocol '{}'",
                protocol_name
            ));
        } else {
            NxcGlobalOutput::info(&format!(
                "Modules for '{}' protocol:",
                protocol_name.to_uppercase()
            ));
            for module in modules {
                println!(
                    "  {:<20} {}",
                    module.name().bold().cyan(),
                    module.description()
                );
            }
        }
        return Ok(());
    }

    // ── Resolve protocol handler ──
    let protocol = match get_protocol_handler(protocol_name, sub_matches) {
        Some(p) => p,
        None => {
            NxcGlobalOutput::error(&format!(
                "Protocol '{}' is not yet implemented",
                protocol_name
            ));
            return Ok(());
        }
    };

    // ── Parse targets ──
    let target_specs: Vec<&str> = sub_matches
        .get_many::<String>("target")
        .map(|vals| vals.map(|s| s.as_str()).collect())
        .unwrap_or_default();

    let mut all_targets = Vec::new();
    for spec in target_specs {
        match parse_targets(spec) {
            Ok(targets) => all_targets.extend(targets),
            Err(e) => {
                NxcGlobalOutput::error(&format!("Failed to parse target '{}': {}", spec, e));
            }
        }
    }

    if all_targets.is_empty() {
        NxcGlobalOutput::error("No valid targets specified");
        return Ok(());
    }

    // ── Build credentials ──
    let creds = build_credentials(sub_matches);
    if creds.is_empty() {
        NxcGlobalOutput::error("No credentials specified");
        return Ok(());
    }

    // ── Build execution options ──
    let threads = matches.get_one::<usize>("threads").copied().unwrap_or(256);
    let timeout = matches.get_one::<u64>("timeout").copied().unwrap_or(30);
    let jitter = matches.get_one::<u64>("jitter").copied();
    let continue_on_success = sub_matches.get_flag("continue-on-success");
    let no_bruteforce = sub_matches.get_flag("no-bruteforce");

    let exec_opts = ExecutionOpts {
        threads,
        timeout: Duration::from_secs(timeout),
        jitter_ms: jitter,
        continue_on_success,
        no_bruteforce,
    };

    // ── Print banner ──
    NxcGlobalOutput::banner();
    NxcGlobalOutput::info(&format!("NetExec-RS v{} — {}", VERSION, CODENAME));
    NxcGlobalOutput::info(&format!(
        "Protocol: {} | Targets: {} | Credentials: {} | Threads: {}",
        protocol_name.to_uppercase().bold(),
        all_targets.len(),
        creds.len(),
        threads
    ));

    // ── Run the execution engine ──
    let engine = ExecutionEngine::new(exec_opts);
    let results = engine.run(protocol, all_targets, creds).await;

    // ── Display results ──
    let port = sub_matches
        .get_one::<u16>("port")
        .copied()
        .unwrap_or_else(|| {
            Protocol::from_str(protocol_name)
                .map(|p| p.default_port())
                .unwrap_or(0)
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
    NxcGlobalOutput::info(&format!(
        "Completed: {} total, {} successful, {} admin",
        total,
        successes.to_string().green().bold(),
        admins.to_string().yellow().bold()
    ));

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
        let targets: Vec<&String> = sub_m.get_many::<String>("target").unwrap().collect();
        assert_eq!(targets.len(), 2);
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
