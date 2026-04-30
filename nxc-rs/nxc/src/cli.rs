use clap::{Arg, ArgAction, Command};
use colored::Colorize;
use nxc_auth::Credentials;
use std::sync::Arc;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const CODENAME: &str = "Rusty-Reaper";

pub fn build_cli() -> Command {
    let spider = format!(
        r#"
           {}   {}
          {}   {}
          {}   {}
          {}( ){}
          {}={ }={}
         {} {} {}
         {} {} {}
           {}   {}
"#,
        ".".cyan().bold(),
        ".".cyan().bold(),
        ".|".cyan().bold(),
        "|.".cyan().bold(),
        "||".cyan().bold(),
        "||".cyan().bold(),
        "\\\\".cyan().bold(),
        "//".cyan().bold(),
        ".[".cyan().bold(),
        " ".white().bold(),
        "].".cyan().bold(),
        "/ /".cyan().bold(),
        "˙-˙".yellow().bold(),
        "\\ \\".cyan().bold(),
        "˙".cyan().bold(),
        "\\ /".yellow().bold(),
        "˙".cyan().bold(),
        "˙".cyan().bold(),
        "˙".cyan().bold()
    );

    let text_block = format!(
        r#"
      _      _____  _____  _____ __  __  _____  ____      ____  ____
     | \ | || ____||_   _|| ____|\ \/ / | ____|/ ___|    |  _ \/ ___|
     |  \| ||  _|    | |  |  _|   \  /  |  _| | |        | |_) \___ \
     | |\  || |___   | |  | |___  /  \  | |___| |___  __ |  _ < ___) |
     |_| \_||_____|  |_|  |_____|/_/\_\ |_____|\____||__||_| \_\____/

    NetExec-RS — {}

    Version : {}
    Codename: {}
    Maintained by: {}
"#,
        "The Network Execution Tool (Pure Rust)".white().bold(),
        VERSION.yellow().bold(),
        CODENAME.yellow().bold(),
        "@thrive-spectrexq".yellow().bold()
    );

    let banner = format!("{spider}{text_block}");

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
        Arg::new("db-creds")
            .long("db-creds")
            .help("Use all credentials from the current workspace in the database")
            .action(ArgAction::SetTrue),
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
        Arg::new("kdc-host").long("kdc-host").help("FQDN of the domain controller"),
    ];

    // ── Module arguments ──
    let module_args = vec![
        Arg::new("module").short('M').long("module").help("Module to use").num_args(1),
        Arg::new("module-options").short('o').help("Module options (KEY=VALUE)").num_args(1..),
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

    // ── Export arguments ──
    let export_args = vec![
        Arg::new("export")
            .long("export")
            .help("Export results to a file (json, csv, html, md, ndjson, xml)")
            .value_parser(["json", "csv", "html", "md", "ndjson", "xml"]),
        Arg::new("export-path")
            .long("export-path")
            .help("Path to save the exported file")
            .default_value("nxc_report"),
    ];

    // ── Create protocol subcommands ──

    let smb_cmd = build_smb_cmd(&auth_args, &kerberos_args, &module_args, &export_args);
    let ssh_cmd = build_ssh_cmd(&auth_args, &module_args, &export_args);
    let ldap_cmd = build_ldap_cmd(&auth_args, &kerberos_args, &module_args, &export_args);
    let winrm_cmd = build_winrm_cmd(&auth_args, &kerberos_args, &module_args, &export_args);
    let mssql_cmd = build_mssql_cmd(&auth_args, &kerberos_args, &module_args, &export_args);
    let rdp_cmd = build_rdp_cmd(&auth_args, &module_args, &export_args);

    let ftp_cmd = build_ftp_cmd(&auth_args, &module_args, &export_args);
    let vnc_cmd = build_vnc_cmd(&auth_args, &module_args, &export_args);
    let wmi_cmd = build_wmi_cmd(&auth_args, &kerberos_args, &module_args, &export_args);
    let nfs_cmd = build_nfs_cmd(&auth_args, &module_args, &export_args);
    let adb_cmd = build_adb_cmd(&auth_args, &module_args, &export_args);
    let network_cmd = build_network_cmd(&module_args, &export_args);


    let http_cmd = build_http_cmd(&auth_args, &module_args, &export_args);
    let redis_cmd = build_redis_cmd(&auth_args, &module_args, &export_args);
    let postgres_cmd = build_postgres_cmd(&auth_args, &module_args, &export_args);
    let mysql_cmd = build_mysql_cmd(&auth_args, &module_args, &export_args);
    let snmp_cmd = build_snmp_cmd(&auth_args, &module_args, &export_args);
    let docker_cmd = build_docker_cmd(&auth_args, &module_args, &export_args);
    #[cfg(feature = "opcua-support")]
    let opcua_cmd = build_opcua_cmd(&auth_args, &module_args, &export_args);
    let dns_cmd = build_dns_cmd(&auth_args, &module_args, &export_args);
    let ipmi_cmd = build_ipmi_cmd(&auth_args, &module_args, &export_args);

    let cmd = Command::new("nxc")
        .about(banner)
        .version(VERSION)
        .arg(
            Arg::new("threads")
                .short('t')
                .long("threads")
                .help("Number of concurrent threads")
                .default_value("100")
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
            Arg::new("shuffle")
                .long("shuffle")
                .help("Randomize target order")
                .action(ArgAction::SetTrue)
                .global(true),
        )
        .arg(
            Arg::new("stealth")
                .long("stealth")
                .help("Stealth scan (alias for --threads 1 --jitter 500 --shuffle)")
                .action(ArgAction::SetTrue)
                .global(true),
        )
        .arg(
            Arg::new("proxy")
                .long("proxy")
                .help("SOCKS5 proxy (e.g. socks5://127.0.0.1:1080)")
                .num_args(1)
                .global(true),
        )
        .arg(
            Arg::new("verify-ssl")
                .long("verify-ssl")
                .help("Verify SSL certificates (default: false)")
                .action(ArgAction::SetTrue)
                .global(true),
        )
        .arg(
            Arg::new("log")
                .long("log")
                .help("Export results to a custom file")
                .global(true),
        )
        .arg(
            Arg::new("workspace")
                .short('w')
                .long("workspace")
                .help("Workspace to use")
                .default_value("default")
                .global(true),
        )
        .arg(
            Arg::new("profiling")
                .long("profiling")
                .help("Enable performance and memory profiling")
                .action(ArgAction::SetTrue)
                .global(true),
        )
        .arg(
            Arg::new("retries")
                .long("retries")
                .help("Max number of retries for transient failures")
                .default_value("3")
                .value_parser(clap::value_parser!(u32))
                .global(true),
        )
        .arg(
            Arg::new("cb-threshold")
                .long("cb-threshold")
                .help("Circuit breaker failure threshold")
                .default_value("5")
                .value_parser(clap::value_parser!(u32))
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
        .subcommand(
            Command::new("relay")
                .about("Start NTLM relay / capture server")
                .arg(
                    Arg::new("bind-addr")
                        .long("bind-addr")
                        .help("Address to bind the HTTP listener (e.g. 0.0.0.0:80)")
                        .default_value("0.0.0.0:80"),
                )
                .arg(
                    Arg::new("target")
                        .long("target")
                        .short('t')
                        .help("Target to relay authentication to (omit for capture-only mode)"),
                )
        )
        .subcommand(wmi_cmd)
        .subcommand(mysql_cmd)
        .subcommand(snmp_cmd)
        .subcommand(docker_cmd);

    #[cfg(feature = "opcua-support")]
    let cmd = cmd.subcommand(opcua_cmd);

    let cmd = cmd
        .subcommand(dns_cmd)
        .subcommand(ipmi_cmd)
        .subcommand(nfs_cmd)
        .subcommand(adb_cmd)
        .subcommand(network_cmd)
        .subcommand(http_cmd)
        .subcommand(redis_cmd)
        .subcommand(postgres_cmd)

        .subcommand(
            Command::new("ai")
                .about("LLM-powered automation and network discovery")
                .arg(
                    Arg::new("prompt")
                        .help("Natural language prompt for the AI agent (e.g., 'Scan 10.0.0.0/24 for hosts with SMB')")
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::new("provider")
                        .long("provider")
                        .help("AI provider to use (gemini, openai, anthropic, ollama). Auto-detected if omitted based on env vars."),
                )
                .arg(
                    Arg::new("model")
                        .long("model")
                        .help("Specific model to use (default: gemini-1.5-flash)"),
                ),
        );

    cmd
}

pub fn build_credentials(matches: &clap::ArgMatches) -> Vec<Credentials> {
    let mut creds = Vec::new();

    let usernames: Vec<&str> = matches
        .get_many::<String>("username")
        .map(|vals| vals.map(std::string::String::as_str).collect())
        .unwrap_or_default();

    let passwords: Vec<&str> = matches
        .get_many::<String>("password")
        .map(|vals| vals.map(std::string::String::as_str).collect())
        .unwrap_or_default();

    let hashes: Vec<&str> = matches
        .get_many::<String>("hash")
        .map(|vals| vals.map(std::string::String::as_str).collect())
        .unwrap_or_default();

    let no_bruteforce = matches.get_flag("no-bruteforce");
    let use_kerberos = matches.get_flag("kerberos");

    // If no credentials provided, use null session
    if usernames.is_empty() && passwords.is_empty() && hashes.is_empty() {
        let mut c = Credentials::null_session();
        c.use_kerberos = use_kerberos;
        creds.push(c);
        return creds;
    }

    if no_bruteforce {
        // Pair usernames with passwords 1:1
        let max_len = usernames.len().max(passwords.len()).max(hashes.len());
        for i in 0..max_len {
            let user = usernames.get(i).copied().unwrap_or("");
            let mut c = if let Some(hash) = hashes.get(i) {
                Credentials::nt_hash(user, hash, None)
            } else {
                let pass = passwords.get(i).copied().unwrap_or("");
                Credentials::password(user, pass, None)
            };
            c.use_kerberos = use_kerberos;
            creds.push(c);
        }
    } else {
        // Spray mode: every user × every password/hash
        for user in &usernames {
            if !hashes.is_empty() {
                for hash in &hashes {
                    let mut c = Credentials::nt_hash(user, hash, None);
                    c.use_kerberos = use_kerberos;
                    creds.push(c);
                }
            }
            if !passwords.is_empty() {
                for pass in &passwords {
                    let mut c = Credentials::password(user, pass, None);
                    c.use_kerberos = use_kerberos;
                    creds.push(c);
                }
            }
            // If only usernames given (no pass/hash), try empty password
            if passwords.is_empty() && hashes.is_empty() {
                let mut c = Credentials::password(user, "", None);
                c.use_kerberos = use_kerberos;
                creds.push(c);
            }
        }
    }

    creds
}

pub fn get_protocol_handler(
    protocol_name: &str,
    sub_matches: &clap::ArgMatches,
) -> Option<Arc<dyn nxc_protocols::NxcProtocol>> {
    let verify_ssl = sub_matches.get_flag("verify-ssl");

    match protocol_name {
        "smb" => Some(Arc::new(nxc_protocols::smb::SmbProtocol::new())),
        "ssh" => Some(Arc::new(nxc_protocols::ssh::SshProtocol::new())),
        "ldap" => Some(Arc::new(nxc_protocols::ldap::LdapProtocol::new())),
        "winrm" => {
            Some(Arc::new(nxc_protocols::winrm::WinrmProtocol::new().with_verify_ssl(verify_ssl)))
        }
        "mssql" => Some(Arc::new(nxc_protocols::mssql::MssqlProtocol::new())),
        "rdp" => Some(Arc::new(nxc_protocols::rdp::RdpProtocol::new())),
        "wmi" => Some(Arc::new(nxc_protocols::wmi::WmiProtocol::new())),
        "ftp" => Some(Arc::new(nxc_protocols::ftp::FtpProtocol::new())),
        "vnc" => Some(Arc::new(nxc_protocols::vnc::VncProtocol::new())),
        "nfs" => Some(Arc::new(nxc_protocols::nfs::NfsProtocol::new())),
        "adb" => Some(Arc::new(nxc_protocols::adb::AdbProtocol::new())),
        #[cfg(feature = "opcua-support")]
        "opcua" => Some(Arc::new(nxc_protocols::opcua::OpcUaProtocol::new())),
        "network" | "net" | "wifi" => {
            let scan = sub_matches.get_flag("scan");
            let connect = sub_matches.get_one::<String>("connect").cloned();
            let devices = sub_matches.get_flag("devices");
            let profiles = sub_matches.get_flag("profiles");
            let dump = sub_matches.get_flag("dump");
            let mdns = sub_matches.get_flag("mdns");
            let llmnr = sub_matches.get_flag("llmnr");
            Some(Arc::new(nxc_protocols::network::NetworkProtocol::new(
                scan, connect, devices, profiles, dump, mdns, llmnr,
            )))
        }
        "http" => {
            let ssl = sub_matches.get_flag("ssl");
            let verify_ssl = sub_matches.get_flag("verify-ssl");
            Some(Arc::new(nxc_protocols::http::HttpProtocol::new(ssl, verify_ssl)))
        }
        "redis" => Some(Arc::new(nxc_protocols::redis::RedisProtocol::new())),
        "postgres" | "postgresql" => {
            Some(Arc::new(nxc_protocols::postgresql::PostgresProtocol::new()))
        }
        "mysql" => Some(Arc::new(nxc_protocols::mysql::MysqlProtocol::new())),
        "snmp" => Some(Arc::new(nxc_protocols::snmp::SnmpProtocol::new())),
        "docker" => Some(Arc::new(nxc_protocols::docker::DockerProtocol::new())),
        "dns" => Some(Arc::new(nxc_protocols::dns::DnsProtocol::new())),
        "ipmi" => Some(Arc::new(nxc_protocols::ipmi::IpmiProtocol::new())),
        "kube" | "kubernetes" | "k8s" => Some(Arc::new(nxc_protocols::kube::KubeProtocol::new())),
        _ => None,
    }
}


fn build_ftp_cmd(auth_args: &[Arg], module_args: &[Arg], export_args: &[Arg]) -> Command {
    Command::new("ftp")
        .about("FTP protocol (port 21)")
        .args(auth_args)
        .args(module_args)
        .args(export_args)
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("21")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(Arg::new("ls").long("ls").help("List files in directory").num_args(0..=1))
        .arg(
            Arg::new("get")
                .long("get")
                .help("Download a file (e.g. --get /path/to/file)"),
        )
        .arg(
            Arg::new("put")
                .long("put")
                .help("Upload a file (e.g. --put local.txt remote.txt)")
                .num_args(2),
        )
}

fn build_vnc_cmd(auth_args: &[Arg], module_args: &[Arg], export_args: &[Arg]) -> Command {
    Command::new("vnc")
        .about("VNC protocol (port 5900)")
        .args(auth_args)
        .args(module_args)
        .args(export_args)
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("5900")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("screenshot")
                .long("screenshot")
                .help("Take screenshot upon successful auth")
                .action(ArgAction::SetTrue),
        )
}

fn build_wmi_cmd(auth_args: &[Arg], kerberos_args: &[Arg], module_args: &[Arg], export_args: &[Arg]) -> Command {
    Command::new("wmi")
        .about("WMI protocol (port 135)")
        .args(auth_args)
        .args(kerberos_args)
        .args(module_args)
        .args(export_args)
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("135")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(Arg::new("query").short('q').long("query").help("Execute WQL query"))
        .arg(
            Arg::new("exec-command")
                .short('x')
                .long("exec-command")
                .help("Execute command via Win32_Process"),
        )
}

fn build_nfs_cmd(auth_args: &[Arg], module_args: &[Arg], export_args: &[Arg]) -> Command {
    Command::new("nfs")
        .about("NFS protocol (port 2049)")
        .args(auth_args)
        .args(module_args)
        .args(export_args)
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("2049")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("shares")
                .long("shares")
                .help("Enumerate NFS exports")
                .action(ArgAction::SetTrue),
        )
}

fn build_adb_cmd(auth_args: &[Arg], module_args: &[Arg], export_args: &[Arg]) -> Command {
    Command::new("adb")
        .about("Android Debug Bridge protocol (port 5555)")
        .args(auth_args)
        .args(module_args)
        .args(export_args)
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
                .help("Execute command via adb shell"),
        )
}

fn build_network_cmd(module_args: &[Arg], export_args: &[Arg]) -> Command {
    Command::new("network")
        .about("Network enumeration and analysis (No authentication required)")
        .args(module_args)
        .args(export_args)
        .arg(
            Arg::new("scan")
                .long("scan")
                .help("Perform a network scan (ARP/ping sweep)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("connect")
                .long("connect")
                .help("Attempt to connect to a specific WiFi network (e.g. --connect 'Corporate WiFi')"),
        )
        .arg(
            Arg::new("devices")
                .long("devices")
                .help("List wireless interfaces")
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
                .help("Dump saved WiFi credentials")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("mdns")
                .long("mdns")
                .help("Perform mDNS (Bonjour) service discovery")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("llmnr")
                .long("llmnr")
                .help("Perform LLMNR service discovery")
                .action(ArgAction::SetTrue),
        )
}


fn build_http_cmd(auth_args: &[Arg], module_args: &[Arg], export_args: &[Arg]) -> Command {
    Command::new("http")
        .about("HTTP / HTTPS protocol (port 80/443)")
        .args(auth_args)
        .args(module_args)
        .args(export_args)
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("80")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(Arg::new("ssl").long("ssl").help("Use HTTPS").action(ArgAction::SetTrue))
        .arg(
            Arg::new("verify-ssl")
                .long("verify-ssl")
                .help("Verify SSL certificate")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("path")
                .long("path")
                .help("Path to request (default: /)")
                .default_value("/"),
        )
}

fn build_redis_cmd(auth_args: &[Arg], module_args: &[Arg], export_args: &[Arg]) -> Command {
    Command::new("redis")
        .about("Redis protocol (port 6379)")
        .args(auth_args)
        .args(module_args)
        .args(export_args)
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("6379")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("info")
                .long("info")
                .help("Retrieve Redis server info")
                .action(ArgAction::SetTrue),
        )
}

fn build_postgres_cmd(auth_args: &[Arg], module_args: &[Arg], export_args: &[Arg]) -> Command {
    Command::new("postgres")
        .about("PostgreSQL protocol (port 5432)")
        .args(auth_args)
        .args(module_args)
        .args(export_args)
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("5432")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(Arg::new("dbs").long("dbs").help("List databases").action(ArgAction::SetTrue))
        .arg(Arg::new("query").short('q').long("query").help("Execute SQL query"))
        .arg(
            Arg::new("exec-command")
                .short('x')
                .long("exec-command")
                .help("Execute system command via COPY/libc"),
        )
}

fn build_mysql_cmd(auth_args: &[Arg], module_args: &[Arg], export_args: &[Arg]) -> Command {
    Command::new("mysql")
        .about("MySQL protocol (port 3306)")
        .args(auth_args)
        .args(module_args)
        .args(export_args)
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("3306")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(Arg::new("dbs").long("dbs").help("List databases").action(ArgAction::SetTrue))
        .arg(Arg::new("query").short('q').long("query").help("Execute SQL query"))
}

fn build_snmp_cmd(auth_args: &[Arg], module_args: &[Arg], export_args: &[Arg]) -> Command {
    Command::new("snmp")
        .about("SNMP protocol (port 161/udp)")
        .args(auth_args)
        .args(module_args)
        .args(export_args)
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("161")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("enum")
                .long("enum")
                .help("Enumerate system information")
                .action(ArgAction::SetTrue),
        )
}

fn build_docker_cmd(auth_args: &[Arg], module_args: &[Arg], export_args: &[Arg]) -> Command {
    Command::new("docker")
        .about("Docker API & Registry protocol (port 2375/5000)")
        .args(auth_args)
        .args(module_args)
        .args(export_args)
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("2375")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("enum")
                .long("enum")
                .help("Enumerate containers or repositories")
                .action(ArgAction::SetTrue),
        )
}

#[cfg(feature = "opcua-support")]
fn build_opcua_cmd(auth_args: &[Arg], module_args: &[Arg], export_args: &[Arg]) -> Command {
    Command::new("opcua")
        .about("OPC-UA (Industrial Control Systems) protocol (port 4840)")
        .args(auth_args)
        .args(module_args)
        .args(export_args)
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("4840")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("enum")
                .long("enum")
                .help("Enumerate OPC-UA server status and metadata")
                .action(ArgAction::SetTrue),
        )
}

fn build_dns_cmd(auth_args: &[Arg], module_args: &[Arg], export_args: &[Arg]) -> Command {
    Command::new("dns")
        .about("DNS protocol (port 53)")
        .args(auth_args)
        .args(module_args)
        .args(export_args)
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("53")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("enum").long("enum").help("Enumerate DNS records").action(ArgAction::SetTrue),
        )
}

fn build_ipmi_cmd(auth_args: &[Arg], module_args: &[Arg], export_args: &[Arg]) -> Command {
    Command::new("ipmi")
        .about("IPMI protocol (port 623/udp)")
        .args(auth_args)
        .args(module_args)
        .args(export_args)
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("623")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("enum")
                .long("enum")
                .help("Enumerate IPMI information")
                .action(ArgAction::SetTrue),
        )
}


fn build_smb_cmd(auth_args: &[Arg], kerberos_args: &[Arg], module_args: &[Arg], export_args: &[Arg]) -> Command {
    Command::new("smb")
        .about("SMB protocol (port 445)")
        .args(auth_args)
        .args(kerberos_args)
        .args(module_args)
        .args(export_args)
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
        .arg(Arg::new("disks").long("disks").help("Enumerate disks").action(ArgAction::SetTrue))
        .arg(
            Arg::new("loggedon-users")
                .long("loggedon-users")
                .help("Enumerate logged-on users")
                .action(ArgAction::SetTrue),
        )
        .arg(Arg::new("users").long("users").help("Enumerate users").action(ArgAction::SetTrue))
        .arg(Arg::new("groups").long("groups").help("Enumerate groups").action(ArgAction::SetTrue))
        .arg(
            Arg::new("local-groups")
                .long("local-groups")
                .help("Enumerate local groups")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("pass-pol")
                .long("pass-pol")
                .help("Dump password policy")
                .action(ArgAction::SetTrue),
        )
        .arg(Arg::new("rid-brute").long("rid-brute").help("RID bruteforce").num_args(0..=1))
        .arg(
            Arg::new("sam")
                .long("sam")
                .help("Dump SAM hashes")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("lsa")
                .long("lsa")
                .help("Dump LSA secrets")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("ntds")
                .long("ntds")
                .help("Dump NTDS.dit hashes (VSS)")
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
        )
}

fn build_ssh_cmd(auth_args: &[Arg], module_args: &[Arg], export_args: &[Arg]) -> Command {
    Command::new("ssh")
        .about("SSH protocol (port 22)")
        .args(auth_args)
        .args(module_args)
        .args(export_args)
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("22")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(Arg::new("key-file").long("key-file").help("SSH private key file for authentication"))
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
        )
}

fn build_ldap_cmd(auth_args: &[Arg], kerberos_args: &[Arg], module_args: &[Arg], export_args: &[Arg]) -> Command {
    Command::new("ldap")
        .about("LDAP protocol (port 389/636)")
        .args(auth_args)
        .args(kerberos_args)
        .args(module_args)
        .args(export_args)
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("389")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("ldaps").long("ldaps").help("Use LDAPS (port 636)").action(ArgAction::SetTrue),
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
        )
}

fn build_winrm_cmd(auth_args: &[Arg], kerberos_args: &[Arg], module_args: &[Arg], export_args: &[Arg]) -> Command {
    Command::new("winrm")
        .about("WinRM protocol (port 5985/5986)")
        .args(auth_args)
        .args(kerberos_args)
        .args(module_args)
        .args(export_args)
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("5985")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(Arg::new("ssl").long("ssl").help("Use HTTPS (port 5986)").action(ArgAction::SetTrue))
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
        )
}

fn build_mssql_cmd(auth_args: &[Arg], kerberos_args: &[Arg], module_args: &[Arg], export_args: &[Arg]) -> Command {
    Command::new("mssql")
        .about("MSSQL protocol (port 1433)")
        .args(auth_args)
        .args(kerberos_args)
        .args(module_args)
        .args(export_args)
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("1433")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(Arg::new("query").short('q').long("query").help("Execute SQL query"))
        .arg(
            Arg::new("exec-command")
                .short('x')
                .long("exec-command")
                .help("Execute command via xp_cmdshell"),
        )
}

fn build_rdp_cmd(auth_args: &[Arg], module_args: &[Arg], export_args: &[Arg]) -> Command {
    Command::new("rdp")
        .about("RDP protocol (port 3389)")
        .args(auth_args)
        .args(module_args)
        .args(export_args)
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("3389")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("screenshot")
                .long("screenshot")
                .help("Take a screenshot of the RDP login screen")
                .action(ArgAction::SetTrue),
        )
}
