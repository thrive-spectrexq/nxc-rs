//! # nxc — NetExec-RS CLI Entry Point
//!
//! Provides the familiar `nxc <protocol> <targets> -u -p` interface.
//! When running non-interactively, prints coloured output to stdout.

use anyhow::Result;
use clap::{Parser, Subcommand};

/// ◈ NetExec-RS ◈ — Network Execution Tool (Pure Rust)
#[derive(Parser, Debug)]
#[command(
    name = "nxc",
    author = "Antigravity",
    version,
    about = "◈ NetExec-RS ◈ — Network Execution Tool (Pure Rust Rewrite)",
    long_about = "A full Rust reimplementation of the NetExec (nxc) network execution framework.\nBuilt on the NetSage platform architecture."
)]
struct Cli {
    #[command(subcommand)]
    protocol: ProtocolCommand,

    /// Concurrent threads
    #[arg(short = 't', long, default_value = "256", global = true)]
    threads: usize,

    /// Per-connection timeout in seconds
    #[arg(long, default_value = "30", global = true)]
    timeout: u64,

    /// Random delay between attempts (ms)
    #[arg(long, global = true)]
    jitter: Option<u64>,

    /// Suppress progress bar
    #[arg(long, global = true)]
    no_progress: bool,

    /// Verbose output
    #[arg(long, global = true)]
    verbose: bool,

    /// Debug output
    #[arg(long, global = true)]
    debug: bool,

    /// nxc-db workspace name
    #[arg(long, default_value = "default", global = true)]
    workspace: String,
}

#[derive(Subcommand, Debug)]
enum ProtocolCommand {
    /// SMB protocol (port 445)
    Smb(ProtocolArgs),
    /// LDAP protocol (port 389/636)
    Ldap(ProtocolArgs),
    /// WinRM protocol (port 5985/5986)
    Winrm(ProtocolArgs),
    /// WMI protocol (port 135)
    Wmi(ProtocolArgs),
    /// RDP protocol (port 3389)
    Rdp(ProtocolArgs),
    /// MSSQL protocol (port 1433)
    Mssql(ProtocolArgs),
    /// SSH protocol (port 22)
    Ssh(ProtocolArgs),
    /// FTP protocol (port 21)
    Ftp(ProtocolArgs),
    /// VNC protocol (port 5900)
    Vnc(ProtocolArgs),
    /// NFS protocol (port 2049)
    Nfs(ProtocolArgs),
}

#[derive(Parser, Debug)]
struct ProtocolArgs {
    /// Target specification (IP, CIDR, range, hostname, or file)
    #[arg(required = true)]
    targets: Vec<String>,

    // ── Auth Options ──

    /// Username or file of usernames
    #[arg(short = 'u', long)]
    username: Option<String>,

    /// Password or file of passwords
    #[arg(short = 'p', long)]
    password: Option<String>,

    /// NT hash (pass-the-hash)
    #[arg(short = 'H', long = "hash")]
    nt_hash: Option<String>,

    /// Use Kerberos authentication
    #[arg(short = 'k', long)]
    kerberos: bool,

    /// Path to ccache ticket file
    #[arg(long)]
    ccache_file: Option<String>,

    /// Kerberos AES key (overpass-the-hash)
    #[arg(long)]
    aes_key: Option<String>,

    /// Certificate PFX for PKINIT
    #[arg(long)]
    pfx: Option<String>,

    /// Domain name
    #[arg(short = 'd', long)]
    domain: Option<String>,

    /// Force local authentication
    #[arg(long)]
    local_auth: bool,

    /// Don't stop after first hit
    #[arg(long)]
    continue_on_success: bool,

    /// Spray each password once across all users
    #[arg(long)]
    no_bruteforce: bool,

    /// Use LAPS password
    #[arg(long)]
    laps: bool,

    /// KDC IP override
    #[arg(long)]
    kdchost: Option<String>,

    // ── Execution Options ──

    /// Execute shell command
    #[arg(short = 'x')]
    exec_cmd: Option<String>,

    /// Execute PowerShell command
    #[arg(short = 'X')]
    exec_ps: Option<String>,

    /// Run module
    #[arg(short = 'M', long = "module")]
    module: Option<String>,

    /// Module option (KEY=VALUE)
    #[arg(short = 'o')]
    module_opts: Vec<String>,

    /// List available modules for this protocol
    #[arg(short = 'L')]
    list_modules: bool,

    // ── Output Options ──

    /// Export results to CSV
    #[arg(long = "export")]
    export_file: Option<String>,

    /// Write output to log file
    #[arg(long = "log")]
    log_file: Option<String>,

    /// Custom port override
    #[arg(long)]
    port: Option<u16>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let level = if cli.debug {
        "debug"
    } else if cli.verbose {
        "info"
    } else {
        "warn"
    };
    tracing_subscriber::fmt()
        .with_env_filter(level)
        .init();

    println!("◈ NetExec-RS ◈ — Network Execution Tool");
    println!();

    match &cli.protocol {
        ProtocolCommand::Smb(args) => run_protocol("smb", args, &cli).await,
        ProtocolCommand::Ldap(args) => run_protocol("ldap", args, &cli).await,
        ProtocolCommand::Winrm(args) => run_protocol("winrm", args, &cli).await,
        ProtocolCommand::Wmi(args) => run_protocol("wmi", args, &cli).await,
        ProtocolCommand::Rdp(args) => run_protocol("rdp", args, &cli).await,
        ProtocolCommand::Mssql(args) => run_protocol("mssql", args, &cli).await,
        ProtocolCommand::Ssh(args) => run_protocol("ssh", args, &cli).await,
        ProtocolCommand::Ftp(args) => run_protocol("ftp", args, &cli).await,
        ProtocolCommand::Vnc(args) => run_protocol("vnc", args, &cli).await,
        ProtocolCommand::Nfs(args) => run_protocol("nfs", args, &cli).await,
    }
}

async fn run_protocol(proto: &str, args: &ProtocolArgs, cli: &Cli) -> Result<()> {
    // List modules if requested
    if args.list_modules {
        let registry = nxc_modules::ModuleRegistry::new();
        let modules = registry.list(Some(proto));
        if modules.is_empty() {
            println!("No modules available for {} (protocol implementation pending)", proto);
        } else {
            println!("Available {} modules:", proto.to_uppercase());
            for m in modules {
                println!("  {:<20} {}", m.name(), m.description());
            }
        }
        return Ok(());
    }

    // Parse targets
    let mut targets = Vec::new();
    for spec in &args.targets {
        targets.extend(nxc_targets::parse_targets(spec)?);
    }

    let proto_upper = proto.to_uppercase();
    let port = args.port.unwrap_or_else(|| {
        nxc_protocols::Protocol::from_str(proto)
            .map(|p| p.default_port())
            .unwrap_or(0)
    });

    println!(
        "{:<6} Targeting {} host(s) on port {} with {} thread(s)",
        proto_upper,
        targets.len(),
        port,
        cli.threads,
    );

    // TODO: Build credentials from args, create protocol handler, run execution engine
    println!();
    println!("⚠ Protocol implementation pending — nxc-rs scaffold ready");
    println!("  Use `cargo build --workspace` to verify the skeleton compiles.");

    Ok(())
}
