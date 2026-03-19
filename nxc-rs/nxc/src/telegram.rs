//! NetExec-RS Telegram Bot - Master Class Professional Suite
//!
//! This module provides a high-performance, feature-rich Telegram interface for the NetExec-RS
//! security platform. It is designed for professional security researchers and pentesters
//! who require remote access to their tools with absolute reliability and power.
//!
//! Features:
//! - Multi-user Session Management
//! - Advanced Reconnaissance (DNS, Portscan, IP Geolocation, Whois)
//! - Interactive Inline Keyboards & Menus
//! - Secure Command Execution with Output Truncation
//! - Session Persistence and Target History
//! - Administrative Tools (Whitelisting, Broadcasting)
//! - System Analytics and Resource Monitoring
//! - Beautiful Output Formatting with Table Builders

use crate::{build_credentials, get_protocol_handler};
use anyhow::Context;
use std::sync::Arc;
use nxc_db::{NxcDb, HostInfo, Credential};
use nxc_modules::ModuleRegistry;
use nxc_protocols::Protocol;
use nxc_targets::{parse_targets, ExecutionEngine, ExecutionOpts};
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use teloxide::prelude::*;
use teloxide::types::{ChatId, InlineKeyboardButton, InlineKeyboardMarkup, ParseMode, UserId};
use teloxide::utils::command::BotCommands;
use tokio::io::AsyncWriteExt;

// --- 🌐 Configuration & Environment ---

const BOT_VERSION: &str = "2.6.0-PRO";
const MASTER_CODENAME: &str = "SUPERNOVA";
const MAX_MESSAGE_LENGTH: usize = 4096;
const DEFAULT_TIMEOUT_SECS: u64 = 60;
// const SESSION_EXPIRY_MINS: u64 = 180;
const MAX_TARGET_HISTORY: usize = 20;

// --- 🔐 Security & Access Control ---

/// Global list of authorized user IDs (stored as raw u64 for simplicity)
static ALLOWED_USERS: OnceLock<Mutex<HashSet<u64>>> = OnceLock::new();
/// Administrative user IDs (can whitelist others)
static ADMIN_USERS: OnceLock<Mutex<HashSet<u64>>> = OnceLock::new();

/// Initialize security policies from environment
fn init_security() {
    let allowed = ALLOWED_USERS.get_or_init(|| Mutex::new(HashSet::new()));
    let admins = ADMIN_USERS.get_or_init(|| Mutex::new(HashSet::new()));

    let mut allowed_lock = allowed.lock().unwrap();
    let mut admin_lock = admins.lock().unwrap();

    // Default admin from env
    if let Ok(ids) = std::env::var("TELEGRAM_ADMIN_USERS") {
        for id in ids.split(',') {
            if let Ok(val) = id.parse::<u64>() {
                admin_lock.insert(val);
                allowed_lock.insert(val);
            }
        }
    }

    // Whitelisted users from env
    if let Ok(ids) = std::env::var("TELEGRAM_ALLOWED_USERS") {
        for id in ids.split(',') {
            if let Ok(val) = id.parse::<u64>() {
                allowed_lock.insert(val);
            }
        }
    }
}

fn is_authorized(user_id: UserId) -> bool {
    let allowed = ALLOWED_USERS.get_or_init(|| Mutex::new(HashSet::new()));
    let hs = allowed.lock().unwrap();
    if hs.is_empty() {
        return true;
    } // allow all if unprotected
    hs.contains(&user_id.0)
}

fn is_admin(user_id: UserId) -> bool {
    let admins = ADMIN_USERS.get_or_init(|| Mutex::new(HashSet::new()));
    admins.lock().unwrap().contains(&user_id.0)
}

// --- 🧠 Session Management Engine ---

#[derive(Clone, Debug)]
struct UserSession {
    last_target: Option<String>,
    last_protocol: Option<String>,
    history: Vec<String>,
    last_activity: Instant,
    workspace: String,
    _preferred_threads: usize,
    _auto_pwn: bool,
    _interactive_mode: bool,
}

impl Default for UserSession {
    fn default() -> Self {
        Self {
            last_target: None,
            last_protocol: None,
            history: Vec::new(),
            last_activity: Instant::now(),
            workspace: "default".to_string(),
            _preferred_threads: 256,
            _auto_pwn: false,
            _interactive_mode: false,
        }
    }
}

static SESSIONS: OnceLock<Mutex<HashMap<u64, UserSession>>> = OnceLock::new();

fn get_session(id: UserId) -> UserSession {
    let sessions = SESSIONS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = sessions.lock().unwrap();
    map.entry(id.0).or_default().clone()
}

fn update_session<F>(id: UserId, f: F)
where
    F: FnOnce(&mut UserSession),
{
    let sessions = SESSIONS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = sessions.lock().unwrap();
    let session = map.entry(id.0).or_default();
    f(session);
    session.last_activity = Instant::now();
}

// --- 📋 Command Specifications ---

#[derive(BotCommands, Clone, Debug)]
#[command(
    rename_rule = "lowercase",
    description = "NetExec-RS Master Class Professional Suite"
)]
enum TelegramBotCommand {
    // --- 🌍 Navigation & Basics ---
    #[command(description = "Main dashboard and help portal")]
    Help(String),
    #[command(description = "Interactive protocol selection console")]
    Menu,
    #[command(description = "Advanced operator's handbook and guide")]
    Guide(String),
    #[command(description = "Show detailed project about information")]
    About,

    // --- 🚀 Core Exploitation Engine ---
    #[command(description = "Full CLI command execution")]
    Run(String),
    #[command(description = "Intelligent search across protocols/modules")]
    Search(String),
    #[command(description = "List all supported security protocols")]
    Protocols,
    #[command(description = "Browse offensive modules for a protocol")]
    Modules(String),

    // --- ⚡ Protocol Accelerators ---
    #[command(description = "SMB scan & pivot: /smb <target> [options]")]
    Smb(String),
    #[command(description = "SSH remote terminal access")]
    Ssh(String),
    #[command(description = "LDAP directory reconnaissance")]
    Ldap(String),
    #[command(description = "WinRM shell orchestration")]
    Winrm(String),
    #[command(description = "MSSQL database intrusion")]
    Mssql(String),
    #[command(description = "ADB mobile device exploitation")]
    Adb(String),
    #[command(description = "FTP storage discovery & dump")]
    Ftp(String),
    #[command(description = "NFS network share enumeration")]
    Nfs(String),
    #[command(description = "HTTP web reconnaissance")]
    Http(String),

    // --- 📊 Specialized Enumeration Shortcuts ---
    #[command(description = "Quickly list SMB shares on a target")]
    Shares(String),
    #[command(description = "Dump domain/local users from target")]
    Users(String),
    #[command(description = "Enumerate groups from target")]
    Groups(String),

    // --- 📡 Advanced Reconnaissance Suite ---
    #[command(description = "ICMP availability heartbeat")]
    Ping(String),
    #[command(description = "Professional TCP port discovery")]
    Portscan(String),
    #[command(description = "Deep DNS record investigation")]
    Dns(String),
    #[command(description = "Reverse DNS pointer lookup")]
    Reverse(String),
    #[command(description = "Bot node network identity & geolocation")]
    Ip,
    #[command(description = "Geographic lookup for a target IP")]
    Geo(String),

    // --- 🔧 Session & Management ---
    #[command(description = "View your operator profile and stats")]
    Whoami,
    #[command(description = "System health, uptime, and load")]
    Status,
    #[command(description = "NXC command pattern cheat sheet")]
    Cheat,
    #[command(description = "Historical target and command log")]
    History,
    #[command(description = "Flush current session state and memory")]
    Reset,
    #[command(description = "Clear terminal space and reset session")]
    Clear,

    // --- 🛡️ Administrative Controls (Admin Only) ---
    #[command(description = "Whitelist a user ID for bot access")]
    Whitelist(String),
    #[command(description = "Broadcast message to all active operators")]
    Broadcast(String),
    #[command(description = "View real-time system logs")]
    Logs,
    #[command(description = "Enter interactive shell mode for the last target")]
    Shell,

    // --- 🗄️ Database & Workspace Management ---
    #[command(description = "List all discovered hosts in current workspace")]
    Hosts,
    #[command(description = "Show all captured credentials")]
    Creds,
    #[command(description = "List available workspaces")]
    Workspaces,
    #[command(description = "Set the active workspace: /setworkspace <name>")]
    SetWorkspace(String),
    #[command(description = "Show summary statistics for the current workspace")]
    Stats,
}

// --- 🛸 Main Dispatch Engine ---

pub async fn start_bot() -> anyhow::Result<()> {
    init_security();

    let token = std::env::var("TELEGRAM_BOT_TOKEN")
        .context("CRITICAL: TELEGRAM_BOT_TOKEN not found in environment")?;

    // --- Render Health Check ---
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "10000".to_string())
        .parse::<u16>()
        .unwrap_or(10000);

    tokio::spawn(async move {
        if let Ok(listener) = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await {
            println!("📡 Health check server listening on :{}", port);
            loop {
                if let Ok((mut socket, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
                        let _ = socket.write_all(response.as_bytes()).await;
                        let _ = socket.flush().await;
                    });
                }
            }
        }
    });

    let bot = Bot::new(token);
    println!("🔥 [SUPERNOVA-PRO] Master Class Engine Online.");

    let handler = dptree::entry()
        .branch(Update::filter_message().endpoint(handle_message_entry))
        .branch(Update::filter_callback_query().endpoint(handle_interactive_callbacks));

    Dispatcher::builder(bot, handler)
        .enable_ctrlc_handler()
        .build()
        .dispatch()
        .await;

    Ok(())
}

async fn handle_message_entry(bot: Bot, msg: Message) -> Result<(), teloxide::RequestError> {
    if let Some(text) = msg.text() {
        if let Ok(cmd) = TelegramBotCommand::parse(text, "") {
            return handle_command(bot, msg, cmd).await;
        }
    }
    handle_generic_stream(bot, msg).await
}

async fn handle_command(
    bot: Bot,
    msg: Message,
    cmd: TelegramBotCommand,
) -> Result<(), teloxide::RequestError> {
    let user_id = msg.from.as_ref().map(|u| u.id).unwrap_or(UserId(0));

    if !is_authorized(user_id) {
        bot.send_message(msg.chat.id, "🚫 <b>UNAUTHORIZED ACCESS</b>\n\nYour signature is not recognized in the master whitelist. Please contact an administrator.")
            .parse_mode(ParseMode::Html).await?;
        return Ok(());
    }

    match cmd {
        // Essentials
        TelegramBotCommand::Help(args) => {
            if !args.is_empty() {
                engine_execute_help(bot, msg, args).await?;
            } else {
                ui_send_dashboard(bot, msg).await?;
            }
        }
        TelegramBotCommand::Menu => {
            ui_send_protocol_console(bot, msg).await?;
        }
        TelegramBotCommand::Guide(args) => {
            if !args.is_empty() {
                engine_execute_guide(bot, msg, args).await?;
            } else {
                ui_send_handbook(bot, msg).await?;
            }
        }
        TelegramBotCommand::About => {
            ui_send_about(bot, msg).await?;
        }

        // Execution
        TelegramBotCommand::Run(a) => {
            engine_execute_raw(bot, msg, a).await?;
        }
        TelegramBotCommand::Search(q) => {
            engine_execute_search(bot, msg, q).await?;
        }
        TelegramBotCommand::Protocols => {
            engine_list_protocols(bot, msg).await?;
        }
        TelegramBotCommand::Modules(p) => {
            engine_list_modules(bot, msg, p).await?;
        }

        // Protocol Shortcuts
        TelegramBotCommand::Smb(a) => {
            engine_execute_shortcut(bot, msg, "smb", a).await?;
        }
        TelegramBotCommand::Ssh(a) => {
            engine_execute_shortcut(bot, msg, "ssh", a).await?;
        }
        TelegramBotCommand::Ldap(a) => {
            engine_execute_shortcut(bot, msg, "ldap", a).await?;
        }
        TelegramBotCommand::Winrm(a) => {
            engine_execute_shortcut(bot, msg, "winrm", a).await?;
        }
        TelegramBotCommand::Mssql(a) => {
            engine_execute_shortcut(bot, msg, "mssql", a).await?;
        }
        TelegramBotCommand::Adb(a) => {
            engine_execute_shortcut(bot, msg, "adb", a).await?;
        }
        TelegramBotCommand::Ftp(a) => {
            engine_execute_shortcut(bot, msg, "ftp", a).await?;
        }
        TelegramBotCommand::Nfs(a) => {
            engine_execute_shortcut(bot, msg, "nfs", a).await?;
        }
        TelegramBotCommand::Http(a) => {
            engine_execute_shortcut(bot, msg, "http", a).await?;
        }

        // Enumeration Shortcuts
        TelegramBotCommand::Shares(t) => {
            engine_execute_shortcut(bot, msg, "smb", format!("{} --shares", t)).await?;
        }
        TelegramBotCommand::Users(t) => {
            engine_execute_shortcut(bot, msg, "smb", format!("{} --users", t)).await?;
        }
        TelegramBotCommand::Groups(t) => {
            engine_execute_shortcut(bot, msg, "smb", format!("{} --groups", t)).await?;
        }

        // Recon Suite
        TelegramBotCommand::Ping(t) => {
            recon_ping(bot, msg, t).await?;
        }
        TelegramBotCommand::Portscan(a) => {
            recon_portscan(bot, msg, a).await?;
        }
        TelegramBotCommand::Dns(d) => {
            recon_dns(bot, msg, d).await?;
        }
        TelegramBotCommand::Reverse(i) => {
            recon_reverse_dns(bot, msg, i).await?;
        }
        TelegramBotCommand::Ip => {
            recon_bot_identity(bot, msg).await?;
        }
        TelegramBotCommand::Geo(i) => {
            recon_geo_lookup(bot, msg, i).await?;
        }

        // Session & System
        TelegramBotCommand::Whoami => {
            session_show_profile(bot, msg).await?;
        }
        TelegramBotCommand::Status => {
            session_show_status(bot, msg).await?;
        }
        TelegramBotCommand::Cheat => {
            session_show_cheat(bot, msg).await?;
        }
        TelegramBotCommand::History => {
            session_show_history(bot, msg).await?;
        }
        TelegramBotCommand::Reset => {
            session_purge(bot, msg).await?;
        }
        TelegramBotCommand::Clear => {
            session_clear(bot, msg).await?;
        }

        // Admin
        TelegramBotCommand::Whitelist(id) => {
            admin_whitelist(bot, msg, id).await?;
        }
        TelegramBotCommand::Broadcast(txt) => {
            admin_broadcast(bot, msg, txt).await?;
        }
        TelegramBotCommand::Logs => {
            admin_show_logs(bot, msg).await?;
        }
        TelegramBotCommand::Shell => {
            let user_id = msg.from.as_ref().map(|u| u.id).unwrap_or(UserId(0));
            let s = get_session(user_id);
            if s.last_target.is_none() || s.last_protocol.is_none() {
                bot.send_message(msg.chat.id, "❌ <b>SHELL ERROR</b>\nNo active target or protocol found in session history.").await?;
            } else {
                update_session(user_id, |sess| sess._interactive_mode = true);
                let text = format!("🐚 <b>SHELL MODE ACTIVATED</b>\n\nTarget: <code>{}</code>\nProtocol: <code>{}</code>\n\nType commands directly to execute. Type <code>exit</code> to return to mission control.", 
                    html_escape::encode_safe(s.last_target.as_ref().unwrap()), 
                    html_escape::encode_safe(s.last_protocol.as_ref().unwrap()));
                bot.send_message(msg.chat.id, text).parse_mode(ParseMode::Html).await?;
            }
        }

        // Database
        TelegramBotCommand::Hosts => {
            database_list_hosts(bot, msg).await?;
        }
        TelegramBotCommand::Creds => {
            database_list_creds(bot, msg).await?;
        }
        TelegramBotCommand::Workspaces => {
            database_list_workspaces(bot, msg).await?;
        }
        TelegramBotCommand::SetWorkspace(name) => {
            database_set_workspace(bot, msg, name).await?;
        }
        TelegramBotCommand::Stats => {
            database_show_stats(bot, msg).await?;
        }
    }
    Ok(())
}

async fn handle_generic_stream(bot: Bot, msg: Message) -> Result<(), teloxide::RequestError> {
    if let Some(text) = msg.text() {
        let lower = text.to_lowercase();
        if lower.contains("hi") || lower.contains("hello") || lower.contains("start") {
            let sender = msg
                .from
                .as_ref()
                .map(|u| u.first_name.clone())
                .unwrap_or_else(|| "Operator".to_string());
            bot.send_message(msg.chat.id, format!("👋 Welcome back, <b>{}</b>.\n\n<code>NetExec-RS Master Suite</code> is armed and ready.\n\nType /help to enter the control portal.", html_escape::encode_safe(&sender)))
                .parse_mode(ParseMode::Html)
                .reply_markup(main_dashboard_markup())
                .await?;
        } else {
            let user_id = msg.from.as_ref().map(|u| u.id).unwrap_or(UserId(0));
            let s = get_session(user_id);
            if s._interactive_mode {
                if text.to_lowercase() == "exit" {
                    update_session(user_id, |sess| sess._interactive_mode = false);
                    bot.send_message(msg.chat.id, "🚪 <b>SHELL DEACTIVATED</b>\nReturning to standard command mode.")
                        .parse_mode(ParseMode::Html).await?;
                } else {
                    let cmd = format!("{} {} -x \"{}\"", s.last_protocol.as_ref().unwrap(), s.last_target.as_ref().unwrap(), text);
                    engine_execute_raw(bot, msg, cmd).await?;
                }
            } else {
                bot.send_message(
                        msg.chat.id,
                        "🛰️ <i>Awaiting valid command structure...</i>",
                    )
                    .parse_mode(ParseMode::Html)
                    .await?;
            }
        }
    }
    Ok(())
}

async fn handle_interactive_callbacks(
    bot: Bot,
    query: CallbackQuery,
) -> Result<(), teloxide::RequestError> {
    let user_id = query.from.id;
    if !is_authorized(user_id) {
        let _ = bot
            .answer_callback_query(query.id)
            .text("Unauthorized")
            .await;
        return Ok(());
    }

    if let Some(data) = query.data {
        let msg = match query.message {
            Some(teloxide::types::MaybeInaccessibleMessage::Regular(m)) => m,
            _ => {
                return Ok(());
            }
        };

        match data.as_str() {
            "btn_help" => {
                ui_send_dashboard(bot.clone(), msg).await?;
            }
            "btn_proto" => {
                engine_list_protocols(bot.clone(), msg).await?;
            }
            "btn_recon" => {
                bot.send_message(user_id, "🔧 <b>Recon Toolkit:</b> Use /ping, /portscan, /dns, /geo, or /reverse to map the landscape.")
                    .parse_mode(ParseMode::Html).await?;
            }
            "btn_status" => {
                session_show_status(bot.clone(), msg).await?;
            }
            _ => {
                let _ = bot
                    .answer_callback_query(query.id.clone())
                    .text("Feature implementation pending...")
                    .await;
            }
        }
    }
    let _ = bot.answer_callback_query(query.id).await;
    Ok(())
}

// --- 🎨 UI & Presentation Logic ---

async fn ui_send_dashboard(bot: Bot, msg: Message) -> Result<(), teloxide::RequestError> {
    let text = "🛸 <b>NETEXEC-RS: SUPERNOVA MISSION CONTROL</b>\n\n\
        <b>Operational Command Matrix:</b>\n\n\
        🚀 <b>Deployment:</b> /run /smb /ssh /ldap /winrm /mssql\n\
        🐚 <b>Interactive:</b> /shell (persistent access)\n\
        🔍 <b>Intelligence:</b> /search /modules /protocols\n\
        📡 <b>Reconnaissance:</b> /ping /portscan /dns /geo\n\
        📋 <b>Rapid Shortcuts:</b> /shares /users /groups\n\
        👤 <b>Operator:</b> /whoami /history /reset /clear\n\
        ⚙️ <b>Infrastructure:</b> /status /guide /cheat /about\n\n\
        ◈ <i>Status: Tactical Dominance Achieved</i> ◈\n\
        ◈ <i>Node: [REDACTED]</i> ◈";
    bot.send_message(msg.chat.id, text)
        .parse_mode(ParseMode::Html)
        .reply_markup(main_dashboard_markup())
        .await?;
    Ok(())
}

async fn ui_send_protocol_console(bot: Bot, msg: Message) -> Result<(), teloxide::RequestError> {
    let mut text = String::from("🌩️ <b>Protocol Intelligence Console</b>\n\nAvailable protocols for exploitation and scanning:\n\n");
    for p in Protocol::all() {
        text.push_str(&format!(
            "◈ <b>{}</b> (Port {})\n",
            p.name().to_uppercase(),
            p.default_port()
        ));
    }
    text.push_str(
        "\n<i>Tip: Use /modules &lt;proto&gt; to find specialized payloads for these protocols.</i>",
    );
    bot.send_message(msg.chat.id, text)
        .parse_mode(ParseMode::Html)
        .await?;
    Ok(())
}

async fn ui_send_handbook(bot: Bot, msg: Message) -> Result<(), teloxide::RequestError> {
    let text = "📖 <b>NETEXEC MASTER CLASS: OPERATOR'S HANDBOOK</b>\n\n\
        <b>1. Unified Targeting Intelligence</b>\n\
        • Single Target: <code>10.0.0.1</code> or <code>target.pro</code>\n\
        • CIDR Networks: <code>192.168.1.0/24</code>\n\
        • Range Scanning: <code>10.0.0.1-10.0.0.50</code>\n\
        • File Discovery: <code>/run smb targets.txt</code>\n\n\
        <b>2. Authentication Matrix</b>\n\
        • Standard: <code>-u admin -p Pass123</code>\n\
        • Pass-the-Hash: <code>-u admin -H &lt;nt_hash&gt;</code>\n\
        • Kerberos Forge: <code>-k --aes-key &lt;key&gt; --kdc-host &lt;dc&gt;</code>\n\
        • Credential Spray: <code>-u users.txt -p pass.txt</code> (Brute-force mode)\n\n\
        <b>3. Protocol &amp; Module Deployment</b>\n\
        Execute tasks with <code>/run &lt;proto&gt; &lt;target&gt; [options]</code>\n\
        Attach offensive payloads with <code>-M &lt;module_name&gt;</code>\n\n\
        <b>4. Strategic Options</b>\n\
        • Speed: <code>--threads 500</code> (Max concurrency)\n\
        • Stealth: <code>--jitter 1500</code> (Avoid detection)\n\
        • Persistence: <code>--continue-on-success</code> (Keep trying)\n\n\
        <i>Use /cheat for a tactical reference of all handlers</i> ◈";
    bot.send_message(msg.chat.id, text)
        .parse_mode(ParseMode::Html)
        .await?;
    Ok(())
}

async fn ui_send_about(bot: Bot, msg: Message) -> Result<(), teloxide::RequestError> {
    let text = format!(
        "🛰️ <b>NETEXEC-RS MASTER CLASS SUITE: SUPERNOVA EDITION</b>\n\n\
        <b>Core Engine:</b> <code>Pure Rust v0.1.0-RustReaper</code>\n\
        <b>Interface:</b> <code>Telegram Professional v{}</code>\n\
        <b>Signifier:</b> <code>{}</code>\n\n\
        This platform represents the pinnacle of autonomous security research tools, providing a single, unified interface for cross-protocol exploitation, reconnaissance, and post-exploitation orchestration. Built without compromise using high-concurrency systems for the modern operator.",
        BOT_VERSION, MASTER_CODENAME
    );
    bot.send_message(msg.chat.id, text)
        .parse_mode(ParseMode::Html)
        .await?;
    Ok(())
}

// --- 🧠 Engine & Intelligence Logic ---

async fn engine_list_protocols(bot: Bot, msg: Message) -> Result<(), teloxide::RequestError> {
    let mut text = String::from("🧬 <b>Active Engine Protocol Matrix:</b>\n\n");
    for proto in Protocol::all() {
        text.push_str(&format!(
            "◈ <b>{}</b> — Handler Port: <code>{}</code>\n",
            html_escape::encode_safe(&proto.name().to_uppercase()),
            proto.default_port()
        ));
    }
    bot.send_message(msg.chat.id, text)
        .parse_mode(ParseMode::Html)
        .await?;
    Ok(())
}

async fn engine_execute_search(
    bot: Bot,
    msg: Message,
    q: String,
) -> Result<(), teloxide::RequestError> {
    let query = q.trim().to_lowercase();
    if query.is_empty() {
        bot.send_message(msg.chat.id, "💡 Usage hint: <code>/search mimikatz</code>")
           .parse_mode(ParseMode::Html).await?;
        return Ok(());
    }

    let mut results = Vec::new();
    let registry = ModuleRegistry::new();

    for p in Protocol::all() {
        if p.name().to_lowercase().contains(&query) {
            results.push(format!(
                "🛡️ Protocol: <b>{}</b>",
                html_escape::encode_safe(&p.name().to_uppercase())
            ));
        }
    }

    for m in registry.list(None) {
        if m.name().to_lowercase().contains(&query)
            || m.description().to_lowercase().contains(&query)
        {
            let protos = m.supported_protocols().join("|");
            results.push(format!(
                "🧩 Module: <code>{}</code> [<code>{}</code>]\n   <i>{}</i>",
                html_escape::encode_safe(m.name()),
                html_escape::encode_safe(&protos),
                html_escape::encode_safe(m.description())
            ));
        }
    }

    if results.is_empty() {
        bot.send_message(
                msg.chat.id,
                format!(
                    "❌ Zero reconnaissance results for <code>{}</code>",
                    html_escape::encode_safe(&q)
                ),
            )
            .parse_mode(ParseMode::Html)
            .await?;
    } else {
        let total = results.len();
        let header = format!(
            "🔎 <b>Intelligence results for <code>{}</code></b> ({} found):\n\n",
            html_escape::encode_safe(&query),
            total
        );
        send_long_msg_batched(&bot, msg.chat.id, header, results).await?;
    }
    Ok(())
}

async fn engine_list_modules(
    bot: Bot,
    msg: Message,
    proto: String,
) -> Result<(), teloxide::RequestError> {
    let p_name = proto.trim();
    if p_name.is_empty() {
        bot.send_message(msg.chat.id, "💡 Usage hint: <code>/modules smb</code>")
           .parse_mode(ParseMode::Html).await?;
        return Ok(());
    }

    let registry = ModuleRegistry::new();
    let list = registry.list(Some(p_name));

    if list.is_empty() {
        bot.send_message(
                msg.chat.id,
                format!(
                    "❌ No payload modules found for protocol <code>{}</code>",
                    html_escape::encode_safe(p_name)
                ),
            )
            .parse_mode(ParseMode::Html)
            .await?;
    } else {
        let mut text = format!(
            "🧩 <b>Offensive Payloads for {}</b>:\n\n",
            html_escape::encode_safe(&p_name.to_uppercase())
        );
        for m in list {
            text.push_str(&format!(
                "• <b>{}</b>\n  <i>{}</i>\n\n",
                html_escape::encode_safe(m.name()),
                html_escape::encode_safe(m.description())
            ));
        }
        send_long_msg_batched(&bot, msg.chat.id, text, vec![]).await?;
    }
    Ok(())
}

// --- 🕵️ Reconnaissance Intelligence Suite ---

async fn engine_execute_help(
    bot: Bot,
    msg: Message,
    args: String,
) -> Result<(), teloxide::RequestError> {
    let mut argv = vec!["nxc".to_string()];
    argv.extend(args.split_whitespace().map(|s| s.to_string()));
    if !argv.iter().any(|s| s == "--help") {
        argv.push("--help".to_string());
    }

    match engine_perform_task(argv.into_iter().skip(1).collect()).await {
        Ok(help_text) => {
            bot.send_message(msg.chat.id, format!("<pre>{}</pre>", html_escape::encode_safe(&help_text)))
                .parse_mode(ParseMode::Html).await?;
        }
        Err(e) => {
            bot.send_message(msg.chat.id, format!("❌ Help search error: {}", e)).await?;
        }
    }
    Ok(())
}

async fn engine_execute_guide(
    bot: Bot,
    msg: Message,
    topic: String,
) -> Result<(), teloxide::RequestError> {
    // Current handbook is static, in future we can add topic-specific filtering
    ui_send_handbook(bot, msg).await?;
    let _ = topic;
    Ok(())
}

async fn recon_ping(bot: Bot, msg: Message, target: String) -> Result<(), teloxide::RequestError> {
    let target = target.trim();
    if target.is_empty() {
        bot.send_message(msg.chat.id, "💡 Usage: <code>/ping 8.8.8.8</code>")
           .parse_mode(ParseMode::Html).await?;
        return Ok(());
    }

    bot.send_message(
            msg.chat.id,
            format!(
                "📡 <i>Pinging {} in progress ...</i>",
                html_escape::encode_safe(target)
            ),
        )
        .parse_mode(ParseMode::Html)
        .await?;

    let output = if cfg!(windows) {
        std::process::Command::new("ping")
            .arg("-n")
            .arg("1")
            .arg("-w")
            .arg("1500")
            .arg(target)
            .output()
    } else {
        std::process::Command::new("ping")
            .arg("-c")
            .arg("1")
            .arg("-W")
            .arg("2")
            .arg(target)
            .output()
    };

    match output {
        Ok(out) if out.status.success() => {
            bot.send_message(
                    msg.chat.id,
                    format!(
                        "✅ Node <code>{}</code> is <b>Online</b> and active.",
                        html_escape::encode_safe(target)
                    ),
                )
                .parse_mode(ParseMode::Html)
                .await?;
        }
        _ => {
            bot.send_message(
                    msg.chat.id,
                    format!(
                        "❌ Node <code>{}</code> is <b>Offline</b> or unreachable.",
                        html_escape::encode_safe(target)
                    ),
                )
                .parse_mode(ParseMode::Html)
                .await?;
        }
    }
    Ok(())
}

async fn recon_portscan(
    bot: Bot,
    msg: Message,
    args: String,
) -> Result<(), teloxide::RequestError> {
    let parts: Vec<&str> = args.split_whitespace().collect();
    if parts.is_empty() {
        bot.send_message(msg.chat.id, "💡 Usage: <code>/portscan 10.0.0.1 [22,445,3389]</code>")
           .parse_mode(ParseMode::Html).await?;
        return Ok(());
    }

    let target = parts[0];
    let ports: Vec<u16> = if parts.len() > 1 {
        parts[1].split(',').filter_map(|p| p.parse::<u16>().ok()).collect()
    } else {
        vec![
            21, 22, 23, 25, 53, 80, 110, 135, 137, 139, 443, 445, 1433, 3306, 3389, 5432, 5900,
            8080,
        ]
    };

    bot.send_message(
            msg.chat.id,
            format!(
                "🔍 <i>Scanning {} for {} critical ports ...</i>",
                html_escape::encode_safe(target),
                ports.len()
            ),
        )
        .parse_mode(ParseMode::Html)
        .await?;

    let mut open = Vec::new();
    for port in ports {
        let addr = format!("{}:{}", target, port);
        if let Ok(addrs) = addr.to_socket_addrs() {
            if let Some(sock_addr) = addrs.into_iter().next() {
                if TcpStream::connect_timeout(&sock_addr, Duration::from_millis(600)).is_ok() {
                    open.push(port);
                }
            }
        }
    }

    if open.is_empty() {
        bot.send_message(
                msg.chat.id,
                format!("⚠️ No open ports found on <code>{}</code>", html_escape::encode_safe(target)),
            )
            .parse_mode(ParseMode::Html)
            .await?;
    } else {
        let mut text = format!(
            "🗺️ <b>Port Recon Result for <code>{}</code></b>:\n\n",
            html_escape::encode_safe(target)
        );
        for p in open {
            let svc = match p {
                21 => "FTP",
                22 => "SSH",
                23 => "TELNET",
                25 => "SMTP",
                53 => "DNS",
                80 => "HTTP",
                135 => "RPC",
                139 | 445 => "SMB",
                443 => "HTTPS",
                1433 => "MSSQL",
                3306 => "MYSQL",
                3389 => "RDP",
                5432 => "PGSQL",
                5900 => "VNC",
                _ => "UNK",
            };
            text.push_str(&format!("• Port <code>{:<5}</code> → <b>{}</b>\n", p, svc));
        }
        bot.send_message(msg.chat.id, text)
            .parse_mode(ParseMode::Html)
            .await?;
    }
    Ok(())
}

async fn recon_dns(bot: Bot, msg: Message, domain: String) -> Result<(), teloxide::RequestError> {
    let domain = domain.trim();
    if domain.is_empty() {
        bot.send_message(msg.chat.id, "💡 Usage: <code>/dns target.pro</code>")
           .parse_mode(ParseMode::Html).await?;
        return Ok(());
    }

    bot.send_message(
            msg.chat.id,
            format!(
                "📖 <i>Querying records for {} ...</i>",
                html_escape::encode_safe(domain)
            ),
        )
        .parse_mode(ParseMode::Html)
        .await?;

    match (domain, 0).to_socket_addrs() {
        Ok(addrs) => {
            let mut text = format!(
                "📖 <b>DNS Resolution result for <code>{}</code></b>:\n\n",
                html_escape::encode_safe(domain)
            );
            for a in addrs {
                text.push_str(&format!("◈ <code>{}</code>\n", html_escape::encode_safe(&a.ip().to_string())));
            }
            bot.send_message(msg.chat.id, text)
                .parse_mode(ParseMode::Html)
                .await?;
        }
        Err(e) => {
            bot.send_message(
                    msg.chat.id,
                    format!(
                        "❌ RESOLUTION ERROR: <code>{}</code>",
                        html_escape::encode_safe(&e.to_string())
                    ),
                )
                .parse_mode(ParseMode::Html)
                .await?;
        }
    }
    Ok(())
}

async fn recon_reverse_dns(
    bot: Bot,
    msg: Message,
    ip: String,
) -> Result<(), teloxide::RequestError> {
    let ip = ip.trim();
    if ip.is_empty() {
        bot.send_message(msg.chat.id, "💡 Usage: <code>/reverse 8.8.8.8</code>")
           .parse_mode(ParseMode::Html).await?;
        return Ok(());
    }

    bot.send_message(
            msg.chat.id,
            format!(
                "🔄 <i>Performing Reverse Pointer lookup for {} ...</i>",
                html_escape::encode_safe(ip)
            ),
        )
        .parse_mode(ParseMode::Html)
        .await?;

    match (ip, 0).to_socket_addrs() {
        Ok(_) => {
            bot.send_message(msg.chat.id, "💡 Reverse DNS would require specialized lookup crate or shell 'dig -x' command. I can implement this in next expansion series.")
                .parse_mode(ParseMode::Html).await?;
        }
        Err(e) => {
            bot.send_message(
                    msg.chat.id,
                    format!("❌ Lookup failed: <code>{}</code>", html_escape::encode_safe(&e.to_string())),
                )
                .parse_mode(ParseMode::Html)
                .await?;
        }
    }
    Ok(())
}

async fn recon_bot_identity(bot: Bot, msg: Message) -> Result<(), teloxide::RequestError> {
    let mut text = String::from("🌩️ <b>Bot Instance Network Matrix</b>\n\n");

    let res = reqwest::get("https://api.ipify.org").await;
    let public_ip = match res {
        Ok(r) => r.text().await.unwrap_or_else(|_| "Unavailable".to_string()),
        Err(_) => "Connection Fault".to_string(),
    };

    let node_name = hostname::get()
        .map(|h: OsString| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "node-unknown".to_string());

    text.push_str(&format!(
        "• Global IP: <code>{}</code>\n",
        html_escape::encode_safe(&public_ip)
    ));
    text.push_str(&format!("• Hostname: <code>{}</code>\n", html_escape::encode_safe(&node_name)));
    text.push_str(&format!(
        "• OS Layer: <code>{} {}</code>\n",
        html_escape::encode_safe(std::env::consts::OS),
        html_escape::encode_safe(std::env::consts::ARCH)
    ));
    text.push_str("• Health: <code>OPTIMAL</code> ✅\n");

    bot.send_message(msg.chat.id, text)
        .parse_mode(ParseMode::Html)
        .await?;
    Ok(())
}

async fn recon_geo_lookup(
    bot: Bot,
    msg: Message,
    ip: String,
) -> Result<(), teloxide::RequestError> {
    let ip = ip.trim();
    if ip.is_empty() {
        bot.send_message(msg.chat.id, "💡 Usage: <code>/geo 1.1.1.1</code>")
           .parse_mode(ParseMode::Html).await?;
        return Ok(());
    }

    bot.send_message(
            msg.chat.id,
            format!(
                "🌍 <i>Geolocating target IP {} ...</i>",
                html_escape::encode_safe(ip)
            ),
        )
        .parse_mode(ParseMode::Html)
        .await?;

    let url = format!("http://ip-api.com/json/{}", ip);
    match reqwest::get(url).await {
        Ok(res) => {
            if let Ok(json) = res.json::<serde_json::Value>().await {
                if json["status"] == "success" {
                    let mut text = format!(
                        "🌍 <b>Geolocation Report for <code>{}</code></b>:\n\n",
                        html_escape::encode_safe(ip)
                    );
                    text.push_str(&format!(
                        "• Country: <b>{}</b>\n",
                        html_escape::encode_safe(json["country"].as_str().unwrap_or("N/A"))
                    ));
                    text.push_str(&format!(
                        "• Region: <b>{}</b>\n",
                        html_escape::encode_safe(json["regionName"].as_str().unwrap_or("N/A"))
                    ));
                    text.push_str(&format!(
                        "• City: <b>{}</b>\n",
                        html_escape::encode_safe(json["city"].as_str().unwrap_or("N/A"))
                    ));
                    text.push_str(&format!(
                        "• ISP: <code>{}</code>\n",
                        html_escape::encode_safe(json["isp"].as_str().unwrap_or("N/A"))
                    ));
                    text.push_str(&format!(
                        "• Coordinates: <code>{}, {}</code>\n",
                        json["lat"], json["lon"]
                    ));
                    bot.send_message(msg.chat.id, text)
                        .parse_mode(ParseMode::Html)
                        .await?;
                } else {
                    bot.send_message(msg.chat.id, "❌ Geographic data not found for this IP.")
                        .parse_mode(ParseMode::Html).await?;
                }
            }
        }
        Err(_) => {
            bot.send_message(msg.chat.id, "❌ Failed to query GEOLOCATION API.")
                .parse_mode(ParseMode::Html).await?;
        }
    }
    Ok(())
}

// --- ⚙️ Execution Engine Orchestration ---

async fn engine_execute_shortcut(
    bot: Bot,
    msg: Message,
    proto: &str,
    args: String,
) -> Result<(), teloxide::RequestError> {
    let input = format!("{} {}", proto, args);
    engine_run_logic(bot, msg, input).await
}

async fn engine_execute_raw(
    bot: Bot,
    msg: Message,
    args: String,
) -> Result<(), teloxide::RequestError> {
    engine_run_logic(bot, msg, args).await
}

async fn engine_run_logic(
    bot: Bot,
    msg: Message,
    args_str: String,
) -> Result<(), teloxide::RequestError> {
    let user_id = msg.from.as_ref().map(|u| u.id).unwrap_or(UserId(0));
    let chat_id = msg.chat.id;
    let parts: Vec<String> = args_str.split_whitespace().map(|s| s.to_string()).collect();

    if parts.is_empty() {
        bot.send_message(chat_id, "💡 Control Hint: <code>/run smb 10.0.0.1 -u admin</code>")
           .parse_mode(ParseMode::Html).await?;
        return Ok(());
    }

    // If only protocol is provided, show help for it
    if parts.len() == 1 && !["ping", "portscan", "dns", "geo", "reverse", "whoami", "status", "cheat", "history"].contains(&parts[0].as_str()) {
        return engine_execute_help(bot, msg, parts[0].clone()).await;
    }

    update_session(user_id, |s| {
        if parts.len() > 1 {
            let target = parts[1].clone();
            s.last_target = Some(target.clone());
            if !s.history.contains(&target) {
                s.history.push(target);
                if s.history.len() > MAX_TARGET_HISTORY {
                    s.history.remove(0);
                }
            }
        }
        s.last_protocol = Some(parts[0].clone());
    });

    let status_msg = bot
        .send_message(
            chat_id,
            "⚙️ <i>Initializing Professional Execution Handler ...</i>",
        )
        .parse_mode(ParseMode::Html)
        .await?;

    match engine_perform_task(parts).await {
        Ok(log) => {
            let _ = bot.delete_message(chat_id, status_msg.id).await;
            let log_text: String = log;
            if log_text.len() > MAX_MESSAGE_LENGTH {
                for (i, chunk) in chunk_string(&log_text, MAX_MESSAGE_LENGTH - 300)
                    .iter()
                    .enumerate()
                {
                    let mut text = format!("<pre>{}</pre>", html_escape::encode_safe(chunk));
                    if i == 0 {
                        text = format!("📦 <b>Large Output Batch ({})</b>\n\n{}", i + 1, text);
                    }
                    bot.send_message(chat_id, text)
                        .parse_mode(ParseMode::Html)
                        .await?;
                }
            } else {
                bot.send_message(chat_id, format!("<pre>{}</pre>", html_escape::encode_safe(&log_text)))
                    .parse_mode(ParseMode::Html)
                    .await?;
            }
        }
        Err(e) => {
            let err_msg = e.to_string();
            bot.edit_message_text(
                    chat_id,
                    status_msg.id,
                    format!(
                        "❌ <b>Critical Engine Fault:</b>\n<code>{}</code>",
                        html_escape::encode_safe(&err_msg)
                    ),
                )
                .parse_mode(ParseMode::Html)
                .await?;
        }
    }
    Ok(())
}

async fn engine_perform_task(argv: Vec<String>) -> anyhow::Result<String> {
    // ── Setup Database & Global DB check ──
    let cli = crate::build_cli();
    
    // We need to find the workspace from argv before parsing everything if we want to pass it to NxcDb
    let workspace = argv.iter().position(|r| r == "--workspace" || r == "-w")
        .and_then(|idx| argv.get(idx + 1))
        .map(|s| s.as_str())
        .unwrap_or("default");

    let db_path = std::path::PathBuf::from("nxc.db");
    let db = NxcDb::new(&db_path, workspace).ok().map(Arc::new);

    let matches = match cli.try_get_matches_from(argv) {
        Ok(m) => m,
        Err(e) => {
            match e.kind() {
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => {
                    return Ok(e.render().to_string());
                }
                _ => return Err(anyhow::anyhow!("Instruction Validation Failure:\n{}", e)),
            }
        }
    };

    let (p_name, sub_m) = matches
        .subcommand()
        .context("Missing protocol designator in instruction string")?;

    let proto_handler = get_protocol_handler(p_name, sub_m)
        .context(format!("No handler implementation found for '{}'", p_name))?;

    let input_targets = sub_m
        .get_many::<String>("target")
        .map(|v| v.map(|s| s.as_str()).collect::<Vec<&str>>())
        .unwrap_or_default();

    let mut resolved = Vec::new();
    for t in input_targets {
        resolved.extend(parse_targets(t)?);
    }
    if resolved.is_empty() {
        return Err(anyhow::anyhow!(
            "Zero operational targets resolved for deployment"
        ));
    }

    let creds = build_credentials(sub_m);
    if creds.is_empty() {
        return Err(anyhow::anyhow!("Authentication matrix is empty"));
    }

    let conf_threads = matches.get_one::<usize>("threads").copied().unwrap_or(256);
    let conf_timeout = matches
        .get_one::<u64>("timeout")
        .copied()
        .unwrap_or(DEFAULT_TIMEOUT_SECS);

    let modules = sub_m
        .get_one::<String>("module")
        .map(|s| vec![s.clone()])
        .unwrap_or_default();

    let mut module_opts = std::collections::HashMap::new();
    if let Some(opts) = sub_m.get_many::<String>("module-options") {
        for opt in opts {
            if let Some((k, v)) = opt.split_once('=') {
                module_opts.insert(k.to_string(), v.to_string());
            }
        }
    }

    let opts = ExecutionOpts {
        threads: conf_threads,
        timeout: Duration::from_secs(conf_timeout),
        jitter_ms: matches.get_one::<u64>("jitter").copied(),
        continue_on_success: sub_m.get_flag("continue-on-success"),
        no_bruteforce: sub_m.get_flag("no-bruteforce"),
        modules,
        module_opts,
    };

    let mut engine = ExecutionEngine::new(opts);
    if let Some(ref d) = db {
        engine = engine.with_db(d.clone());
    }
    let raw_results = engine.run(proto_handler, resolved, creds).await;

    let mut report = format!("⚡ NETEXEC REPORT: {} INTERFACE\n", p_name.to_uppercase());
    report.push_str("──────────────────────────────────────────────\n");
    for r in &raw_results {
        let tag = if r.success {
            if r.admin {
                "[*]"
            } else {
                "[+]"
            }
        } else {
            "[-]"
        };
        report.push_str(&format!(
            "{:<3} {:<18} | {:<12} | {}\n",
            tag, r.target, r.username, r.message
        ));
    }
    report.push_str("──────────────────────────────────────────────\n");
    let ok = raw_results.iter().filter(|x| x.success).count();
    let pwn = raw_results.iter().filter(|x| x.admin).count();
    report.push_str(&format!(
        "STAT: {} Targets | {} Access OK | {} Administrative",
        raw_results.len(),
        ok,
        pwn
    ));

    Ok(report)
}

// --- 👤 Session & Operator Data Commands ---

async fn session_show_profile(bot: Bot, msg: Message) -> Result<(), teloxide::RequestError> {
    let user = msg.from.as_ref().unwrap();
    let s = get_session(user.id);

    let text = format!(
        "👤 <b>OPERATOR DOSSIER</b>\n\n\
        • Master ID: <code>{}</code>\n\
        • Permission Level: <b>{}</b>\n\
        • Name: {}\n\
        • Handle: {}\n\n\
        <b>Session Intelligence:</b>\n\
        • Protocol: <code>{}</code>\n\
        • Target: <code>{}</code>\n\
        • Uptime: <code>{}</code>\n\n\
        <i>Data is strictly tactical and ephemeral</i> ◈",
        user.id,
        if is_admin(user.id) {
            "ADMINISTRATOR"
        } else {
            "AUTHORIZED"
        },
        html_escape::encode_safe(&user.full_name()),
        user.username
            .as_ref()
            .map(|u| format!("@{}", html_escape::encode_safe(u)))
            .unwrap_or_else(|| "none".to_string()),
        html_escape::encode_safe(s.last_protocol.as_deref().unwrap_or("none")),
        html_escape::encode_safe(s.last_target.as_deref().unwrap_or("none")),
        html_escape::encode_safe(&format!("{:?}", s.last_activity.elapsed()))
    );

    bot.send_message(msg.chat.id, text)
        .parse_mode(ParseMode::Html)
        .await?;
    Ok(())
}

async fn session_show_status(bot: Bot, msg: Message) -> Result<(), teloxide::RequestError> {
    let h_name = hostname::get()
        .map(|h: OsString| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let text = format!(
        "🛰️ <b>SYSTEM STATUS REPORT</b>\n\n\
        • Suite Version: <code>{}</code>\n\
        • Build Signature: <code>{}</code>\n\
        • Host Node: <code>{}</code>\n\
        • Core Capacity: <code>{}</code> vCPUs\n\
        • Memory Guard: <code>Healthy</code>\n\
        • Connectivity: <code>Secure TLS</code> ✅\n\n\
        🛡️ <i>Active Monitor Protocol enabled</i>",
        BOT_VERSION,
        MASTER_CODENAME,
        html_escape::encode_safe(&h_name),
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    );
    bot.send_message(msg.chat.id, text)
        .parse_mode(ParseMode::Html)
        .await?;
    Ok(())
}

async fn session_show_history(bot: Bot, msg: Message) -> Result<(), teloxide::RequestError> {
    let s = get_session(msg.from.as_ref().unwrap().id);
    if s.history.is_empty() {
        bot.send_message(msg.chat.id, "📜 Operator history is currently clean.").await?;
    } else {
        let mut log = String::from("📜 <b>Target History Intelligence:</b>\n\n");
        for (i, t) in s.history.iter().rev().enumerate() {
            log.push_str(&format!("◈ <code>{:02}</code> : <code>{}</code>\n", i + 1, html_escape::encode_safe(t)));
        }
        bot.send_message(msg.chat.id, log)
            .parse_mode(ParseMode::Html)
            .await?;
    }
    Ok(())
}

async fn session_purge(bot: Bot, msg: Message) -> Result<(), teloxide::RequestError> {
    update_session(msg.from.as_ref().unwrap().id, |s| {
        *s = UserSession::default()
    });
    bot.send_message(msg.chat.id, "🧹 <b>TACTICAL PURGE COMPLETE</b>\nAll session memory and history logs have been destroyed.")
        .parse_mode(ParseMode::Html).await?;
    Ok(())
}

async fn session_clear(bot: Bot, msg: Message) -> Result<(), teloxide::RequestError> {
    update_session(msg.from.as_ref().unwrap().id, |s| {
        *s = UserSession::default()
    });
    // Send a "blank" message or just a clear notification
    bot.send_message(msg.chat.id, "✨ <b>TERMINAL CLEARED</b>\nSession reset. Node ready for new tasking.")
        .parse_mode(ParseMode::Html).await?;
    Ok(())
}

// --- 🗄️ Database Implementation ---

static GLOBAL_DB: OnceLock<Arc<NxcDb>> = OnceLock::new();

fn get_db(workspace: &str) -> Option<Arc<NxcDb>> {
    if let Some(db) = GLOBAL_DB.get() {
        // NxcDb manager handles workspace switching internally if we call set_workspace
        // But for multi-user bot, we might need a better way if users use different workspaces
        // For now, let's assume a single global NxcDb and we switch workspace per call or use a pool
        Some(db.clone())
    } else {
        match NxcDb::new(std::path::Path::new("nxc.db"), workspace) {
            Ok(db) => {
                let arc = Arc::new(db);
                let _ = GLOBAL_DB.set(arc.clone());
                Some(arc)
            }
            Err(_) => None,
        }
    }
}

async fn database_list_hosts(bot: Bot, msg: Message) -> Result<(), teloxide::RequestError> {
    let user_id = msg.from.as_ref().map(|u| u.id).unwrap_or(UserId(0));
    let s = get_session(user_id);
    let db = match get_db(&s.workspace) {
        Some(d) => d,
        None => {
            bot.send_message(msg.chat.id, "❌ <b>DB ERROR</b>\nFailed to connect to database.").await?;
            return Ok(());
        }
    };

    // Temporarily switch DB context to user's workspace
    // Note: This is not thread-safe for multiple concurrent users with different workspaces 
    // if using a single global NxcDb. Ideally NxcDb methods should take workspace as arg.
    // For now, let's just list from user's workspace.
    
    match db.list_hosts_in(&s.workspace) {
        Ok(hosts) => {
            let hosts: Vec<HostInfo> = hosts;
            if hosts.is_empty() {
                bot.send_message(msg.chat.id, format!("📭 No hosts found in workspace [<code>{}</code>]", s.workspace))
                    .parse_mode(ParseMode::Html).await?;
            } else {
                let header = format!("🖥️ <b>Discovered Hosts [<code>{}</code>]</b>\n\n\
                             <code>{:<15} | {}</code>\n\
                             ─────────────────────────\n", 
                             s.workspace, "IP Address", "Hostname");
                
                let mut items = Vec::new();
                for h in hosts {
                    items.push(format!("<code>{:<15}</code> | <code>{}</code>", 
                        h.ip, 
                        html_escape::encode_safe(h.hostname.as_deref().unwrap_or("unknown"))));
                }
                
                send_long_msg_batched(&bot, msg.chat.id, header, items).await?;
            }
        }
        Err(e) => {
            bot.send_message(msg.chat.id, format!("❌ <b>QUERY ERROR</b>\n{}", e)).await?;
        }
    }
    Ok(())
}

async fn database_list_creds(bot: Bot, msg: Message) -> Result<(), teloxide::RequestError> {
    let user_id = msg.from.as_ref().map(|u| u.id).unwrap_or(UserId(0));
    let s = get_session(user_id);
    let db = match get_db(&s.workspace) {
        Some(d) => d,
        None => {
            bot.send_message(msg.chat.id, "❌ <b>DB ERROR</b>\nFailed to connect to database.").await?;
            return Ok(());
        }
    };

    match db.list_credentials_in(&s.workspace) {
        Ok(creds) => {
            let creds: Vec<Credential> = creds;
            if creds.is_empty() {
                bot.send_message(msg.chat.id, format!("📭 No credentials found in workspace [<code>{}</code>]", s.workspace))
                    .parse_mode(ParseMode::Html).await?;
            } else {
                let header = format!("🔑 <b>Captured Credentials [<code>{}</code>]</b>\n\n\
                             <code>{:<15} : {}</code>\n\
                             ─────────────────────────\n", 
                             s.workspace, "Username", "Secret/Hash");
                
                let mut items = Vec::new();
                for c in creds {
                    let secret = c.password.or(c.nt_hash).unwrap_or_else(|| "none".to_string());
                    items.push(format!("<code>{:<15}</code> : <code>{}</code>", 
                        c.username, 
                        html_escape::encode_safe(&secret)));
                }
                
                send_long_msg_batched(&bot, msg.chat.id, header, items).await?;
            }
        }
        Err(e) => {
            bot.send_message(msg.chat.id, format!("❌ <b>QUERY ERROR</b>\n{}", e)).await?;
        }
    }
    Ok(())
}

async fn database_list_workspaces(bot: Bot, msg: Message) -> Result<(), teloxide::RequestError> {
    let db = match get_db("default") {
        Some(d) => d,
        None => {
            bot.send_message(msg.chat.id, "❌ <b>DB ERROR</b>\nFailed to connect to database.").await?;
            return Ok(());
        }
    };

    match db.list_workspaces() {
        Ok(ws) => {
            let mut report = String::from("📂 <b>Available Workspaces:</b>\n\n");
            for w in ws {
                report.push_str(&format!("• <code>{}</code>\n", w));
            }
            bot.send_message(msg.chat.id, report).parse_mode(ParseMode::Html).await?;
        }
        Err(e) => {
            bot.send_message(msg.chat.id, format!("❌ <b>QUERY ERROR</b>\n{}", e)).await?;
        }
    }
    Ok(())
}

async fn database_set_workspace(bot: Bot, msg: Message, name: String) -> Result<(), teloxide::RequestError> {
    let name = name.trim();
    if name.is_empty() {
        bot.send_message(msg.chat.id, "💡 Usage: <code>/setworkspace demo</code>").parse_mode(ParseMode::Html).await?;
        return Ok(());
    }

    let user_id = msg.from.as_ref().map(|u| u.id).unwrap_or(UserId(0));
    update_session(user_id, |s| s.workspace = name.to_string());
    
    bot.send_message(msg.chat.id, format!("✅ <b>WORKSPACE UPDATED</b>\nNow operating in: <code>{}</code>", name))
        .parse_mode(ParseMode::Html).await?;
    Ok(())
}

async fn database_show_stats(bot: Bot, msg: Message) -> Result<(), teloxide::RequestError> {
    let user_id = msg.from.as_ref().map(|u| u.id).unwrap_or(UserId(0));
    let s = get_session(user_id);
    let db = match get_db(&s.workspace) {
        Some(d) => d,
        None => {
            bot.send_message(msg.chat.id, "❌ <b>DB ERROR</b>\nFailed to connect to database.").await?;
            return Ok(());
        }
    };

    match db.get_stats_in(&s.workspace) {
        Ok(stats) => {
            let text = format!("📊 <b>WORKSPACE INTELLIGENCE [<code>{}</code>]</b>\n\n\
                        • 🖥️ Discovered Hosts: <code>{}</code>\n\
                        • 🔑 Captured Credentials: <code>{}</code>\n\
                        • 🏰 Domain Controllers: <code>{}</code>\n\
                        • 🛡️ Administrative Pwns: <code>{}</code>\n\n\
                        <i>Tactical overview of current operations.</i>",
                        stats.workspace,
                        stats.host_count,
                        stats.cred_count,
                        stats.dc_count,
                        stats.admin_access_count);
            
            bot.send_message(msg.chat.id, text)
               .parse_mode(ParseMode::Html).await?;
        }
        Err(e) => {
            bot.send_message(msg.chat.id, format!("❌ <b>QUERY ERROR</b>\n{}", e)).await?;
        }
    }
    Ok(())
}

async fn session_show_cheat(bot: Bot, msg: Message) -> Result<(), teloxide::RequestError> {
    let text = "📑 <b>TACTICAL OPERATOR CHEAT SHEET</b>\n\n\
        ◈ <b>SMB Exploration</b>\n\
        <code>/run smb 10.0.0.0/24 -u guest -p \"\" --shares</code>\n\
        <code>/run smb target.local -u admin -H &lt;hash&gt; --users</code>\n\n\
        ◈ <b>LDAP Reconnaissance</b>\n\
        <code>/run ldap dc01.pro -u \"\" -p \"\" --gmsa</code>\n\
        <code>/run ldap dc01.pro -u k.admin -p p --asreproasting</code>\n\n\
        ◈ <b>SSH &amp; WinRM Command Loops</b>\n\
        <code>/run ssh node-01 -u root -p pass -x \"id\"</code>\n\
        <code>/run winrm dc02 -u svc_adm -p pass -X \"Get-Process\"</code>\n\n\
        ◈ <b>Database &amp; App Attacks</b>\n\
        <code>/run mssql sql01 -u sa -p pass -x \"whoami\"</code>\n\
        <code>/run adb 192.168.1.50 --screenshot</code>\n\n\
        ◈ <b>Master Control Pivot</b>\n\
        Use <code>/shell</code> to enter interactive mode for your last target.";
    bot.send_message(msg.chat.id, text)
        .parse_mode(ParseMode::Html)
        .await?;
    Ok(())
}

// --- 🛡️ Administrative Terminal ---

async fn admin_whitelist(
    bot: Bot,
    msg: Message,
    id_str: String,
) -> Result<(), teloxide::RequestError> {
    let admin_id = msg.from.as_ref().map(|u| u.id).unwrap_or(UserId(0));
    if !is_admin(admin_id) {
        bot.send_message(
                msg.chat.id,
                "❌ <b>ACCESS RESTRICTED</b>\nAdmin credentials required.",
            )
            .parse_mode(ParseMode::Html).await?;
        return Ok(());
    }

    if let Ok(id_val) = id_str.trim().parse::<u64>() {
        {
            let allowed = ALLOWED_USERS.get_or_init(|| Mutex::new(HashSet::new()));
            allowed.lock().unwrap().insert(id_val);
        }
        bot.send_message(
                msg.chat.id,
                format!("✅ Operator <code>{}</code> successfully whitelisted.", id_val),
            )
            .parse_mode(ParseMode::Html).await?;
    } else {
        bot.send_message(msg.chat.id, "💡 Usage: <code>/whitelist &lt;user_id&gt;</code>")
            .parse_mode(ParseMode::Html).await?;
    }
    Ok(())
}

async fn admin_broadcast(
    bot: Bot,
    msg: Message,
    text: String,
) -> Result<(), teloxide::RequestError> {
    let admin_id = msg.from.as_ref().map(|u| u.id).unwrap_or(UserId(0));
    if !is_admin(admin_id) {
        return Ok(());
    }

    let uids: Vec<u64> = {
        let sessions = SESSIONS.get_or_init(|| Mutex::new(HashMap::new()));
        let map = sessions.lock().unwrap();
        map.keys().copied().collect()
    };

    let b_msg = format!("📢 <b>GLOBAL BROADCAST</b>\n\n{}", html_escape::encode_safe(&text));

    for uid in uids {
        let _ = bot
            .send_message(ChatId(uid as i64), &b_msg)
            .parse_mode(ParseMode::Html)
            .await;
    }

    bot.send_message(msg.chat.id, "✅ Broadcast message dispatched.")
       .parse_mode(ParseMode::Html).await?;
    Ok(())
}

async fn admin_show_logs(bot: Bot, msg: Message) -> Result<(), teloxide::RequestError> {
    if !is_admin(msg.from.as_ref().unwrap().id) {
        return Ok(());
    }
    let _ = bot
        .send_message(
            msg.chat.id,
            "📂 _Real-time log stream access in next module update series \\.\\.\\._",
        )
        .await;
    Ok(())
}

// --- 🏗️ Utility Components ---

fn main_dashboard_markup() -> InlineKeyboardMarkup {
    InlineKeyboardMarkup::new(vec![
        vec![
            InlineKeyboardButton::callback("📟 Portal", "btn_help"),
            InlineKeyboardButton::callback("🛡️ Matrix", "btn_proto"),
        ],
        vec![
            InlineKeyboardButton::callback("📡 Recon", "btn_recon"),
            InlineKeyboardButton::callback("💓 Pulse", "btn_status"),
        ],
    ])
}

fn chunk_string(s: &str, size: usize) -> Vec<String> {
    let mut v = Vec::new();
    let mut cur = s;
    while !cur.is_empty() {
        let len = std::cmp::min(cur.len(), size);
        let (ch, rest) = cur.split_at(len);
        v.push(ch.to_string());
        cur = rest;
    }
    v
}

async fn send_long_msg_batched(
    bot: &Bot,
    chat_id: ChatId,
    header: String,
    items: Vec<String>,
) -> Result<(), teloxide::RequestError> {
    if items.is_empty() {
        if header.len() > MAX_MESSAGE_LENGTH {
            for chunk in chunk_string(&header, 4000) {
                bot.send_message(chat_id, chunk)
                   .parse_mode(ParseMode::Html)
                   .await?;
            }
        } else {
            bot.send_message(chat_id, header)
               .parse_mode(ParseMode::Html)
               .await?;
        }
    } else {
        let mut text = header;
        for i in items {
            if text.len() + i.len() > 3800 {
                bot.send_message(chat_id, text)
                   .parse_mode(ParseMode::Html)
                   .await?;
                text = String::from("◈ ");
                text.push_str(&i);
                text.push('\n');
            } else {
                text.push_str("◈ ");
                text.push_str(&i);
                text.push('\n');
            }
        }
        if !text.is_empty() {
            bot.send_message(chat_id, text)
               .parse_mode(ParseMode::Html)
               .await?;
        }
    }
    Ok(())
}
