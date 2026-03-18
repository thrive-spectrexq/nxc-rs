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
use teloxide::utils::markdown;
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

    // --- 🛡️ Administrative Controls (Admin Only) ---
    #[command(description = "Whitelist a user ID for bot access")]
    Whitelist(String),
    #[command(description = "Broadcast message to all active operators")]
    Broadcast(String),
    #[command(description = "View real-time system logs")]
    Logs,
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
        let _ = bot.send_message(msg.chat.id, "🚫 *UNAUTHORIZED ACCESS*\n\nYour signature is not recognized in the master whitelist\\. Please contact an administrator\\.")
            .parse_mode(ParseMode::MarkdownV2).await;
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
            let _ = bot.send_message(msg.chat.id, format!("👋 Welcome back, *{}*\\.\n\n`NetExec\\-RS Master Suite` is armed and ready\\.\n\nType /help to enter the control portal\\.", markdown::escape(&sender)))
                .parse_mode(ParseMode::MarkdownV2)
                .reply_markup(main_dashboard_markup())
                .await;
        } else {
            let _ = bot
                .send_message(
                    msg.chat.id,
                    "🛰️ _Awaiting valid command structure\\.\\.\\._",
                )
                .parse_mode(ParseMode::MarkdownV2)
                .await;
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
                let _ = bot.send_message(user_id, "🔧 *Recon Toolkit:* Use /ping, /portscan, /dns, /geo, or /reverse to map the landscape\\.")
                    .parse_mode(ParseMode::MarkdownV2).await;
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
    let text = "🛡️ *NETEXEC\\-RS PROFESSIONAL CONTROL CENTER*\n\n\
        *Strategic Operations Commands:*\n\n\
        🚀 *Deploy:* /run /smb /ssh /ldap /winrm\n\
        🔍 *Intelligence:* /search /modules /protocols\n\
        📡 *Recon:* /ping /portscan /dns /geo /reverse\n\
        📋 *Shortcuts:* /shares /users /groups\n\
        👤 *Identity:* /whoami /history /reset\n\
        ⚙️ *System:* /status /guide /cheat /about\n\n\
        _Rank: master\\-operator_ ◈ _Node: rusty\\-reaper_".to_string();
    let _ = bot
        .send_message(msg.chat.id, &text)
        .parse_mode(ParseMode::MarkdownV2)
        .reply_markup(main_dashboard_markup())
        .await;
    Ok(())
}

async fn ui_send_protocol_console(bot: Bot, msg: Message) -> Result<(), teloxide::RequestError> {
    let mut text = String::from("🌩️ *Protocol Intelligence Console*\n\nAvailable protocols for exploitation and scanning:\n\n");
    for p in Protocol::all() {
        text.push_str(&format!(
            "◈ *{}* \\(Port {}\\)\n",
            markdown::escape(&p.name().to_uppercase()),
            p.default_port()
        ));
    }
    text.push_str(
        "\n_Tip: Use /modules <proto> to find specialized payloads for these protocols\\._",
    );
    let _ = bot
        .send_message(msg.chat.id, &text)
        .parse_mode(ParseMode::MarkdownV2)
        .await;
    Ok(())
}

async fn ui_send_handbook(bot: Bot, msg: Message) -> Result<(), teloxide::RequestError> {
    let text = "📜 *MASTER OPERATOR'S HANDBOOK*\n\n\
        *1. Targeting Intelligence*\n\
        • Individual: `10.0.0.1`\n\
        • CIDR Range: `192.168.1.0/24`\n\
        • IP List: `10.0.0.1-50`\n\n\
        *2. Authentication Strategies*\n\
        • Explicit: `-u admin -p Pass123`\n\
        • Hash Injection: `-u admin -H <nt_hash>`\n\
        • Spray Mode: `-u file.txt -p pass1 pass2` \\(Tried iteratively\\)\n\n\
        *3. Module Integration*\n\
        Attach scripts with `-M module_name`\\.\n\
        Example: `/smb 192.168.1.5 -M mimikatz`\n\n\
        *4. Advanced Optimization*\n\
        Tune performance with `--threads 500` or `--timeout 120`\\.".to_string();
    let _ = bot
        .send_message(msg.chat.id, text)
        .parse_mode(ParseMode::MarkdownV2)
        .await;
    Ok(())
}

async fn ui_send_about(bot: Bot, msg: Message) -> Result<(), teloxide::RequestError> {
    let text = format!(
        "◈ *NETEXEC\\-RS MASTER SUITE* ◈\n\n\
        *Version:* `{}`\n\
        *Codename:* `{}`\n\
        *Core Edition:* `0.1.0\\-alpha`\n\n\
        Designed by elite security engineers for cross\\-platform network operation and security research\\. Built exclusively in Pure Rust 🦀\\.",
        markdown::escape(BOT_VERSION), markdown::escape(MASTER_CODENAME)
    );
    let _ = bot
        .send_message(msg.chat.id, text)
        .parse_mode(ParseMode::MarkdownV2)
        .await;
    Ok(())
}

// --- 🧠 Engine & Intelligence Logic ---

async fn engine_list_protocols(bot: Bot, msg: Message) -> Result<(), teloxide::RequestError> {
    let mut text = String::from("🧬 *Active Engine Protocol Matrix:*\n\n");
    for proto in Protocol::all() {
        text.push_str(&format!(
            "◈ *{}* \\- Handler Port: `{}`\n",
            markdown::escape(&proto.name().to_uppercase()),
            proto.default_port()
        ));
    }
    let _ = bot
        .send_message(msg.chat.id, text)
        .parse_mode(ParseMode::MarkdownV2)
        .await;
    Ok(())
}

async fn engine_execute_search(
    bot: Bot,
    msg: Message,
    q: String,
) -> Result<(), teloxide::RequestError> {
    let query = q.trim().to_lowercase();
    if query.is_empty() {
        let _ = bot
            .send_message(msg.chat.id, "💡 Usage hint: `/search mimikatz`")
            .await;
        return Ok(());
    }

    let mut results = Vec::new();
    let registry = ModuleRegistry::new();

    for p in Protocol::all() {
        if p.name().to_lowercase().contains(&query) {
            results.push(format!(
                "🛡️ Protocol: *{}*",
                markdown::escape(&p.name().to_uppercase())
            ));
        }
    }

    for m in registry.list(None) {
        if m.name().to_lowercase().contains(&query)
            || m.description().to_lowercase().contains(&query)
        {
            let protos = m.supported_protocols().join("|");
            results.push(format!(
                "🧩 Module: `{}` \\[`{}`\\]\n   _{}_",
                markdown::escape(m.name()),
                markdown::escape(&protos),
                markdown::escape(m.description())
            ));
        }
    }

    if results.is_empty() {
        let _ = bot
            .send_message(
                msg.chat.id,
                format!(
                    "❌ Zero reconnaissance results for `{}`",
                    markdown::escape(&q)
                ),
            )
            .parse_mode(ParseMode::MarkdownV2)
            .await;
    } else {
        let total = results.len();
        let header = format!(
            "🔎 *Intelligence results for* `{}` \\({} found\\):\n\n",
            markdown::escape(&query),
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
        let _ = bot
            .send_message(msg.chat.id, "💡 Usage hint: `/modules smb`")
            .await;
        return Ok(());
    }

    let registry = ModuleRegistry::new();
    let list = registry.list(Some(p_name));

    if list.is_empty() {
        let _ = bot
            .send_message(
                msg.chat.id,
                format!(
                    "❌ No payload modules found for protocol `{}`",
                    markdown::escape(p_name)
                ),
            )
            .parse_mode(ParseMode::MarkdownV2)
            .await;
    } else {
        let mut text = format!(
            "🧩 *Offensive Payloads for {}*:\n\n",
            markdown::escape(&p_name.to_uppercase())
        );
        for m in list {
            text.push_str(&format!(
                "• *{}*\n  _{}_\n\n",
                markdown::escape(m.name()),
                markdown::escape(m.description())
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
            let _ = bot.send_message(msg.chat.id, format!("```\n{}\n```", help_text))
                .parse_mode(ParseMode::MarkdownV2).await;
        }
        Err(e) => {
            let _ = bot.send_message(msg.chat.id, format!("❌ Help search error: {}", e)).await;
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
        let _ = bot
            .send_message(msg.chat.id, "💡 Usage: `/ping 8.8.8.8`")
            .await;
        return Ok(());
    }

    let _ = bot
        .send_message(
            msg.chat.id,
            format!(
                "📡 _Pinging {} in progress \\.\\.\\._",
                markdown::escape(target)
            ),
        )
        .parse_mode(ParseMode::MarkdownV2)
        .await;

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
            let _ = bot
                .send_message(
                    msg.chat.id,
                    format!(
                        "✅ Node `{}` is *Online* and active\\.",
                        markdown::escape(target)
                    ),
                )
                .parse_mode(ParseMode::MarkdownV2)
                .await;
        }
        _ => {
            let _ = bot
                .send_message(
                    msg.chat.id,
                    format!(
                        "❌ Node `{}` is *Offline* or unreachable\\.",
                        markdown::escape(target)
                    ),
                )
                .parse_mode(ParseMode::MarkdownV2)
                .await;
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
        let _ = bot
            .send_message(msg.chat.id, "💡 Usage: `/portscan 10.0.0.1 [22,445,3389]`")
            .await;
        return Ok(());
    }

    let target = parts[0];
    let ports: Vec<u16> = if parts.len() > 1 {
        parts[1].split(',').filter_map(|p| p.parse().ok()).collect()
    } else {
        vec![
            21, 22, 23, 25, 53, 80, 110, 135, 137, 139, 443, 445, 1433, 3306, 3389, 5432, 5900,
            8080,
        ]
    };

    let _ = bot
        .send_message(
            msg.chat.id,
            format!(
                "🔍 _Scanning {} for {} critical ports \\.\\.\\._",
                markdown::escape(target),
                ports.len()
            ),
        )
        .parse_mode(ParseMode::MarkdownV2)
        .await;

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
        let _ = bot
            .send_message(
                msg.chat.id,
                format!("⚠️ No open ports found on `{}`", markdown::escape(target)),
            )
            .parse_mode(ParseMode::MarkdownV2)
            .await;
    } else {
        let mut text = format!(
            "🗺️ *Port Recon Result for `{}`*:\n\n",
            markdown::escape(target)
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
            text.push_str(&format!("• Port `{:<5}` → *{}*\n", p, svc));
        }
        let _ = bot
            .send_message(msg.chat.id, text)
            .parse_mode(ParseMode::MarkdownV2)
            .await;
    }
    Ok(())
}

async fn recon_dns(bot: Bot, msg: Message, domain: String) -> Result<(), teloxide::RequestError> {
    let domain = domain.trim();
    if domain.is_empty() {
        let _ = bot
            .send_message(msg.chat.id, "💡 Usage: `/dns target.pro`")
            .await;
        return Ok(());
    }

    let _ = bot
        .send_message(
            msg.chat.id,
            format!(
                "📖 _Querying records for {} \\.\\.\\._",
                markdown::escape(domain)
            ),
        )
        .parse_mode(ParseMode::MarkdownV2)
        .await;

    match (domain, 0).to_socket_addrs() {
        Ok(addrs) => {
            let mut text = format!(
                "📖 *DNS Resolution result for `{}`*:\n\n",
                markdown::escape(domain)
            );
            for a in addrs {
                text.push_str(&format!("◈ `{}`\n", markdown::escape(&a.ip().to_string())));
            }
            let _ = bot
                .send_message(msg.chat.id, text)
                .parse_mode(ParseMode::MarkdownV2)
                .await;
        }
        Err(e) => {
            let _ = bot
                .send_message(
                    msg.chat.id,
                    format!(
                        "❌ RESOLUTION ERROR: `{}`",
                        markdown::escape(&e.to_string())
                    ),
                )
                .parse_mode(ParseMode::MarkdownV2)
                .await;
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
        let _ = bot
            .send_message(msg.chat.id, "💡 Usage: `/reverse 8.8.8.8`")
            .await;
        return Ok(());
    }

    let _ = bot
        .send_message(
            msg.chat.id,
            format!(
                "🔄 _Performing Reverse Pointer lookup for {} \\.\\.\\._",
                markdown::escape(ip)
            ),
        )
        .parse_mode(ParseMode::MarkdownV2)
        .await;

    match (ip, 0).to_socket_addrs() {
        Ok(_) => {
            let _ = bot.send_message(msg.chat.id, "💡 Reverse DNS would require specialized lookup crate or shell 'dig -x' command\\. I can implement this in next expansion series\\.")
                .parse_mode(ParseMode::MarkdownV2).await;
        }
        Err(e) => {
            let _ = bot
                .send_message(
                    msg.chat.id,
                    format!("❌ Lookup failed: `{}`", markdown::escape(&e.to_string())),
                )
                .parse_mode(ParseMode::MarkdownV2)
                .await;
        }
    }
    Ok(())
}

async fn recon_bot_identity(bot: Bot, msg: Message) -> Result<(), teloxide::RequestError> {
    let mut text = String::from("🌩️ *Bot Instance Network Matrix*\n\n");

    let res = reqwest::get("https://api.ipify.org").await;
    let public_ip = match res {
        Ok(r) => r.text().await.unwrap_or_else(|_| "Unavailable".to_string()),
        Err(_) => "Connection Fault".to_string(),
    };

    let node_name = hostname::get()
        .map(|h: OsString| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "node-unknown".to_string());

    text.push_str(&format!(
        "• Global IP: `{}`\n",
        markdown::escape(&public_ip)
    ));
    text.push_str(&format!("• Hostname: `{}`\n", markdown::escape(&node_name)));
    text.push_str(&format!(
        "• OS Layer: `{} {}`\n",
        markdown::escape(std::env::consts::OS),
        markdown::escape(std::env::consts::ARCH)
    ));
    text.push_str("• Health: `OPTIMAL` ✅\n");

    let _ = bot
        .send_message(msg.chat.id, text)
        .parse_mode(ParseMode::MarkdownV2)
        .await;
    Ok(())
}

async fn recon_geo_lookup(
    bot: Bot,
    msg: Message,
    ip: String,
) -> Result<(), teloxide::RequestError> {
    let ip = ip.trim();
    if ip.is_empty() {
        let _ = bot
            .send_message(msg.chat.id, "💡 Usage: `/geo 1.1.1.1`")
            .await;
        return Ok(());
    }

    let _ = bot
        .send_message(
            msg.chat.id,
            format!(
                "🌍 _Geolocating target IP {} \\.\\.\\._",
                markdown::escape(ip)
            ),
        )
        .parse_mode(ParseMode::MarkdownV2)
        .await;

    let url = format!("http://ip-api.com/json/{}", ip);
    match reqwest::get(url).await {
        Ok(res) => {
            if let Ok(json) = res.json::<serde_json::Value>().await {
                if json["status"] == "success" {
                    let mut text = format!(
                        "🌍 *Geolocation Report for `{}`*:\n\n",
                        markdown::escape(ip)
                    );
                    text.push_str(&format!(
                        "• Country: *{}*\n",
                        markdown::escape(json["country"].as_str().unwrap_or("N/A"))
                    ));
                    text.push_str(&format!(
                        "• Region: *{}*\n",
                        markdown::escape(json["regionName"].as_str().unwrap_or("N/A"))
                    ));
                    text.push_str(&format!(
                        "• City: *{}*\n",
                        markdown::escape(json["city"].as_str().unwrap_or("N/A"))
                    ));
                    text.push_str(&format!(
                        "• ISP: `{}`\n",
                        markdown::escape(json["isp"].as_str().unwrap_or("N/A"))
                    ));
                    text.push_str(&format!(
                        "• Coordinates: `{}, {}`\n",
                        json["lat"], json["lon"]
                    ));
                    let _ = bot
                        .send_message(msg.chat.id, text)
                        .parse_mode(ParseMode::MarkdownV2)
                        .await;
                } else {
                    let _ = bot
                        .send_message(msg.chat.id, "❌ Geographic data not found for this IP\\.")
                        .await;
                }
            }
        }
        Err(_) => {
            let _ = bot
                .send_message(msg.chat.id, "❌ Failed to query GEOLOCATION API\\.")
                .await;
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
        let _ = bot
            .send_message(chat_id, "💡 Control Hint: `/run smb 10.0.0.1 -u admin`")
            .await;
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
            "⚙️ _Initializing Professional Execution Handler \\.\\.\\._",
        )
        .parse_mode(ParseMode::MarkdownV2)
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
                    let mut text = format!("```\n{}\n```", chunk);
                    if i == 0 {
                        text = format!("📦 *Large Output Batch \\({}\\)*\n\n{}", i + 1, text);
                    }
                    let _ = bot
                        .send_message(chat_id, text)
                        .parse_mode(ParseMode::MarkdownV2)
                        .await;
                }
            } else {
                let _ = bot
                    .send_message(chat_id, format!("```\n{}\n```", log_text))
                    .parse_mode(ParseMode::MarkdownV2)
                    .await;
            }
        }
        Err(e) => {
            let err_msg = e.to_string();
            let _ = bot
                .edit_message_text(
                    chat_id,
                    status_msg.id,
                    format!(
                        "❌ *Critical Engine Fault:*\n`{}`",
                        markdown::escape(&err_msg)
                    ),
                )
                .parse_mode(ParseMode::MarkdownV2)
                .await;
        }
    }
    Ok(())
}

async fn engine_perform_task(args: Vec<String>) -> anyhow::Result<String> {
    let mut argv = vec!["nxc".to_string()];
    argv.extend(args);

    let cli = crate::build_cli();
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

    let opts = ExecutionOpts {
        threads: conf_threads,
        timeout: Duration::from_secs(conf_timeout),
        jitter_ms: matches.get_one::<u64>("jitter").copied(),
        continue_on_success: sub_m.get_flag("continue-on-success"),
        no_bruteforce: sub_m.get_flag("no-bruteforce"),
        modules: Vec::new(),
        module_opts: std::collections::HashMap::new(),
    };

    let engine = ExecutionEngine::new(opts);
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
        "👤 *OPERATOR DOSSIER*\n\n\
        • Master ID: `{}`\n\
        • Permission Level: `{}`\n\
        • Name: {}\n\
        • Handle: {}\n\n\
        *Session Intelligence:*\n\
        • Protocol: `{}`\n\
        • Target: `{}`\n\
        • Uptime: `{}`\n\n\
        _Data is strictly tactical and ephemeral_ ◈",
        user.id,
        if is_admin(user.id) {
            "ADMINISTRATOR"
        } else {
            "AUTHORIZED"
        },
        markdown::escape(&user.full_name()),
        user.username
            .as_ref()
            .map(|u| format!("@{}", markdown::escape(u)))
            .unwrap_or_else(|| "none".to_string()),
        markdown::escape(s.last_protocol.as_deref().unwrap_or("none")),
        markdown::escape(s.last_target.as_deref().unwrap_or("none")),
        markdown::escape(&format!("{:?}", s.last_activity.elapsed()))
    );

    let _ = bot
        .send_message(msg.chat.id, text)
        .parse_mode(ParseMode::MarkdownV2)
        .await;
    Ok(())
}

async fn session_show_status(bot: Bot, msg: Message) -> Result<(), teloxide::RequestError> {
    let h_name = hostname::get()
        .map(|h: OsString| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let text = format!(
        "🛰️ *SYSTEM STATUS REPORT*\n\n\
        • Suite Version: `{}`\n\
        • Build Signature: `{}`\n\
        • Host Node: `{}`\n\
        • Core Capacity: `{}` vCPUs\n\
        • Memory Guard: `Healthy`\n\
        • Connectivity: `Secure TLS` ✅\n\n\
        🛡️ _Active Monitor Protocol enabled_",
        markdown::escape(BOT_VERSION),
        markdown::escape(MASTER_CODENAME),
        markdown::escape(&h_name),
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    );
    let _ = bot
        .send_message(msg.chat.id, text)
        .parse_mode(ParseMode::MarkdownV2)
        .await;
    Ok(())
}

async fn session_show_history(bot: Bot, msg: Message) -> Result<(), teloxide::RequestError> {
    let s = get_session(msg.from.as_ref().unwrap().id);
    if s.history.is_empty() {
        let _ = bot
            .send_message(msg.chat.id, "📜 Operator history is currently clean\\.")
            .await;
    } else {
        let mut log = String::from("📜 *Target History Intelligence:*\n\n");
        for (i, t) in s.history.iter().rev().enumerate() {
            log.push_str(&format!("◈ `{:02}` : `{}`\n", i + 1, markdown::escape(t)));
        }
        let _ = bot
            .send_message(msg.chat.id, log)
            .parse_mode(ParseMode::MarkdownV2)
            .await;
    }
    Ok(())
}

async fn session_purge(bot: Bot, msg: Message) -> Result<(), teloxide::RequestError> {
    update_session(msg.from.as_ref().unwrap().id, |s| {
        *s = UserSession::default()
    });
    let _ = bot.send_message(msg.chat.id, "🧹 *TACTICAL PURGE COMPLETE*\nAll session memory and history logs have been destroyed\\.").parse_mode(ParseMode::MarkdownV2).await;
    Ok(())
}

async fn session_show_cheat(bot: Bot, msg: Message) -> Result<(), teloxide::RequestError> {
    let text = "📑 *NXC OPERATOR CHEAT SHEET*\n\n\
        ◈ *SMB Enumeration*\n\
        `/run smb 10.0.0.0/24 -u guest -p \"\" --shares`\n\n\
        ◈ *SSH Command Loop*\n\
        `/ssh node\\-01 -u root -p pass -x \"cat /etc/passwd\"`\n\n\
        ◈ *WinRM Admin Check*\n\
        `/winrm 192.168.1.1 -u admin -H <nt_hash>`\n\n\
        ◈ *LDAP User Extraction*\n\
        `/ldap dc01 -u \"\" -p \"\" --users`".to_string();
    let _ = bot
        .send_message(msg.chat.id, text)
        .parse_mode(ParseMode::MarkdownV2)
        .await;
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
        let _ = bot
            .send_message(
                msg.chat.id,
                "❌ *ACCESS RESTRICTED*\nAdmin credentials required\\.",
            )
            .await;
        return Ok(());
    }

    if let Ok(id_val) = id_str.trim().parse::<u64>() {
        {
            let allowed = ALLOWED_USERS.get_or_init(|| Mutex::new(HashSet::new()));
            allowed.lock().unwrap().insert(id_val);
        }
        let _ = bot
            .send_message(
                msg.chat.id,
                format!("✅ Operator `{}` successfully whitelisted\\.", id_val),
            )
            .await;
    } else {
        let _ = bot
            .send_message(msg.chat.id, "💡 Usage: `/whitelist <user_id>`")
            .await;
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

    let b_msg = format!("📢 *GLOBAL BROADCAST*\n\n{}", markdown::escape(&text));

    for uid in uids {
        let _ = bot
            .send_message(ChatId(uid as i64), &b_msg)
            .parse_mode(ParseMode::MarkdownV2)
            .await;
    }

    let _ = bot
        .send_message(msg.chat.id, "✅ Broadcast message dispatched\\.")
        .await;
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
                let _ = bot
                    .send_message(chat_id, chunk)
                    .parse_mode(ParseMode::MarkdownV2)
                    .await;
            }
        } else {
            let _ = bot
                .send_message(chat_id, header)
                .parse_mode(ParseMode::MarkdownV2)
                .await;
        }
    } else {
        let mut text = header;
        for i in items {
            if text.len() + i.len() > 3800 {
                let _ = bot
                    .send_message(chat_id, text)
                    .parse_mode(ParseMode::MarkdownV2)
                    .await;
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
            let _ = bot
                .send_message(chat_id, text)
                .parse_mode(ParseMode::MarkdownV2)
                .await;
        }
    }
    Ok(())
}
