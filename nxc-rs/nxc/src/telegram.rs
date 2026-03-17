use anyhow::Result;
use nxc_targets::{ExecutionEngine, ExecutionOpts, parse_targets};
use teloxide::prelude::*;
use teloxide::utils::command::BotCommands;
use std::time::Duration;
use crate::{build_credentials, get_protocol_handler};
use nxc_protocols::Protocol;
use nxc_modules::ModuleRegistry;

#[derive(BotCommands, Clone)]
#[command(rename_rule = "lowercase", description = "NetExec-RS Telegram Bot Commands")]
enum TelegramBotCommand {
    #[command(description = "Display this help message")]
    Help,
    #[command(description = "List all supported protocols")]
    Protocols,
    #[command(description = "List available modules for a protocol (usage: /modules <protocol>)")]
    Modules(String),
    #[command(description = "Execute an NXC command (usage: /run <protocol> <target> [options])")]
    Run(String),
}

pub async fn start_bot() -> Result<()> {
    let token = std::env::var("TELEGRAM_BOT_TOKEN")
        .map_err(|_| anyhow::anyhow!("TELEGRAM_BOT_TOKEN not found in environment"))?;

    let bot = Bot::new(token);

    println!("Starting NetExec-RS Telegram bot...");

    TelegramBotCommand::repl(bot, handle_command).await;

    Ok(())
}

async fn handle_command(bot: Bot, msg: Message, cmd: TelegramBotCommand) -> ResponseResult<()> {
    match cmd {
        TelegramBotCommand::Help => {
            let help_text = format!(
                "**NetExec-RS Bot Help**\n\n\
                Commands:\n\
                /protocols - List all supported protocols\n\
                /modules <protocol> - List modules for a protocol\n\
                /run <protocol> <target> [options] - Execute a command\n\n\
                **Examples:**\n\
                `/run smb 192.168.1.0/24 -u admin -p Pass123`\n\
                `/run ssh 10.0.0.5 -u root --key-file id_rsa`\n\
                `/modules smb`"
            );
            bot.send_message(msg.chat.id, help_text)
                .parse_mode(teloxide::types::ParseMode::MarkdownV2)
                .await?;
        }
        TelegramBotCommand::Protocols => {
            let mut text = String::from("**Supported Protocols:**\n\n");
            for proto in Protocol::all() {
                text.push_str(&format!("• `{:<6}` (Port {})\n", proto.name(), proto.default_port()));
            }
            bot.send_message(msg.chat.id, text)
                .parse_mode(teloxide::types::ParseMode::MarkdownV2)
                .await?;
        }
        TelegramBotCommand::Modules(proto_name) => {
            let proto_name = proto_name.trim();
            if proto_name.is_empty() {
                bot.send_message(msg.chat.id, "Usage: `/modules <protocol>`")
                    .parse_mode(teloxide::types::ParseMode::MarkdownV2)
                    .await?;
                return Ok(());
            }

            let registry = ModuleRegistry::new();
            let modules = registry.list(Some(proto_name));

            if modules.is_empty() {
                bot.send_message(msg.chat.id, format!("No modules found for protocol `{}`", proto_name))
                    .parse_mode(teloxide::types::ParseMode::MarkdownV2)
                    .await?;
            } else {
                let mut text = format!("**Modules for `{}`:**\n\n", proto_name.to_uppercase());
                for module in modules {
                    text.push_str(&format!("• **{}**: {}\n", module.name(), module.description()));
                }
                bot.send_message(msg.chat.id, text)
                    .parse_mode(teloxide::types::ParseMode::MarkdownV2)
                    .await?;
            }
        }
        TelegramBotCommand::Run(args_str) => {
            let chat_id = msg.chat.id;
            
            let args: Vec<String> = args_str.split_whitespace().map(|s| s.to_string()).collect();
            if args.is_empty() {
                bot.send_message(chat_id, "Usage: `/run <protocol> <target> [options]`")
                    .parse_mode(teloxide::types::ParseMode::MarkdownV2)
                    .await?;
                return Ok(());
            }

            bot.send_message(chat_id, "⚙️ _Executing command..._")
                .parse_mode(teloxide::types::ParseMode::MarkdownV2)
                .await?;

            match execute_nxc_command(args).await {
                Ok(output) => {
                    if output.len() > 4000 {
                        let truncated = format!("{}...\n\n⚠️ _Output truncated due to Telegram limit._", &output[..3900]);
                        bot.send_message(chat_id, format!("```\n{}\n```", truncated))
                            .parse_mode(teloxide::types::ParseMode::MarkdownV2) // Use V2 for blocks
                            .await?;
                    } else {
                        bot.send_message(chat_id, output)
                            .parse_mode(teloxide::types::ParseMode::MarkdownV2)
                            .await?;
                    }
                }
                Err(e) => {
                    bot.send_message(chat_id, format!("❌ **Error:**\n`{}`", e))
                        .parse_mode(teloxide::types::ParseMode::MarkdownV2)
                        .await?;
                }
            }
        }
    }
    Ok(())
}

async fn execute_nxc_command(args: Vec<String>) -> Result<String> {
    let mut full_args = vec!["nxc".to_string()];
    full_args.extend(args);

    let app = crate::build_cli();
    let matches = match app.try_get_matches_from(full_args) {
        Ok(m) => m,
        Err(e) => return Err(anyhow::anyhow!("CLI Parse Error:\n{}", e)),
    };

    let (protocol_name, sub_matches) = match matches.subcommand() {
        Some((name, sub_m)) => (name, sub_m),
        None => return Err(anyhow::anyhow!("No protocol specified")),
    };

    let protocol = match get_protocol_handler(protocol_name, sub_matches) {
        Some(p) => p,
        None => return Err(anyhow::anyhow!("Protocol '{}' not implemented", protocol_name)),
    };

    let target_specs: Vec<&str> = sub_matches
        .get_many::<String>("target")
        .map(|vals| vals.map(|s| s.as_str()).collect())
        .unwrap_or_default();

    let mut all_targets = Vec::new();
    for spec in target_specs {
        all_targets.extend(parse_targets(spec)?);
    }

    if all_targets.is_empty() {
        return Err(anyhow::anyhow!("No valid targets specified"));
    }

    let creds = build_credentials(sub_matches);
    if creds.is_empty() {
        return Err(anyhow::anyhow!("No credentials specified"));
    }

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

    let engine = ExecutionEngine::new(exec_opts);
    let results = engine.run(protocol, all_targets, creds).await;

    let mut output = format!("🚀 **Execution Results ({})**\n\n", protocol_name.to_uppercase());
    let successes = results.iter().filter(|r| r.success).count();
    let admins = results.iter().filter(|r| r.admin).count();

    for result in &results {
        let status_emoji = if result.success {
            if result.admin { "🔥" } else { "✅" }
        } else {
            "❌"
        };
        
        output.push_str(&format!(
            "{} `{}` | **{}** | {}\n",
            status_emoji, result.target, result.username, result.message
        ));
    }

    output.push_str(&format!(
        "\n📊 **Summary:**\n• Total: {}\n• Success: {}\n• Admin: {}",
        results.len(), successes, admins
    ));

    Ok(output)
}
