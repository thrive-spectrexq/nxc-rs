use anyhow::{Context, Result};
use std::sync::Arc;
use std::io::Write;
use colored::Colorize;
use nxc_ai::{AiAgent, GeminiProvider, ToolRegistry, ScanTool, ProtocolTool, QueryDbTool, SearchModulesTool, UtilityTool, agent::CliFeedback};
use nxc_db::NxcDb;
use nxc_modules::ModuleRegistry;

pub async fn handle_ai_mode(
    initial_prompt: Option<String>,
    provider_name: &str,
    model: Option<String>,
) -> Result<()> {
    dotenvy::dotenv().ok();

    let api_key = match provider_name {
        "gemini" => {
            std::env::var("GEMINI_API_KEY").context("GEMINI_API_KEY not found in .env")
        }
        "openai" => {
            std::env::var("OPENAI_API_KEY").context("OPENAI_API_KEY not found in .env")
        }
        "anthropic" => std::env::var("ANTHROPIC_API_KEY")
            .context("ANTHROPIC_API_KEY not found in .env"),
        _ => anyhow::bail!("Unsupported AI provider: {}", provider_name),
    }?;

    println!(
        "{} Initializing AI Automation Engine with provider: {}...",
        "◆".cyan().bold(),
        provider_name.yellow().bold()
    );

    // Initialize AI Agent
    let provider: Box<dyn nxc_ai::providers::AiProvider> = match provider_name {
        "gemini" => Box::new(GeminiProvider::new(api_key, model)),
        _ => anyhow::bail!("Provider {} is not yet fully implemented", provider_name),
    };

    // Initialize shared resources for AI tools
    let db_path = std::path::Path::new("nxc.db");
    let db = Arc::new(NxcDb::new(db_path, "default")?);
    let registry_mod = Arc::new(ModuleRegistry::new());

    let mut registry = ToolRegistry::new();
    registry.register(Box::new(ScanTool));
    registry.register(Box::new(ProtocolTool));
    registry.register(Box::new(QueryDbTool::new(db)));
    registry.register(Box::new(SearchModulesTool::new(registry_mod)));
    registry.register(Box::new(UtilityTool));

    let mut agent = AiAgent::new(provider, registry, Box::new(CliFeedback));

    // If an initial prompt was provided on CLI, run it first
    if let Some(prompt) = initial_prompt {
        println!("{} Goal: {}", "🛰️".green().bold(), prompt.green().bold());
        if let Err(e) = agent.run(&prompt).await {
            eprintln!("{} AI Error: {}", "ERROR".red().bold(), e);
        }
    }

    // Enter conversational mode
    loop {
        print!("\n{} > ", "AI".cyan().bold());
        std::io::stdout().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let input = input.trim();

        if input.is_empty() {
            continue;
        }

        match input.to_lowercase().as_str() {
            "exit" | "quit" | "bye" => {
                println!("{} Mission complete. Standby.", "⏹".red().bold());
                break;
            }
            _ => {
                if let Err(e) = agent.run(input).await {
                    eprintln!("{} AI Error: {}", "ERROR".red().bold(), e);
                }
            }
        }
    }

    Ok(())
}
