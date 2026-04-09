use anyhow::{Context, Result};
use std::sync::Arc;
use std::io::Write;
use colored::Colorize;
use nxc_ai::{AiAgent, GeminiProvider, ToolRegistry, ScanTool, ProtocolTool, QueryDbTool, SearchModulesTool, UtilityTool, agent::CliFeedback};
use nxc_db::NxcDb;
use nxc_modules::ModuleRegistry;

pub async fn handle_ai_mode(
    initial_prompt: Option<String>,
    provider_name: Option<String>,
    model: Option<String>,
) -> Result<()> {
    dotenvy::dotenv().ok();

    let (detected_provider, api_key) = match provider_name.as_deref() {
        Some("gemini") => ("gemini".to_string(), std::env::var("GEMINI_API_KEY").context("GEMINI_API_KEY not found in .env")?),
        Some("openai") => ("openai".to_string(), std::env::var("OPENAI_API_KEY").context("OPENAI_API_KEY not found in .env")?),
        Some("anthropic") => ("anthropic".to_string(), std::env::var("ANTHROPIC_API_KEY").context("ANTHROPIC_API_KEY not found in .env")?),
        Some("ollama") => ("ollama".to_string(), std::env::var("OLLAMA_API_BASE").unwrap_or_else(|_| "http://localhost:11434".to_string())),
        Some(p) => anyhow::bail!("Unsupported AI provider: {}", p),
        None => {
            // Auto-detect based on env vars
            if let Ok(k) = std::env::var("GEMINI_API_KEY") {
                ("gemini".to_string(), k)
            } else if let Ok(k) = std::env::var("OPENAI_API_KEY") {
                ("openai".to_string(), k)
            } else if let Ok(k) = std::env::var("ANTHROPIC_API_KEY") {
                ("anthropic".to_string(), k)
            } else if let Ok(k) = std::env::var("OLLAMA_API_BASE") {
                ("ollama".to_string(), k)
            } else {
                anyhow::bail!("No AI provider specified and no API keys found in environment. Set GEMINI_API_KEY, OPENAI_API_KEY, etc.");
            }
        }
    };

    println!(
        "{} Initializing AI Automation Engine with provider: {}...",
        "◆".cyan().bold(),
        detected_provider.yellow().bold()
    );

    // Initialize AI Agent
    let provider: Box<dyn nxc_ai::providers::AiProvider> = match detected_provider.as_str() {
        "gemini" => Box::new(nxc_ai::providers::GeminiProvider::new(api_key, model)),
        "openai" => Box::new(nxc_ai::providers::OpenAiProvider::new(api_key, model)),
        "anthropic" => Box::new(nxc_ai::providers::AnthropicProvider::new(api_key, model)),
        "ollama" => Box::new(nxc_ai::providers::OllamaProvider::new(api_key, model)),
        _ => anyhow::bail!("Provider {} is not yet fully implemented", detected_provider),
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
