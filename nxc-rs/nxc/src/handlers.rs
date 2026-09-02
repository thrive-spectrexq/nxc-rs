use anyhow::{Context, Result};
use colored::Colorize;
use nxc_ai::{
    agent::CliFeedback, AiAgent, ProtocolTool, QueryDbTool, ScanTool, SearchModulesTool,
    ToolRegistry, UtilityTool,
};
use nxc_db::NxcDb;
use nxc_modules::ModuleRegistry;
use std::io::Write;
use std::sync::Arc;

pub async fn handle_ai_mode(
    initial_prompt: Option<String>,
    provider_name: Option<String>,
    model: Option<String>,
    confirm_exec: bool,
    dry_run: bool,
    log_prompts: bool,
) -> Result<()> {
    dotenvy::dotenv().ok();

    let (detected_provider, api_key) = match provider_name.as_deref() {
        Some("gemini") => (
            "gemini".to_string(),
            std::env::var("GEMINI_API_KEY").context("GEMINI_API_KEY not found in .env")?,
        ),
        Some("openai") => (
            "openai".to_string(),
            std::env::var("OPENAI_API_KEY").context("OPENAI_API_KEY not found in .env")?,
        ),
        Some("anthropic") => (
            "anthropic".to_string(),
            std::env::var("ANTHROPIC_API_KEY").context("ANTHROPIC_API_KEY not found in .env")?,
        ),
        Some("ollama") => (
            "ollama".to_string(),
            std::env::var("OLLAMA_API_BASE")
                .unwrap_or_else(|_| "http://localhost:11434".to_string()),
        ),
        Some(p) => anyhow::bail!("Unsupported AI provider: {p}"),
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
        _ => anyhow::bail!("Provider {detected_provider} is not yet fully implemented"),
    };

    // Initialize shared resources for AI tools
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

    let db_path = dot_nxc.join("nxc.db");
    let db = Arc::new(NxcDb::new(&db_path, "default")?);
    let registry_mod = Arc::new(ModuleRegistry::new());

    let mut registry = ToolRegistry::new();
    registry.register(Box::new(ScanTool));
    registry.register(Box::new(ProtocolTool));
    registry.register(Box::new(QueryDbTool::new(db)));
    registry.register(Box::new(SearchModulesTool::new(registry_mod)));
    registry.register(Box::new(UtilityTool));

    let mut agent = AiAgent::new(provider, registry, Box::new(CliFeedback))
        .with_confirm_exec(confirm_exec)
        .with_dry_run(dry_run)
        .with_prompt_logging(log_prompts);

    // If an initial prompt was provided on CLI, run it first
    if let Some(prompt) = initial_prompt {
        let sanitized_prompt = sanitize_ai_prompt(&prompt);
        println!("{} Goal: {}", "🛰️".green().bold(), sanitized_prompt.green().bold());
        if let Err(e) = agent.run(&sanitized_prompt).await {
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
                let sanitized_input = sanitize_ai_prompt(input);
                if let Err(e) = agent.run(&sanitized_input).await {
                    eprintln!("{} AI Error: {}", "ERROR".red().bold(), e);
                }
            }
        }
    }

    Ok(())
}

/// Scrub sensitive credential patterns (NTLM hashes, private key headers) from AI prompts
/// before sending outbound requests to LLM providers.
pub fn sanitize_ai_prompt(prompt: &str) -> String {
    let mut sanitized = prompt.to_string();

    // Mask standard 32-character hex hashes (e.g. NTLM hashes)
    let hashes_to_redact: Vec<String> = sanitized
        .split_whitespace()
        .map(|word| word.trim_matches(|c: char| !c.is_ascii_alphanumeric()).to_string())
        .filter(|clean| clean.len() == 32 && clean.chars().all(|c| c.is_ascii_hexdigit()))
        .collect();

    for hash in hashes_to_redact {
        sanitized = sanitized.replace(&hash, "[REDACTED_NTLM_HASH]");
    }

    // Mask private key headers
    if sanitized.contains("BEGIN RSA PRIVATE KEY")
        || sanitized.contains("BEGIN OPENSSH PRIVATE KEY")
    {
        sanitized = "[REDACTED_PRIVATE_KEY]".to_string();
    }

    sanitized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_ai_prompt_ntlm() {
        let prompt =
            "Check if user admin with hash 8846f7eaee8fb117ad06bdd830b7586c has admin access";
        let sanitized = sanitize_ai_prompt(prompt);
        assert!(!sanitized.contains("8846f7eaee8fb117ad06bdd830b7586c"));
        assert!(sanitized.contains("[REDACTED_NTLM_HASH]"));
    }

    #[test]
    fn test_sanitize_ai_prompt_private_key() {
        let prompt =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
        let sanitized = sanitize_ai_prompt(prompt);
        assert_eq!(sanitized, "[REDACTED_PRIVATE_KEY]");
    }
}
