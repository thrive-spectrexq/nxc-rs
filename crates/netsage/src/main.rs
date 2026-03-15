use anyhow::Result;
use netsage_tui::run_tui;

fn main() -> Result<()> {
    // Load .env file
    let _ = dotenvy::dotenv();
    
    tracing_subscriber::fmt::init();

    let config_path = std::path::Path::new("config.toml");
    let config = if config_path.exists() {
        netsage_config::load_config(config_path)?
    } else {
        anyhow::bail!("Config file not found at config.toml");
    };

    // Phase 2: Initialize Session Store
    let session_path = std::path::Path::new("session.db");
    let session_store = netsage_session::SessionStore::open(session_path)?;

    // Phase 2: Initialize Packet Engine
    // Note: This might fail if not running with enough privileges
    let _packet_engine = netsage_capture::PacketEngine::new(None);

    // Phase 5: Initialize Agent with Provider and correct API Key
    let provider = match config.core.provider.as_str() {
        "openai" => netsage_agent::Provider::OpenAI,
        "gemini" => netsage_agent::Provider::Gemini,
        _ => netsage_agent::Provider::Anthropic,
    };

    let api_key_env = match provider {
        netsage_agent::Provider::OpenAI => "OPENAI_API_KEY",
        netsage_agent::Provider::Gemini => "GEMINI_API_KEY",
        netsage_agent::Provider::Anthropic => "ANTHROPIC_API_KEY",
    };

    let api_key = std::env::var(api_key_env).unwrap_or_default();

    let mode = match config.core.approval_mode.as_str() {
        "read-only" => netsage_agent::ApprovalMode::ReadOnly,
        "autonomous" => netsage_agent::ApprovalMode::Autonomous,
        _ => netsage_agent::ApprovalMode::Supervised,
    };

    let _agent = netsage_agent::Agent::new(
        api_key,
        config.core.model.clone(),
        provider,
        mode,
        session_store,
    );

    let context_path = std::path::Path::new("NETWORK.md");
    let _context = if context_path.exists() {
        Some(netsage_config::load_network_context(context_path)?)
    } else {
        None
    };

    println!("Starting NetSage Phase 2...");
    run_tui()?;

    Ok(())
}
