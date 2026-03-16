use anyhow::Result;
use clap::Parser;
use netsage_agent::Agent;
use netsage_capture::CaptureEngine;
use netsage_common::AppEvent;
use netsage_session::SessionManager;
use netsage_tui::run_tui;
use tokio::sync::{broadcast, mpsc};
use tracing::info;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    interface: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let _ = dotenvy::dotenv();
    tracing_subscriber::fmt::init();

    info!("Launching NetSage v1.0.0...");

    let config_path = std::path::Path::new("config.toml");
    let config = if config_path.exists() {
        netsage_config::load_config(config_path)?
    } else {
        anyhow::bail!("Config file not found at config.toml. Please create it.");
    };

    // Initialize broadcast bus
    let (event_tx, _) = broadcast::channel::<AppEvent>(1024);

    // Initialize Session Manager
    let db_path = std::path::Path::new("session.db");
    let session_manager = SessionManager::new(db_path)?;
    let session_id = uuid::Uuid::new_v4();

    // Initialize Capture Engine
    let capture_engine = CaptureEngine::new(event_tx.clone(), args.interface.as_deref())?;
    let topology = capture_engine.get_topology();
    capture_engine.start();

    // Background Logging Task
    let mut log_rx = event_tx.subscribe();
    let logger_sm = session_manager.clone();
    tokio::spawn(async move {
        while let Ok(event) = log_rx.recv().await {
            if let AppEvent::PacketCaptured(pkt) = event {
                let _ = logger_sm.log_packet(session_id, &pkt).await;
            }
        }
    });

    // Initialize Agent
    let (user_tx, user_rx) = mpsc::channel::<String>(100);
    let agent = Agent::new(
        config.clone(),
        session_manager.clone(),
        session_id,
        event_tx.clone(),
        user_rx,
    );

    let agent_handle = tokio::spawn(async move {
        if let Err(e) = agent.run(Vec::new()).await {
            tracing::error!("Agent error: {}", e);
        }
    });

    // Run TUI
    run_tui(event_tx.clone(), user_tx, topology).await?;

    // Cleanup
    let _ = event_tx.send(AppEvent::Quit);
    let _ = agent_handle.await;

    Ok(())
}
