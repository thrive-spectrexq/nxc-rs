use anyhow::Result;
use chrono::Utc;
use netsage_tui::{run_tui, TuiEvent};
use netsage_agent::{Agent, AgentEvent, Message, Provider, ApprovalMode, Persona};
use netsage_pybridge::PythonBridge;
use tracing::info;
use netsage_capture::PacketEngine;
use netsage_capture::topology::{SharedTopology, TopologyGraph};
use netsage_mcp::McpServer;
use tokio::sync::mpsc;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::Mutex as TokioMutex;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    mcp: bool,

    #[arg(short, long)]
    interface: Option<String>,

    #[arg(short, long)]
    server: bool,

    #[arg(short, long)]
    node: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    // Load .env file
    let _ = dotenvy::dotenv();
    
    if args.mcp {
        // Run in MCP mode - no TUI
        let python_path = "python";
        let script_path = "python/netsage_tools/server.py";
        let bridge = Arc::new(TokioMutex::new(PythonBridge::spawn(python_path, script_path).await?));
        let server = McpServer::new(bridge);
        server.run().await?;
        return Ok(());
    }

    if let Some(server_addr) = args.node {
        // Run in Node mode - streaming to central server
        tracing_subscriber::fmt::init();
        info!("Launching NetSage in NODE mode...");
        
        let engine = if let Ok(engine) = PacketEngine::new(args.interface.as_deref()) {
            engine
        } else {
            anyhow::bail!("Failed to initialize packet engine for node.");
        };

        engine.spawn_remote_loop(server_addr);
        
        // Keep alive
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        }
    }

    tracing_subscriber::fmt::init();

    let config_path = std::path::Path::new("config.toml");
    let config = if config_path.exists() {
        netsage_config::load_config(config_path)?
    } else {
        anyhow::bail!("Config file not found at config.toml");
    };

    // Initialize Session Store
    let session_path = std::path::Path::new("session.db");
    let session_store = netsage_session::SessionStore::open(session_path)?;

    // Initialize Channels
    let (tui_tx, mut agent_rx) = mpsc::channel::<TuiEvent>(100);
    let (ui_tx, ui_rx) = mpsc::channel::<TuiEvent>(100);

    // Initialize Packet Engine
    let ui_tx_pcap = ui_tx.clone();
    let (pcap_tx, mut pcap_rx) = mpsc::channel::<String>(100);
    
    let shared_topology = if let Ok(engine) = PacketEngine::new(args.interface.as_deref()) {
        let topo = engine.get_topology();
        engine.spawn_loop(pcap_tx);
        tokio::spawn(async move {
            let mut byte_count = 0;
            let mut timer = tokio::time::interval(std::time::Duration::from_secs(1));
            while let Some(packet_desc) = pcap_rx.recv().await {
                let _ = ui_tx_pcap.send(TuiEvent::PacketUpdate(packet_desc.clone())).await;
                byte_count += 500; 
                
                tokio::select! {
                    _ = timer.tick() => {
                        let throughput_mbps = (byte_count as f64 * 8.0) / 1_000_000.0;
                        let _ = ui_tx_pcap.send(TuiEvent::ThroughputUpdate(throughput_mbps)).await;
                        byte_count = 0;
                    }
                    else => {}
                }
            }
        });
        Some(topo)
    } else {
        // Fallback to mock
        let ui_tx_clone = ui_tx.clone();
        let topo: SharedTopology = Arc::new(StdMutex::new(TopologyGraph::new()));
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(500));
            loop {
                interval.tick().await;
                let pkt = "[MOCK] TCP 192.168.1.1:443 -> 192.168.1.52:54212 [ACK]".to_string();
                let _ = ui_tx_clone.send(TuiEvent::PacketUpdate(pkt)).await;
                let _ = ui_tx_clone.send(TuiEvent::ThroughputUpdate(45.0 + (rand::random::<f64>() * 10.0))).await;
            }
        });
        Some(topo)
    };

    // If in Server mode, spawn ingestion listener
    if args.server {
        if let Some(topo) = shared_topology.clone() {
            let ui_tx_srv = ui_tx.clone();
            tokio::spawn(async move {
                let listener = tokio::net::TcpListener::bind("0.0.0.0:9090").await.unwrap();
                info!("NetSage Ingestion Server listening on 0.0.0.0:9090");
                loop {
                    if let Ok((socket, addr)) = listener.accept().await {
                        let topo_inner = topo.clone();
                        let ui_tx_inner = ui_tx_srv.clone();
                        info!("New capture node connected: {}", addr);
                        tokio::spawn(async move {
                            use tokio::io::AsyncBufReadExt;
                            let reader = tokio::io::BufReader::new(socket);
                            let mut lines = reader.lines();
                            while let Ok(Some(line)) = lines.next_line().await {
                                // Basic parsing of "src -> dst"
                                if line.contains(" -> ") {
                                    let parts: Vec<&str> = line.split(" -> ").collect();
                                    if parts.len() >= 2 {
                                        let src = parts[0].trim().to_string();
                                        let dst_full = parts[1].trim();
                                        let dst = dst_full.split(' ').next().unwrap_or(dst_full).to_string();
                                        
                                        if let Ok(graph) = topo_inner.lock() {
                                            let mut graph: std::sync::MutexGuard<'_, TopologyGraph> = graph;
                                            graph.add_node(src.clone(), src.clone(), "remote_host".to_string());
                                            graph.add_node(dst.clone(), dst.clone(), "remote_host".to_string());
                                            graph.add_edge(src, dst);
                                        }
                                    }
                                }
                                let _ = ui_tx_inner.send(TuiEvent::PacketUpdate(format!("[REMOTE] {}", line))).await;
                            }
                            info!("Capture node disconnected: {}", addr);
                        });
                    }
                }
            });
        }
    }

    // Initialize Agent
    let provider = match config.core.provider.as_str() {
        "openai" => Provider::OpenAI,
        "gemini" => Provider::Gemini,
        _ => Provider::Anthropic,
    };

    let api_key_env = match provider {
        Provider::OpenAI => "OPENAI_API_KEY",
        Provider::Gemini => "GEMINI_API_KEY",
        Provider::Anthropic => "ANTHROPIC_API_KEY",
    };

    let api_key = std::env::var(api_key_env).unwrap_or_default();
    let model = config.core.model.clone();
    let mode = match config.core.approval_mode.as_str() {
        "read-only" => ApprovalMode::ReadOnly,
        "autonomous" => ApprovalMode::Autonomous,
        _ => ApprovalMode::Supervised,
    };

    let agent = Arc::new(Agent::new(
        api_key,
        model,
        provider,
        mode,
        Persona::General,
        session_store.clone(),
    ));

    // Spawn Python Bridge
    let python_path = "python";
    let script_path = "python/netsage_tools/server.py";
    let bridge = Arc::new(TokioMutex::new(PythonBridge::spawn(python_path, script_path).await?));

    let ui_tx_agent = ui_tx.clone();
    let agent_clone = agent.clone();
    let bridge_clone = bridge.clone();

    let session_store_for_agent = session_store.clone();
    let shared_topology_for_events = shared_topology.clone();

    let _agent_task = tokio::spawn(async move {
        let mut messages: Vec<Message> = Vec::new();

        let network_md = std::path::Path::new("NETWORK.md");
        if network_md.exists() {
            if let Ok(context) = netsage_config::load_network_context(network_md) {
                messages.push(Message {
                    role: "user".to_string(),
                    content: format!("NETWORK CONTEXT:\n\n{}", context),
                });
            }
        }

        while let Some(event) = agent_rx.recv().await {
            match event {
                TuiEvent::Input(cmd) => {
                    messages.push(Message {
                        role: "user".to_string(),
                        content: cmd,
                    });

                    let (agent_event_tx, mut agent_event_rx) = mpsc::channel::<AgentEvent>(100);
                    
                    let agent_run = agent_clone.clone();
                    let bridge_run = bridge_clone.clone();
                    let mut messages_run = messages.clone();
                    let ui_tx_inner = ui_tx_agent.clone();

                    tokio::spawn(async move {
                        let mut bridge_lock = bridge_run.lock().await;
                        if let Err(e) = agent_run.run_loop(&mut messages_run, &mut *bridge_lock, agent_event_tx).await {
                            let _ = ui_tx_inner.send(TuiEvent::AgentResponse(format!("Error: {}", e))).await;
                        }
                    });

                    while let Some(agent_event) = agent_event_rx.recv().await {
                        match agent_event {
                            AgentEvent::TextDelta(delta) => {
                                let _ = ui_tx_agent.send(TuiEvent::TextDelta(delta)).await;
                            }
                            AgentEvent::ToolCall { name, .. } => {
                                let _ = ui_tx_agent.send(TuiEvent::AgentResponse(format!("[Executing Tool: {}]", name))).await;
                            }
                            AgentEvent::Thinking(val) => {
                                let _ = ui_tx_agent.send(TuiEvent::AgentThinking(val)).await;
                            }
                            AgentEvent::Error(err) => {
                                let _ = ui_tx_agent.send(TuiEvent::AgentResponse(format!("Error: {}", err))).await;
                            }
                            AgentEvent::Finished => {}
                            _ => {}
                        }
                    }
                }
                TuiEvent::PersonaUpdate(persona) => {
                    let agent_run = agent_clone.clone();
                    tokio::spawn(async move {
                        agent_run.set_persona(persona).await;
                    });
                }
                TuiEvent::ExportRequested => {
                    let session_store_clone = session_store_for_agent.clone();
                    let ui_tx_inner = ui_tx_agent.clone();
                    tokio::spawn(async move {
                        match session_store_clone.export_as_markdown() {
                            Ok(md) => {
                                let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();
                                let filename = format!("reports/session_{}.md", timestamp);
                                let _ = std::fs::create_dir_all("reports");
                                if let Err(e) = std::fs::write(&filename, md) {
                                    let _ = ui_tx_inner.send(TuiEvent::AgentResponse(format!("Export failed: {}", e))).await;
                                } else {
                                    let _ = ui_tx_inner.send(TuiEvent::AgentResponse(format!("Session exported to {}", filename))).await;
                                }
                            }
                            Err(e) => {
                                let _ = ui_tx_inner.send(TuiEvent::AgentResponse(format!("Export failed: {}", e))).await;
                            }
                        }
                    });
                }
                TuiEvent::MermaidRequested => {
                    if let Some(topo) = shared_topology_for_events.clone() {
                        let ui_tx_inner = ui_tx_agent.clone();
                        tokio::spawn(async move {
                            let (mermaid, filename) = {
                                if let Ok(graph) = topo.lock() {
                                    let graph: std::sync::MutexGuard<'_, TopologyGraph> = graph;
                                    let mermaid = graph.to_mermaid();
                                    let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();
                                    let filename = format!("reports/topology_{}.mmd", timestamp);
                                    (Some(mermaid), Some(filename))
                                } else {
                                    (None, None)
                                }
                            };

                            if let (Some(mermaid), Some(filename)) = (mermaid, filename) {
                                let _ = std::fs::create_dir_all("reports");
                                if let Err(e) = std::fs::write(&filename, mermaid) {
                                    let _ = ui_tx_inner.send(TuiEvent::AgentResponse(format!("Mermaid export failed: {}", e))).await;
                                } else {
                                    let _ = ui_tx_inner.send(TuiEvent::AgentResponse(format!("Topology exported to {}", filename))).await;
                                }
                            }
                        });
                    }
                }
                _ => {}
            }
        }
    });

    // Periodic Topology Snapshots
    if let Some(topo) = shared_topology.clone() {
        let session_store_topo = session_store.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let topo_json = {
                    if let Ok(graph) = topo.lock() {
                        let graph: std::sync::MutexGuard<'_, TopologyGraph> = graph;
                        // Convert nodes/edges to a JSON value for storage
                        let nodes: Vec<_> = graph.nodes.values().cloned().collect();
                        let edges: Vec<_> = graph.edges.clone();
                        Some(serde_json::json!({
                            "nodes": serde_json::to_value(nodes).unwrap_or_default(),
                            "edges": serde_json::to_value(edges).unwrap_or_default(),
                        }))
                    } else {
                        None
                    }
                };

                if let Some(json) = topo_json {
                    let _ = session_store_topo.log_snapshot(&json);
                }
            }
        });
    }

    println!("Starting NetSage Core (Phase 5) TUI...");
    run_tui(ui_rx, tui_tx, shared_topology).await?;

    Ok(())
}
