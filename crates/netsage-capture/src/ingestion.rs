use tokio::net::TcpListener;
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{info, error, warn};
use crate::topology::SharedTopology;
use serde::{Deserialize, Serialize};
use netsage_auth::validate_token;
use tokio::sync::mpsc;

#[derive(Debug, Serialize, Deserialize)]
pub struct IngestionPacket {
    pub auth: String,
    pub payload: String,
}

pub struct IngestionServer {
    topology: SharedTopology,
    addr: String,
}

impl IngestionServer {
    pub fn new(topology: SharedTopology, addr: String) -> Self {
        Self { topology, addr }
    }

    pub async fn run(&self, packet_tx: mpsc::Sender<String>) -> anyhow::Result<()> {
        let listener = TcpListener::bind(&self.addr).await?;
        info!("Ingestion Server listening on {}", self.addr);

        loop {
            match listener.accept().await {
                Ok((socket, addr)) => {
                    info!("Incoming connection from capture node: {}", addr);
                    let topo = self.topology.clone();
                    let pkt_tx_inner = packet_tx.clone();
                    
                    tokio::spawn(async move {
                        let reader = BufReader::new(socket);
                        let mut lines = reader.lines();

                        while let Ok(Some(line)) = lines.next_line().await {
                            match serde_json::from_str::<IngestionPacket>(&line) {
                                Ok(pkt) => {
                                    if !validate_token(&pkt.auth) {
                                        warn!("Unauthorized packet dropped from {}", addr);
                                        continue;
                                    }

                                    let desc = pkt.payload;
                                    // Basic parsing of "src -> dst"
                                    if desc.contains(" -> ") {
                                        let parts: Vec<&str> = desc.split(" -> ").collect();
                                        if parts.len() >= 2 {
                                            let src = parts[0].trim().to_string();
                                            let dst_full = parts[1].trim();
                                            let dst = dst_full.split(' ').next().unwrap_or(dst_full).to_string();
                                            
                                            if let Ok(mut graph) = topo.lock() {
                                                graph.add_node(src.clone(), src.clone(), "remote_host".to_string());
                                                graph.add_node(dst.clone(), dst.clone(), "remote_host".to_string());
                                                graph.add_edge(src, dst);
                                            }
                                        }
                                    }
                                    let _ = pkt_tx_inner.send(format!("[REMOTE] {}", desc)).await;
                                }
                                Err(e) => {
                                    error!("Failed to parse ingestion packet from {}: {}", addr, e);
                                }
                            }
                        }
                        info!("Capture node disconnected: {}", addr);
                    });
                }
                Err(e) => error!("Server accept error: {}", e),
            }
        }
    }
}
