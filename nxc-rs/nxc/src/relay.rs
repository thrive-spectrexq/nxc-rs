//! # NTLM Relay Listener
//!
//! Listens for incoming NTLM authentications and relays them to a target.

use anyhow::Result;
use tokio::net::TcpListener;
use tracing::{debug, info};

#[allow(dead_code)]
pub struct RelayServer {
    pub bind_addr: String,
}

#[allow(dead_code)]
impl RelayServer {
    pub fn new(bind_addr: &str) -> Self {
        Self {
            bind_addr: bind_addr.to_string(),
        }
    }

    pub async fn start(&self) -> Result<()> {
        info!(
            "Relay: Starting NTLM Relay listener on {}...",
            self.bind_addr
        );
        let listener = TcpListener::bind(&self.bind_addr).await?;

        loop {
            let (socket, addr) = listener.accept().await?;
            debug!("Relay: Accepted connection from {}", addr);
            // Handle HTTP/SMB relay logic
            tokio::spawn(async move {
                let _ = socket;
            });
        }
    }
}
