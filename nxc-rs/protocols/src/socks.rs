//! # SOCKS Proxy Support
//!
//! Implementation of SOCKS5 proxying for protocol connections.

use anyhow::Result;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;

pub struct SocksProxy;

impl SocksProxy {
    /// Connect to a target through a SOCKS5 proxy.
    pub async fn connect(proxy_url: &str, target_addr: &str) -> Result<TcpStream> {
        // Parse proxy URL (simple for now: host:port)
        let proxy_addr: SocketAddr = proxy_url
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid proxy address: {}", e))?;

        let target_addr: SocketAddr = target_addr
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid target address: {}", e))?;

        let stream = Socks5Stream::connect(proxy_addr, target_addr).await?;
        Ok(stream.into_inner())
    }

    /// Connect to a target through a SOCKS5 proxy (blocking).
    pub fn connect_blocking(proxy_url: &str, target_addr: &str) -> Result<std::net::TcpStream> {
        use socks::Socks5Stream;
        let stream = Socks5Stream::connect(proxy_url, target_addr)?;
        Ok(stream.into_inner())
    }
}
