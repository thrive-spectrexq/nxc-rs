use anyhow::{Result, Context};
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;
use url::Url;

/// Establishes a TCP connection, routing through a SOCKS5 proxy if provided.
pub async fn connect(target: &str, port: u16, proxy: Option<&str>) -> Result<TcpStream> {
    if let Some(proxy_url) = proxy {
        // Parse the proxy string (expected format: socks5://ip:port)
        let parsed_url = Url::parse(proxy_url).context("Failed to parse proxy URL")?;
        
        if parsed_url.scheme() != "socks5" {
            anyhow::bail!("Only socks5:// proxy scheme is supported");
        }
        
        let proxy_host = parsed_url.host_str().ok_or_else(|| anyhow::anyhow!("Proxy URL missing host"))?;
        let proxy_port = parsed_url.port().unwrap_or(1080);
        let proxy_addr = format!("{}:{}", proxy_host, proxy_port);

        // Resolve the target hostname to an IP address locally for the initial implementation,
        // though true SOCKS5 can resolve remotely. (For nxc-rs, Target parsing usually already resolves IP).
        let target_addr = format!("{}:{}", target, port);

        // Connect via SOCKS5 wrapper
        let proxy_stream = tokio::net::TcpStream::connect(&proxy_addr)
            .await
            .with_context(|| format!("Failed to connect to proxy at {}", proxy_addr))?;

        // Upgrade the raw TCP stream to a SOCKS5 stream
        let socks_stream = Socks5Stream::connect_with_socket(proxy_stream, target_addr.as_str())
            .await
            .with_context(|| format!("Failed to negotiate SOCKS5 connection to target {}", target_addr))?;

        // In tokio-socks 0.5, into_inner() extracts the underlying TcpStream.
        // It's still a standard TcpStream but traffic passing over it is transparently 
        // sent to the remote destination via the proxy's negotiation.
        Ok(socks_stream.into_inner())
    } else {
        // Direct connection
        let target_addr = format!("{}:{}", target, port);
        TcpStream::connect(target_addr)
            .await
            .with_context(|| format!("Failed to connect directly to {}:{}", target, port))
    }
}
