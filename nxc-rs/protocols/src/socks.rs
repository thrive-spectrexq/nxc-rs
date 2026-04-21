//! # SOCKS Proxy Support
//!
//! Implementation of SOCKS5 proxying for protocol connections.
//! Supports anonymous and username/password authentication.

use anyhow::Result;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;

/// Parsed SOCKS5 proxy URL with optional credentials.
#[derive(Debug, Clone)]
pub struct SocksUrl {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl SocksUrl {
    /// Parse a SOCKS5 URL in the format:
    ///   `socks5://host:port`
    ///   `socks5://user:pass@host:port`
    ///   `host:port` (plain format)
    pub fn parse(url: &str) -> Result<Self> {
        let stripped =
            url.strip_prefix("socks5://").or_else(|| url.strip_prefix("socks5h://")).unwrap_or(url);

        // Check if there are credentials (user:pass@host:port)
        if let Some(at_pos) = stripped.rfind('@') {
            let cred_part = &stripped[..at_pos];
            let addr_part = &stripped[at_pos + 1..];

            let (username, password) = if let Some(colon_pos) = cred_part.find(':') {
                (cred_part[..colon_pos].to_string(), cred_part[colon_pos + 1..].to_string())
            } else {
                (cred_part.to_string(), String::new())
            };

            let (host, port) = Self::parse_host_port(addr_part)?;
            Ok(SocksUrl { host, port, username: Some(username), password: Some(password) })
        } else {
            let (host, port) = Self::parse_host_port(stripped)?;
            Ok(SocksUrl { host, port, username: None, password: None })
        }
    }

    fn parse_host_port(addr: &str) -> Result<(String, u16)> {
        if let Some(colon_pos) = addr.rfind(':') {
            let host = addr[..colon_pos].to_string();
            let port: u16 =
                addr[colon_pos + 1..].parse().map_err(|e| anyhow::anyhow!("Invalid port: {e}"))?;
            Ok((host, port))
        } else {
            Ok((addr.to_string(), 1080)) // Default SOCKS5 port
        }
    }

    /// Returns true if this URL has authentication credentials.
    pub fn has_auth(&self) -> bool {
        self.username.is_some()
    }

    /// Returns the socket address string for connection.
    pub fn addr_string(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

pub struct SocksProxy;

impl SocksProxy {
    /// Connect to a target through a SOCKS5 proxy (auto-detect auth from URL).
    pub async fn connect_url(proxy_url: &str, target_addr: &str) -> Result<TcpStream> {
        let parsed = SocksUrl::parse(proxy_url)?;

        if parsed.has_auth() {
            Self::connect_with_auth(
                &parsed.addr_string(),
                target_addr,
                parsed.username.as_deref().unwrap_or(""),
                parsed.password.as_deref().unwrap_or(""),
            )
            .await
        } else {
            Self::connect(&parsed.addr_string(), target_addr).await
        }
    }

    /// Connect to a target through a SOCKS5 proxy (anonymous).
    pub async fn connect(proxy_url: &str, target_addr: &str) -> Result<TcpStream> {
        let proxy_addr: SocketAddr =
            proxy_url.parse().map_err(|e| anyhow::anyhow!("Invalid proxy address: {e}"))?;

        let target_addr: SocketAddr =
            target_addr.parse().map_err(|e| anyhow::anyhow!("Invalid target address: {e}"))?;

        let stream = Socks5Stream::connect(proxy_addr, target_addr).await?;
        Ok(stream.into_inner())
    }

    /// Connect to a target through a SOCKS5 proxy with username/password authentication.
    pub async fn connect_with_auth(
        proxy_addr: &str,
        target_addr: &str,
        username: &str,
        password: &str,
    ) -> Result<TcpStream> {
        let proxy: SocketAddr =
            proxy_addr.parse().map_err(|e| anyhow::anyhow!("Invalid proxy address: {e}"))?;

        let target: SocketAddr =
            target_addr.parse().map_err(|e| anyhow::anyhow!("Invalid target address: {e}"))?;

        let stream = Socks5Stream::connect_with_password(proxy, target, username, password).await?;
        Ok(stream.into_inner())
    }

    /// Connect to a target through a SOCKS5 proxy (blocking).
    pub fn connect_blocking(proxy_url: &str, target_addr: &str) -> Result<std::net::TcpStream> {
        use socks::Socks5Stream;
        let stream = Socks5Stream::connect(proxy_url, target_addr)?;
        Ok(stream.into_inner())
    }

    /// Connect to a target through a SOCKS5 proxy with auth (blocking).
    pub fn connect_blocking_with_auth(
        proxy_url: &str,
        target_addr: &str,
        username: &str,
        password: &str,
    ) -> Result<std::net::TcpStream> {
        use socks::Socks5Stream;
        let stream =
            Socks5Stream::connect_with_password(proxy_url, target_addr, username, password)?;
        Ok(stream.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socks_url_parse_simple() {
        let url = SocksUrl::parse("127.0.0.1:1080").unwrap();
        assert_eq!(url.host, "127.0.0.1");
        assert_eq!(url.port, 1080);
        assert!(!url.has_auth());
    }

    #[test]
    fn test_socks_url_parse_with_scheme() {
        let url = SocksUrl::parse("socks5://10.0.0.1:9050").unwrap();
        assert_eq!(url.host, "10.0.0.1");
        assert_eq!(url.port, 9050);
        assert!(!url.has_auth());
    }

    #[test]
    fn test_socks_url_parse_with_auth() {
        let url = SocksUrl::parse("socks5://admin:secret@proxy.corp.local:1080").unwrap();
        assert_eq!(url.host, "proxy.corp.local");
        assert_eq!(url.port, 1080);
        assert!(url.has_auth());
        assert_eq!(url.username.as_deref(), Some("admin"));
        assert_eq!(url.password.as_deref(), Some("secret"));
    }

    #[test]
    fn test_socks_url_parse_auth_no_scheme() {
        let url = SocksUrl::parse("user:pass@localhost:8080").unwrap();
        assert_eq!(url.host, "localhost");
        assert_eq!(url.port, 8080);
        assert_eq!(url.username.as_deref(), Some("user"));
        assert_eq!(url.password.as_deref(), Some("pass"));
    }

    #[test]
    fn test_socks_url_default_port() {
        let url = SocksUrl::parse("socks5://myproxy").unwrap();
        assert_eq!(url.host, "myproxy");
        assert_eq!(url.port, 1080);
    }

    #[test]
    fn test_socks_url_socks5h_scheme() {
        let url = SocksUrl::parse("socks5h://10.0.0.1:9050").unwrap();
        assert_eq!(url.host, "10.0.0.1");
        assert_eq!(url.port, 9050);
    }

    #[test]
    fn test_socks_url_password_with_special_chars() {
        let url = SocksUrl::parse("socks5://user:p@ss:w0rd@host:1080").unwrap();
        assert_eq!(url.host, "host");
        assert_eq!(url.port, 1080);
        assert_eq!(url.username.as_deref(), Some("user"));
        // rfind('@') grabs the last @, so cred_part = "user:p@ss:w0rd"
        // first ':' splits username="user", password="p@ss:w0rd"
        assert_eq!(url.password.as_deref(), Some("p@ss:w0rd"));
    }
}
