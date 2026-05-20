//! # Telnet Protocol Handler
//!
//! Telnet protocol implementation for NetExec-RS.
//! Supports basic banner grabbing and authentication over raw TCP.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use std::time::Duration;
use tracing::{debug, info};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

// ─── Telnet Session ───────────────────────────────────────────────

pub struct TelnetSession {
    pub target: String,
    pub port: u16,
    pub authenticated: bool,
    pub credentials: Option<Credentials>,
}

impl NxcSession for TelnetSession {
    fn protocol(&self) -> &'static str {
        "telnet"
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn is_admin(&self) -> bool {
        self.authenticated
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

// ─── Telnet Protocol Handler ──────────────────────────────────────

pub struct TelnetProtocol {
    pub timeout: Duration,
}

impl TelnetProtocol {
    pub fn new() -> Self {
        Self { timeout: Duration::from_secs(5) }
    }
}

impl Default for TelnetProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcProtocol for TelnetProtocol {
    fn name(&self) -> &'static str {
        "telnet"
    }

    fn default_port(&self) -> u16 {
        23
    }

    fn supports_exec(&self) -> bool {
        true 
    }

    fn supported_modules(&self) -> &[&str] {
        &["telnet_enum"]
    }

    async fn connect(
        &self,
        target: &str,
        port: u16,
        _proxy: Option<&str>,
    ) -> Result<Box<dyn NxcSession>> {
        debug!("Telnet: Connecting to {}:{}", target, port);

        match timeout(self.timeout, TcpStream::connect((target, port))).await {
            Ok(Ok(_conn)) => {
                info!("Telnet: Connected to {}:{}", target, port);
                Ok(Box::new(TelnetSession {
                    target: target.to_string(),
                    port,
                    authenticated: false, 
                    credentials: None,
                }))
            }
            Ok(Err(e)) => Err(anyhow!("Connection failed: {e}")),
            Err(_) => Err(anyhow!("Connection timeout to {target}:{port}")),
        }
    }

    async fn authenticate(
        &self,
        session: &mut dyn NxcSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        let telnet_sess = match session.protocol() {
            "telnet" => session
                .as_any_mut()
                .downcast_mut::<TelnetSession>()
                .ok_or_else(|| anyhow!("Invalid session type"))?,
            _ => return Err(anyhow!("Invalid session type")),
        };

        if creds.username.is_empty() && creds.password.is_none() {
            return Ok(AuthResult::failure("Anonymous access not supported", None));
        }

        debug!("Telnet: Attempting auth for user: {}", creds.username);
        
        let mut conn = TcpStream::connect((telnet_sess.target.as_str(), telnet_sess.port)).await?;
        
        // Very basic mock Telnet auth sequence
        let mut buf = [0u8; 1024];
        let _ = timeout(self.timeout, conn.read(&mut buf)).await;
        
        let login_str = format!("{}\r\n", creds.username);
        conn.write_all(login_str.as_bytes()).await?;
        let _ = timeout(self.timeout, conn.read(&mut buf)).await;
        
        let pwd_str = format!("{}\r\n", creds.password.as_deref().unwrap_or_default());
        conn.write_all(pwd_str.as_bytes()).await?;
        let _ = timeout(self.timeout, conn.read(&mut buf)).await;

        let response = String::from_utf8_lossy(&buf);
        if response.to_lowercase().contains("login incorrect") || response.to_lowercase().contains("invalid") {
            Ok(AuthResult::failure("Login incorrect", None))
        } else {
            telnet_sess.credentials = Some(creds.clone());
            telnet_sess.authenticated = true; 
            Ok(AuthResult::success(true))
        }
    }

    async fn execute(&self, session: &dyn NxcSession, cmd: &str) -> Result<CommandOutput> {
        let telnet_sess = match session.protocol() {
            "telnet" => session
                .as_any()
                .downcast_ref::<TelnetSession>()
                .ok_or_else(|| anyhow!("Invalid session type"))?,
            _ => return Err(anyhow!("Invalid session type")),
        };

        if !telnet_sess.authenticated {
            return Err(anyhow!("Not authenticated"));
        }

        let mut conn = TcpStream::connect((telnet_sess.target.as_str(), telnet_sess.port)).await?;
        
        // Send command and read output
        let cmd_str = format!("{}\r\n", cmd);
        conn.write_all(cmd_str.as_bytes()).await?;
        
        let mut buf = [0u8; 4096];
        let n = match timeout(self.timeout, conn.read(&mut buf)).await {
            Ok(Ok(n)) => n,
            _ => 0,
        };

        Ok(CommandOutput {
            stdout: String::from_utf8_lossy(&buf[..n]).to_string(),
            stderr: String::new(),
            exit_code: Some(0),
        })
    }
}
