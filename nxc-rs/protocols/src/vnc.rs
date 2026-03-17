//! # VNC Protocol Handler
//!
//! VNC protocol implementation focusing on port 5900 connections,
//! RFB protocol probing, and security type enumeration.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

pub struct VncSession {
    pub target: String,
    pub port: u16,
    pub rfb_version: String,
    pub security_types: Vec<u8>,
    pub no_auth_supported: bool,
    pub admin: bool,
}

impl NxcSession for VncSession {
    fn protocol(&self) -> &'static str {
        "vnc"
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn is_admin(&self) -> bool {
        self.admin
    }
}

pub struct VncProtocol {
    pub timeout: Duration,
}

impl VncProtocol {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(10),
        }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl Default for VncProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcProtocol for VncProtocol {
    fn name(&self) -> &'static str {
        "vnc"
    }

    fn default_port(&self) -> u16 {
        5900
    }

    fn supports_exec(&self) -> bool {
        true // Exec via VNC mouse/keyboard macros
    }

    fn supported_modules(&self) -> &[&str] {
        &["screenshot"]
    }

    async fn connect(&self, target: &str, port: u16) -> Result<Box<dyn NxcSession>> {
        let addr = format!("{}:{}", target, port);
        debug!("VNC: Connecting to {}", addr);

        let timeout_fut = tokio::time::timeout(self.timeout, TcpStream::connect(&addr));
        let mut stream = match timeout_fut.await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(anyhow!("Connection refused or unreachable: {}", e)),
            Err(_) => return Err(anyhow!("Connection timeout to {}", addr)),
        };

        // Probe RFB (Remote Frame Buffer)
        // Read the server banner (e.g., "RFB 003.003\n")
        let mut banner = vec![0; 12];
        let read_fut = tokio::time::timeout(self.timeout, stream.read_exact(&mut banner));
        if let Err(e) = read_fut.await {
            return Err(anyhow!("Failed to read VNC RFB banner: {}", e));
        }

        if !banner.starts_with(b"RFB") {
            return Err(anyhow!("Invalid VNC RFB banner received."));
        }

        let rfb_version = String::from_utf8_lossy(&banner).trim().to_string();

        // Return the banner back to the server to acknowledge
        let _ = stream.write_all(&banner).await;

        let mut security_types = Vec::new();
        let mut no_auth_supported = false;

        // VNC 3.7 and 3.8 return a count followed by security types
        let mut nbytes = vec![0; 1];
        if let Ok(Ok(_)) = tokio::time::timeout(self.timeout, stream.read_exact(&mut nbytes)).await
        {
            let n = nbytes[0];
            if n > 0 {
                let mut types = vec![0; n as usize];
                if let Ok(Ok(_)) =
                    tokio::time::timeout(self.timeout, stream.read_exact(&mut types)).await
                {
                    security_types = types.clone();
                    if types.contains(&1) {
                        // 1 = None (No Auth)
                        no_auth_supported = true;
                    }
                }
            }
        }

        info!(
            "VNC: Connected to {} (Version: {}, SecTypes: {:?}, NoAuth: {})",
            addr, rfb_version, security_types, no_auth_supported
        );

        Ok(Box::new(VncSession {
            target: target.to_string(),
            port,
            rfb_version,
            security_types,
            no_auth_supported,
            admin: false,
        }))
    }

    async fn authenticate(
        &self,
        session: &mut dyn NxcSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        let username = creds.username.clone();

        let vnc_sess = unsafe { &*(session as *const dyn NxcSession as *const VncSession) };
        let addr = format!("{}:{}", vnc_sess.target, vnc_sess.port);

        debug!(
            "VNC: Authenticating {}@{} (No Auth Supported: {})",
            username, addr, vnc_sess.no_auth_supported
        );

        Ok(AuthResult::failure(
            "VNC explicit VNCAuth/DES logic pending implementation",
            None,
        ))
    }

    async fn execute(&self, _session: &dyn NxcSession, _cmd: &str) -> Result<CommandOutput> {
        Err(anyhow!(
            "VNC explicit command execution requires macro injection (not yet ported)."
        ))
    }
}
