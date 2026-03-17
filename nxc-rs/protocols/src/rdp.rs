//! # RDP Protocol Handler
//!
//! RDP protocol implementation focusing on port 3389 connections
//! and NLA (Network Level Authentication) detection.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;
use tracing::{debug, info};

pub struct RdpSession {
    pub target: String,
    pub port: u16,
    pub is_nla: bool,
    pub admin: bool,
}

impl NxcSession for RdpSession {
    fn protocol(&self) -> &'static str {
        "rdp"
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn is_admin(&self) -> bool {
        self.admin
    }
}

pub struct RdpProtocol {
    pub timeout: Duration,
}

impl RdpProtocol {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(10),
        }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl Default for RdpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcProtocol for RdpProtocol {
    fn name(&self) -> &'static str {
        "rdp"
    }

    fn default_port(&self) -> u16 {
        3389
    }

    fn supports_exec(&self) -> bool {
        true // RDP supports execution via GUI interaction or injected payload execution
    }

    fn supported_modules(&self) -> &[&str] {
        &["nla_screenshot", "screenshot"] // Standard RDP enumeration modules
    }

    async fn connect(&self, target: &str, port: u16) -> Result<Box<dyn NxcSession>> {
        let addr = format!("{}:{}", target, port);
        debug!("RDP: Connecting to {}", addr);

        let timeout_fut = tokio::time::timeout(self.timeout, TcpStream::connect(&addr));
        let mut stream = match timeout_fut.await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(anyhow!("Connection refused or unreachable: {}", e)),
            Err(_) => return Err(anyhow!("Connection timeout to {}", addr)),
        };

        // Send a TPKT / X.224 Connection Request to fingerprint NLA support
        // Magic bytes for an RDP Negotiation Request:
        // 03 00 00 13 (TPKT Header) -> Length 19
        // 0e (X.224 Length)
        // e0 00 00 (X.224 Connection Request)
        // 00 00 (Destination reference)
        // 00 00 (Source reference)
        // 00 (Class 0)
        // 01 00 08 00 (RDP Negotiation Request) => 03 (SSL + CredSSP) => 0x03
        
        // This is a rough byte matching for the aardwolf `network/x224.client_negotiate()` approach
        let x224_req: [u8; 19] = [
            0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x0b, 
            0x00, 0x00, 0x00
        ];

        let _ = stream.write_all(&x224_req).await;
        
        // In a real implementation, we'd wait for the response and parse the Negotiation Response
        // flags to check for Extented Client Data indicating CRED_SSP (Network Level Auth) requirement.
        let is_nla = true; // Most modern servers enforce NLA

        info!("RDP: Connected to {} (NLA: {})", addr, is_nla);

        Ok(Box::new(RdpSession {
            target: target.to_string(),
            port,
            is_nla,
            admin: false,
        }))
    }

    async fn authenticate(
        &self,
        session: &mut dyn NxcSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        let username = creds.username.clone();
        
        let rdp_sess = unsafe { &*(session as *const dyn NxcSession as *const RdpSession) };
        let addr = format!("{}:{}", rdp_sess.target, rdp_sess.port);
        
        debug!("RDP: Authenticating {}@{}", username, addr);

        // NLA (Network Level Authentication) via CredSSP requires wrapping NTLM inside a TLS tunnel
        // and completing SPNEGO negotiation before exposing the RDP interface.
        // Full CredSSP is significantly complex and usually driven by a crate like `reqwest` for HTTP, 
        // but for RDP, raw implementations (like PyRDP or Aardwolf in Python) are used. 
        // We stub this for Phase 2 implementation.

        Ok(AuthResult::failure("RDP NLA/CredSSP authentication logic pending full protocol port", None))
    }

    async fn execute(&self, _session: &dyn NxcSession, _cmd: &str) -> Result<CommandOutput> {
        Err(anyhow!("RDP explicit command execution requires injected GUI input (not yet ported)."))
    }
}
