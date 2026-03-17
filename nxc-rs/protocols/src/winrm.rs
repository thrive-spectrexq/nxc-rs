//! # WinRM Protocol Handler
//!
//! WinRM protocol implementation using HTTP/HTTPS connections (`reqwest`).
//! This is a stub for the massive WS-Man/SOAP implementation, establishing
//! the connection logic and preparing for execution commands.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use reqwest::{Client, IntoUrl};
use std::time::Duration;
use tracing::{debug, info};

// ─── WinRM Session ────────────────────────────────────────────────

pub struct WinrmSession {
    pub target: String,
    pub port: u16,
    pub admin: bool,
    pub is_ssl: bool,
    pub endpoint: String,
}

impl NxcSession for WinrmSession {
    fn protocol(&self) -> &'static str {
        "winrm"
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn is_admin(&self) -> bool {
        self.admin
    }
}

// ─── WinRM Protocol Handler ───────────────────────────────────────

pub struct WinrmProtocol {
    pub timeout: Duration,
}

impl WinrmProtocol {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(10),
        }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }

    fn build_url(&self, target: &str, port: u16) -> String {
        let scheme = if port == 5986 { "https" } else { "http" };
        format!("{}://{}:{}/wsman", scheme, target, port)
    }

    /// Build a reqwest client configured for WinRM communication (ignoring rigorous cert checks for now, similar to NXC)
    fn build_client(&self) -> Result<Client> {
        Client::builder()
            .timeout(self.timeout)
            .danger_accept_invalid_certs(true) // Required for internal network targets with self-signed certs
            .build()
            .map_err(|e| anyhow!("Failed to build HTTP client: {}", e))
    }
}

impl Default for WinrmProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcProtocol for WinrmProtocol {
    fn name(&self) -> &'static str {
        "winrm"
    }

    fn default_port(&self) -> u16 {
        5985 // Default HTTP, 5986 for HTTPS
    }

    fn supports_exec(&self) -> bool {
        true // WinRM fully supports execution
    }

    fn supported_modules(&self) -> &[&str] {
        &["sam", "lsa"] // Stub modules matching the reference
    }

    async fn connect(&self, target: &str, port: u16) -> Result<Box<dyn NxcSession>> {
        let url = self.build_url(target, port);
        debug!("WinRM: Connecting to {}", url);

        let client = self.build_client()?;

        // Send a baseline POST request with 0 Content-Length to trigger the 401 Challenge
        // WinRM/WS-Man technically responds to this to advertise Negotiate/NTLM.
        let body = "";
        let request = client
            .post(&url)
            .header("Content-Length", "0")
            .header("Content-Type", "application/soap+xml;charset=UTF-8")
            .header("User-Agent", "Microsoft WinRM Client")
            // Send a dummy authorization header to aggressively provoke the WWW-Authenticate response
            .header("Authorization", "Negotiate TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==")
            .body(body);

        let response = match request.send().await {
            Ok(resp) => resp,
            Err(e) => return Err(anyhow!("Connection failed to WinRM service: {}", e)),
        };

        debug!("WinRM: Received response code: {}", response.status());

        // Check if we got a WWW-Authenticate header indicating NTLM/Negotiate support
        let headers = response.headers();
        let www_auth = headers.get("WWW-Authenticate");

        if let Some(auth_header) = www_auth {
            if auth_header.to_str().unwrap_or("").contains("Negotiate") {
                info!("WinRM: Connected to {} (NTLM supported)", url);
                
                return Ok(Box::new(WinrmSession {
                    target: target.to_string(),
                    port,
                    admin: false,
                    is_ssl: port == 5986,
                    endpoint: url,
                }));
            }
        }

        Err(anyhow!("Failed to get NTLM challenge from target '/wsman' endpoint. Service may not be WinRM."))
    }

    async fn authenticate(
        &self,
        session: &mut dyn NxcSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        let username = creds.username.clone();
        let target = session.target().to_string();
        
        let winrm_sess = unsafe { &*(session as *const dyn NxcSession as *const WinrmSession) };
        let url = self.build_url(&target, winrm_sess.port);

        debug!("WinRM: Authenticating {}@{}", username, url);

        // WinRM authentication via Rust `reqwest` requires a specialized NTLM crate or WS-Man library 
        // to handle the 3-exchange NTLM handshake over HTTP. 
        // For the sake of this implementation plan expansion, we verify the structure works.
        // Full NTLM/WS-Man negotiation requires a crate like `winrm-rs` or custom NTLM middleware.

        // Placeholder for NTLM Handshake
        let ntlm_success = false; 
        
        if ntlm_success {
            // Check admin status by attempting a WSMan enumerate namespace query
            // similar to pypsrp's `enumerate("http://schemas.microsoft.com/wbem/wsman/1/windows/shell")`
            let is_admin = false; // Stub
            Ok(AuthResult::success(is_admin))
        } else {
            Ok(AuthResult::failure("WinRM explicit NTLM logic pending implementation (reqwest-ntlm missing)", None))
        }
    }

    async fn execute(&self, _session: &dyn NxcSession, _cmd: &str) -> Result<CommandOutput> {
        // PowerShell / cmd execution via SOAP
        Err(anyhow!("Full WS-Man execution engine not yet ported. WinRM execute pending implementation."))
    }
}
