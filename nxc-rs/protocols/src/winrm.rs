//! # WinRM Protocol Handler
//!
//! WinRM protocol implementation using HTTP/HTTPS connections (`reqwest`).
//! This is a stub for the massive WS-Man/SOAP implementation, establishing
//! the connection logic and preparing for execution commands.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use reqwest::Client;
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

        // NTLM Type 1 Message (Negotiate)
        // Format: NTLMSSP\0 + MessageType(1) + Flags + Domain(optional) + Workstation(optional)
        // Simple Type 1 message (Negotiate NTLM, Negotiate Unicode, Negotiate OEM, etc.)
        let ntlm_type1 = "TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==";

        let request = client
            .post(&url)
            .header("Content-Length", "0")
            .header("Content-Type", "application/soap+xml;charset=UTF-8")
            .header("User-Agent", "Microsoft WinRM Client")
            .header("Authorization", format!("Negotiate {}", ntlm_type1))
            .body("");

        let response = match request.send().await {
            Ok(resp) => resp,
            Err(e) => return Err(anyhow!("Connection failed to WinRM service: {}", e)),
        };

        debug!("WinRM: Received response code: {}", response.status());

        // Check for WWW-Authenticate header with NTLM challenge (Type 2)
        let headers = response.headers();
        let www_auth = headers.get_all("WWW-Authenticate");

        let mut ntlm_challenge = None;
        for auth in www_auth {
            let auth_str = auth.to_str().unwrap_or("");
            if let Some(challenge) = auth_str.strip_prefix("Negotiate ") {
                ntlm_challenge = Some(challenge.to_string());
                break;
            } else if let Some(challenge) = auth_str.strip_prefix("NTLM ") {
                ntlm_challenge = Some(challenge.to_string());
                break;
            }
        }

        if let Some(_challenge) = ntlm_challenge {
            info!("WinRM: Connected to {} (NTLM Challenge received)", url);
            // In a full implementation, we would decode BASE64 _challenge here
            // and extract Target Name (Domain/Computer), OS Version, etc.

            Ok(Box::new(WinrmSession {
                target: target.to_string(),
                port,
                admin: false,
                is_ssl: port == 5986,
                endpoint: url,
            }))
        } else if response.status() == 200 {
            info!(
                "WinRM: Connected to {} (Unauthenticated access or pre-auth)",
                url
            );
            Ok(Box::new(WinrmSession {
                target: target.to_string(),
                port,
                admin: false,
                is_ssl: port == 5986,
                endpoint: url,
            }))
        } else {
            Err(anyhow!(
                "Failed to get NTLM challenge from target. Status: {}",
                response.status()
            ))
        }
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
            Ok(AuthResult::failure(
                "WinRM explicit NTLM logic pending implementation (reqwest-ntlm missing)",
                None,
            ))
        }
    }

    async fn execute(&self, _session: &dyn NxcSession, _cmd: &str) -> Result<CommandOutput> {
        // PowerShell / cmd execution via SOAP
        Err(anyhow!(
            "Full WS-Man execution engine not yet ported. WinRM execute pending implementation."
        ))
    }
}
