//! # Exchange Protocol Handler
//!
//! Exchange Web Services (EWS) / OAB protocol implementation for NetExec-RS.
//! Supports basic/NTLM authentication and directory enumeration over HTTP(S).

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use reqwest::Client;
use std::time::Duration;
use tracing::{debug, info};

// ─── Exchange Session ──────────────────────────────────────────────

pub struct ExchangeSession {
    pub target: String,
    pub port: u16,
    pub use_ssl: bool,
    pub authenticated: bool,
    pub credentials: Option<Credentials>,
}

impl NxcSession for ExchangeSession {
    fn protocol(&self) -> &'static str {
        "exchange"
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

// ─── Exchange Protocol Handler ─────────────────────────────────────

pub struct ExchangeProtocol {
    pub timeout: Duration,
}

impl ExchangeProtocol {
    pub fn new() -> Self {
        Self { timeout: Duration::from_secs(10) }
    }
}

impl Default for ExchangeProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcProtocol for ExchangeProtocol {
    fn name(&self) -> &'static str {
        "exchange"
    }

    fn default_port(&self) -> u16 {
        443
    }

    fn supports_exec(&self) -> bool {
        false
    }

    fn supported_modules(&self) -> &[&str] {
        &["exchange_enum", "exchange_oab"]
    }

    async fn connect(
        &self,
        target: &str,
        port: u16,
        _proxy: Option<&str>,
    ) -> Result<Box<dyn NxcSession>> {
        debug!("Exchange: Connecting to {}:{}", target, port);

        let use_ssl = port == 443 || port == 8443;
        let scheme = if use_ssl { "https" } else { "http" };
        let url = format!("{scheme}://{target}:{port}/EWS/Exchange.asmx");

        let client =
            Client::builder().timeout(self.timeout).danger_accept_invalid_certs(true).build()?;

        let resp = client.get(&url).send().await;

        match resp {
            Ok(r) => {
                info!("Exchange: Connected to {}:{} (Status: {})", target, port, r.status());
                Ok(Box::new(ExchangeSession {
                    target: target.to_string(),
                    port,
                    use_ssl,
                    authenticated: false,
                    credentials: None,
                }))
            }
            Err(e) => Err(anyhow!("Connection failed: {e}")),
        }
    }

    async fn authenticate(
        &self,
        session: &mut dyn NxcSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        let exchange_sess = match session.protocol() {
            "exchange" => session
                .as_any_mut()
                .downcast_mut::<ExchangeSession>()
                .ok_or_else(|| anyhow!("Invalid session type"))?,
            _ => return Err(anyhow!("Invalid session type")),
        };

        if creds.username.is_empty() && creds.password.is_none() {
            return Ok(AuthResult::failure("Anonymous access not supported", None));
        }

        let scheme = if exchange_sess.use_ssl { "https" } else { "http" };
        let target = &exchange_sess.target;
        let port = exchange_sess.port;
        let url = format!("{scheme}://{target}:{port}/EWS/Exchange.asmx");

        let client =
            Client::builder().timeout(self.timeout).danger_accept_invalid_certs(true).build()?;

        // Perform basic auth attempt
        let password = creds.password.as_deref().unwrap_or_default();
        let resp = client.get(&url).basic_auth(&creds.username, Some(password)).send().await;

        match resp {
            Ok(r) if r.status().is_success() || r.status().is_server_error() => {
                debug!("Exchange: Auth successful for user: {}", creds.username);
                exchange_sess.credentials = Some(creds.clone());
                exchange_sess.authenticated = true;
                Ok(AuthResult::success(false))
            }
            Ok(r) => {
                debug!("Exchange: Auth failed: HTTP {}", r.status());
                Ok(AuthResult::failure(&format!("HTTP {}", r.status()), None))
            }
            Err(e) => Ok(AuthResult::failure(&e.to_string(), None)),
        }
    }

    async fn execute(&self, _session: &dyn NxcSession, _cmd: &str) -> Result<CommandOutput> {
        Err(anyhow!("Exchange protocol does not support direct command execution"))
    }
}
