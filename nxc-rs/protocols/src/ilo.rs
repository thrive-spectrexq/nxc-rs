//! # iLO Protocol Handler
//!
//! HP iLO / Dell iDRAC / Supermicro IPMI management interface reconnaissance.
//! HTTPS-based management interface fingerprinting and credential testing.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use tracing::info;

// ─── iLO Session ────────────────────────────────────────────────

pub struct IloSession {
    pub target: String,
    pub port: u16,
    pub admin: bool,
    pub product: Option<String>,
    pub version: Option<String>,
}

impl NxcSession for IloSession {
    fn protocol(&self) -> &'static str { "ilo" }
    fn target(&self) -> &str { &self.target }
    fn is_admin(&self) -> bool { self.admin }
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }
}

// ─── iLO Protocol ───────────────────────────────────────────────

pub struct IloProtocol;

impl IloProtocol {
    pub fn new() -> Self { Self }
}

impl Default for IloProtocol {
    fn default() -> Self { Self::new() }
}

#[async_trait]
impl NxcProtocol for IloProtocol {
    fn name(&self) -> &'static str { "ilo" }
    fn default_port(&self) -> u16 { 443 }
    fn supports_exec(&self) -> bool { false }

    async fn connect(&self, target: &str, port: u16, _proxy: Option<&str>) -> Result<Box<dyn NxcSession>> {
        info!("iLO: Probing management interface at {}:{}", target, port);

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        let url = format!("https://{}:{}/", target, port);
        let mut product = None;
        let mut version = None;

        // Try to fingerprint the management interface
        match client.get(&url).send().await {
            Ok(resp) => {
                let body = resp.text().await.unwrap_or_default();
                if body.contains("iLO") || body.contains("Integrated Lights-Out") {
                    product = Some("HP iLO".to_string());
                    // Try to extract version
                    if body.contains("iLO 5") { version = Some("5".to_string()); }
                    else if body.contains("iLO 4") { version = Some("4".to_string()); }
                } else if body.contains("iDRAC") {
                    product = Some("Dell iDRAC".to_string());
                } else if body.contains("Supermicro") || body.contains("IPMI") {
                    product = Some("Supermicro IPMI".to_string());
                }
            }
            Err(_) => {
                // Try common iLO REST API endpoint
                let rest_url = format!("https://{}:{}/redfish/v1/", target, port);
                if let Ok(resp) = client.get(&rest_url).send().await {
                    let body = resp.text().await.unwrap_or_default();
                    if body.contains("RedfishVersion") {
                        product = Some("Redfish BMC".to_string());
                    }
                }
            }
        }

        Ok(Box::new(IloSession {
            target: target.to_string(),
            port,
            admin: false,
            product,
            version,
        }))
    }

    async fn authenticate(&self, session: &mut dyn NxcSession, creds: &Credentials) -> Result<AuthResult> {
        let ilo_sess = session.as_any_mut().downcast_mut::<IloSession>()
            .ok_or_else(|| anyhow!("Invalid session type"))?;

        let username = &creds.username;
        let password = creds.password.as_deref().unwrap_or("");

        info!("iLO: Authenticating as '{}' on {}", username, ilo_sess.target);

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        // Try Redfish API authentication
        let auth_url = format!("https://{}:{}/redfish/v1/SessionService/Sessions", ilo_sess.target, ilo_sess.port);
        let auth_body = serde_json::json!({
            "UserName": username,
            "Password": password
        });

        match client.post(&auth_url).json(&auth_body).send().await {
            Ok(resp) => {
                if resp.status().is_success() || resp.status().as_u16() == 201 {
                    ilo_sess.admin = true;
                    Ok(AuthResult::success(true))
                } else {
                    Ok(AuthResult::failure("iLO authentication failed", Some(&resp.status().to_string())))
                }
            }
            Err(e) => Ok(AuthResult::failure(&format!("Connection error: {}", e), None)),
        }
    }

    async fn execute(&self, _session: &dyn NxcSession, _cmd: &str) -> Result<CommandOutput> {
        Err(anyhow!("iLO: Direct command execution not supported — use IPMI commands via BMC"))
    }
}
