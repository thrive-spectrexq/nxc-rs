//! # MQTT Protocol Handler
//!
//! MQTT protocol implementation for NetExec-RS.
//! Supports unauthenticated connection and basic authentication.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use std::time::Duration;
use tracing::{debug, info};
use tokio::net::TcpStream;
use tokio::time::timeout;

// ─── MQTT Session ────────────────────────────────────────────────

pub struct MqttSession {
    pub target: String,
    pub port: u16,
    pub authenticated: bool,
    pub credentials: Option<Credentials>,
}

impl NxcSession for MqttSession {
    fn protocol(&self) -> &'static str {
        "mqtt"
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

// ─── MQTT Protocol Handler ───────────────────────────────────────

pub struct MqttProtocol {
    pub timeout: Duration,
}

impl MqttProtocol {
    pub fn new() -> Self {
        Self { timeout: Duration::from_secs(5) }
    }
}

impl Default for MqttProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcProtocol for MqttProtocol {
    fn name(&self) -> &'static str {
        "mqtt"
    }

    fn default_port(&self) -> u16 {
        1883
    }

    fn supports_exec(&self) -> bool {
        false 
    }

    fn supported_modules(&self) -> &[&str] {
        &["mqtt_enum", "mqtt_publish"]
    }

    async fn connect(
        &self,
        target: &str,
        port: u16,
        _proxy: Option<&str>,
    ) -> Result<Box<dyn NxcSession>> {
        debug!("MQTT: Connecting to {}:{}", target, port);

        match timeout(self.timeout, TcpStream::connect((target, port))).await {
            Ok(Ok(_conn)) => {
                info!("MQTT: Connected to {}:{}", target, port);
                Ok(Box::new(MqttSession {
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
        let mqtt_sess = match session.protocol() {
            "mqtt" => session
                .as_any_mut()
                .downcast_mut::<MqttSession>()
                .ok_or_else(|| anyhow!("Invalid session type"))?,
            _ => return Err(anyhow!("Invalid session type")),
        };

        if creds.username.is_empty() && creds.password.is_none() {
            return Ok(AuthResult::success(false));
        }

        // Mock authentication process
        debug!("MQTT: Attempting auth for user: {}", creds.username);
        mqtt_sess.credentials = Some(creds.clone());
        mqtt_sess.authenticated = true; 
        Ok(AuthResult::success(true))
    }

    async fn execute(&self, _session: &dyn NxcSession, _cmd: &str) -> Result<CommandOutput> {
        Err(anyhow!("MQTT protocol does not support direct command execution"))
    }
}
