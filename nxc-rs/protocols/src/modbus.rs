//! # Modbus Protocol Handler
//!
//! Modbus TCP protocol implementation for NetExec-RS.
//! Supports unauthenticated connection and PLC discovery.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use std::time::Duration;
use tracing::{debug, info};
use tokio::net::TcpStream;
use tokio::time::timeout;

// ─── Modbus Session ───────────────────────────────────────────────

pub struct ModbusSession {
    pub target: String,
    pub port: u16,
}

impl NxcSession for ModbusSession {
    fn protocol(&self) -> &'static str {
        "modbus"
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn is_admin(&self) -> bool {
        true // Modbus typically has no authentication, granting full control
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

// ─── Modbus Protocol Handler ──────────────────────────────────────

pub struct ModbusProtocol {
    pub timeout: Duration,
}

impl ModbusProtocol {
    pub fn new() -> Self {
        Self { timeout: Duration::from_secs(5) }
    }
}

impl Default for ModbusProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcProtocol for ModbusProtocol {
    fn name(&self) -> &'static str {
        "modbus"
    }

    fn default_port(&self) -> u16 {
        502
    }

    fn supports_exec(&self) -> bool {
        false 
    }

    fn supported_modules(&self) -> &[&str] {
        &["modbus_enum"]
    }

    async fn connect(
        &self,
        target: &str,
        port: u16,
        _proxy: Option<&str>,
    ) -> Result<Box<dyn NxcSession>> {
        debug!("Modbus: Connecting to {}:{}", target, port);

        match timeout(self.timeout, TcpStream::connect((target, port))).await {
            Ok(Ok(_conn)) => {
                info!("Modbus: Connected to {}:{}", target, port);
                Ok(Box::new(ModbusSession {
                    target: target.to_string(),
                    port,
                }))
            }
            Ok(Err(e)) => Err(anyhow!("Connection failed: {e}")),
            Err(_) => Err(anyhow!("Connection timeout to {target}:{port}")),
        }
    }

    async fn authenticate(
        &self,
        session: &mut dyn NxcSession,
        _creds: &Credentials,
    ) -> Result<AuthResult> {
        let _modbus_sess = match session.protocol() {
            "modbus" => session
                .as_any_mut()
                .downcast_mut::<ModbusSession>()
                .ok_or_else(|| anyhow!("Invalid session type"))?,
            _ => return Err(anyhow!("Invalid session type")),
        };

        // Modbus TCP does not have built-in authentication
        debug!("Modbus: Protocol lacks authentication; treating as success");
        Ok(AuthResult::success(true))
    }

    async fn execute(&self, _session: &dyn NxcSession, _cmd: &str) -> Result<CommandOutput> {
        Err(anyhow!("Modbus protocol does not support direct command execution"))
    }
}
