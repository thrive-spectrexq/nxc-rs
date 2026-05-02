//! # OPC-UA Protocol Handler
//!
//! OPC-UA (Industrial Control Systems) protocol implementation for NetExec-RS.
//! Leverages the `async-opcua` crate for native async communication.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use opcua::client::prelude::*;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info};

// ─── OPC-UA Session ───────────────────────────────────────────────

pub struct OpcUaSession {
    pub target: String,
    pub port: u16,
    pub admin: bool,
    pub client: Arc<Mutex<Client>>,
    pub session: Option<Arc<opcua::sync::RwLock<Session>>>,
}

impl NxcSession for OpcUaSession {
    fn protocol(&self) -> &'static str {
        "opcua"
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn is_admin(&self) -> bool {
        self.admin
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

// ─── OPC-UA Protocol Handler ──────────────────────────────────────

pub struct OpcUaProtocol;

impl OpcUaProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for OpcUaProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcProtocol for OpcUaProtocol {
    fn name(&self) -> &'static str {
        "opcua"
    }

    fn default_port(&self) -> u16 {
        4840
    }

    async fn connect(
        &self,
        target: &str,
        port: u16,
        _proxy: Option<&str>,
    ) -> Result<Box<dyn NxcSession>> {
        let url = format!("opc.tcp://{}:{}/", target, port);
        debug!("OPC-UA: Connecting to {}", url);

        // Configure OPC-UA Client
        let mut config = ClientConfig::new("NetExec-RS", "nxc-rs");
        config.session_retry_limit = 1;

        let client = Client::new(config);

        // In OPC-UA, connecting usually involves identifying endpoints first
        // For reconnaissance, we attempt to connect and establish a session later
        Ok(Box::new(OpcUaSession {
            target: target.to_string(),
            port,
            admin: false,
            client: Arc::new(Mutex::new(client)),
            session: None,
        }))
    }

    async fn authenticate(
        &self,
        session: &mut dyn NxcSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        let opcua_sess = session
            .as_any_mut()
            .downcast_mut::<OpcUaSession>()
            .ok_or_else(|| anyhow!("Invalid session type"))?;

        let url = format!("opc.tcp://{}:{}/", opcua_sess.target, opcua_sess.port);
        let mut client = opcua_sess.client.lock().await;

        // Identity Token setup
        let identity_token = if let Some(ref pass) = creds.password {
            IdentityToken::UserName(creds.username.clone(), pass.clone())
        } else if !creds.username.is_empty() {
            IdentityToken::UserName(creds.username.clone(), String::new())
        } else {
            IdentityToken::Anonymous
        };

        // Attempt to connect and create session
        // Note: Option 1 (Auto-select highest security) is implicitly handled by async-opcua
        // if we provide the right policy, but for now we go with None (No Security) for initial probe.
        match client.connect_to_endpoint(url.as_str(), identity_token) {
            Ok(session) => {
                info!("OPC-UA: Session established on {}:{}", opcua_sess.target, opcua_sess.port);
                opcua_sess.session = Some(session);
                opcua_sess.admin = true; // In simple auth, we have session access
                Ok(AuthResult::success(true))
            }
            Err(e) => {
                debug!("OPC-UA: Connection failed for {}: {}", url, e);
                Ok(AuthResult::failure(&e.to_string(), None))
            }
        }
    }

    async fn execute(&self, session: &dyn NxcSession, _cmd: &str) -> Result<CommandOutput> {
        let opcua_sess = session
            .as_any()
            .downcast_ref::<OpcUaSession>()
            .ok_or_else(|| anyhow!("Invalid session type"))?;

        if let Some(ref session_arc) = opcua_sess.session {
            let session = session_arc.read();

            // For OPC-UA, "execute" is mapped to reading server metadata
            let node_id = NodeId::new(0, 2256);
            let result = session.read(
                &[opcua::client::prelude::ReadValueId {
                    node_id,
                    attribute_id: AttributeId::Value as u32,
                    index_range: opcua::types::UAString::null(),
                    data_encoding: opcua::types::QualifiedName::null(),
                }],
                opcua::types::TimestampsToReturn::Both,
                0.0,
            );

            match result {
                Ok(data_value) => {
                    let output = format!("Server Status: {:?}", data_value);
                    Ok(CommandOutput { stdout: output, stderr: String::new(), exit_code: Some(0) })
                }
                Err(e) => Err(anyhow!("Failed to read server status: {}", e)),
            }
        } else {
            Err(anyhow!("No active OPC-UA session"))
        }
    }
}
