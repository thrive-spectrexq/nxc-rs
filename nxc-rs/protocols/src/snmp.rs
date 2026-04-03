//! # SNMP Protocol Handler
//!
//! SNMP protocol implementation for NetExec-RS.
//! Supports community string brute-forcing and system enumeration.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use snmp::SyncSession;
use std::time::Duration;
use tracing::{debug, info};

// ─── SNMP Session ───────────────────────────────────────────────

pub struct SnmpSession {
    pub target: String,
    pub port: u16,
    pub admin: bool,
    pub community: String,
}

impl NxcSession for SnmpSession {
    fn protocol(&self) -> &'static str {
        "snmp"
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

// ─── SNMP Protocol Handler ───────────────────────────────────────

pub struct SnmpProtocol {
    pub timeout: Duration,
}

impl SnmpProtocol {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(3),
        }
    }
}

impl Default for SnmpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcProtocol for SnmpProtocol {
    fn name(&self) -> &'static str {
        "snmp"
    }

    fn default_port(&self) -> u16 {
        161
    }

    fn supports_exec(&self) -> bool {
        false // SNMP doesn't natively support command execution easily
    }

    fn supported_modules(&self) -> &[&str] {
        &["snmp_enum", "snmp_brute"]
    }

    async fn connect(&self, target: &str, port: u16, _proxy: Option<&str>) -> Result<Box<dyn NxcSession>> {
        // SNMP is UDP, so "connect" just prepares the session metadata.
        // We'll use "public" as the default community string for the initial "connect".
        info!("SNMP: Initializing session for {}:{}", target, port);
        
        Ok(Box::new(SnmpSession {
            target: target.to_string(),
            port,
            admin: false,
            community: "public".to_string(),
        }))
    }

    async fn authenticate(
        &self,
        session: &mut dyn NxcSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        let snmp_sess = match session.protocol() {
            "snmp" => unsafe { &mut *(session as *mut dyn NxcSession as *mut SnmpSession) },
            _ => return Err(anyhow!("Invalid session type")),
        };

        // For SNMP, the "password" is typically the community string.
        let community = if let Some(ref pass) = creds.password {
            pass.clone()
        } else {
            "public".to_string()
        };

        debug!("SNMP: Testing community string '{}' on {}", community, snmp_sess.target);

        let addr = format!("{}:{}", snmp_sess.target, snmp_sess.port);
        let timeout = self.timeout;

        // Try to get sysDescr (OID .1.3.6.1.2.1.1.1.0)
        let sys_descr_oid = &[1, 3, 6, 1, 2, 1, 1, 1, 0];
        
        let community_clone = community.clone();
        let result: Result<bool, anyhow::Error> = tokio::task::spawn_blocking(move || {
            let mut sess = SyncSession::new(addr, community_clone.as_bytes(), Some(timeout), 0)
                .map_err(|e| anyhow!("SNMP Session Error: {}", e))?;
            let response = sess.get(sys_descr_oid).map_err(|e| anyhow!("SNMP Get Error: {:?}", e))?;
            Ok(response.varbinds.into_iter().next().is_some())
        }).await?;

        match result {
            Ok(success) => {
                if success {
                     debug!("SNMP: Auth successful for community '{}'", community);
                     snmp_sess.community = community;
                     Ok(AuthResult::success(true))
                } else {
                     Ok(AuthResult::failure("No varbinds in response", None))
                }
            }
            Err(e) => {
                debug!("SNMP: Auth failed for community '{}': {:?}", community, e);
                Ok(AuthResult::failure("SNMP Auth Failed", None))
            }
        }
    }

    async fn execute(&self, _session: &dyn NxcSession, _cmd: &str) -> Result<CommandOutput> {
         Err(anyhow!("SNMP protocol does not support command execution"))
    }
}

impl SnmpProtocol {
    /// Enumerate system information.
    pub async fn enumerate(&self, session: &SnmpSession) -> Result<String> {
        let addr = format!("{}:{}", session.target, session.port);
        let community = session.community.clone();
        let timeout = self.timeout;

        let oids = vec![
            (vec![1, 3, 6, 1, 2, 1, 1, 1, 0], "sysDescr"),
            (vec![1, 3, 6, 1, 2, 1, 1, 4, 0], "sysContact"),
            (vec![1, 3, 6, 1, 2, 1, 1, 5, 0], "sysName"),
            (vec![1, 3, 6, 1, 2, 1, 1, 6, 0], "sysLocation"),
        ];

        let community_clone = community.clone();
        let result: Result<String, anyhow::Error> = tokio::task::spawn_blocking(move || {
            let mut sess = SyncSession::new(addr, community_clone.as_bytes(), Some(timeout), 0)
                .map_err(|e| anyhow!("SNMP Session Error: {}", e))?;
            let mut report = String::new();
            for (oid, name) in oids {
                if let Ok(response) = sess.get(&oid) {
                    if let Some(varbind) = response.varbinds.into_iter().next() {
                        report.push_str(&format!("{}: {:?}\n", name, varbind.1));
                    }
                }
            }
            Ok(report)
        }).await?;

        result
    }
}

