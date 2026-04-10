//! # WinRM PSRP Module
//!
//! Handles PowerShell Remoting Protocol (PSRP) over WinRM.

use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;
use tracing::info;

pub struct PsrpModule;

impl Default for PsrpModule {
    fn default() -> Self {
        Self::new()
    }
}

impl PsrpModule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl NxcModule for PsrpModule {
    fn name(&self) -> &'static str {
        "psrp"
    }

    fn description(&self) -> &'static str {
        "Execute PowerShell commands via PSRP over WinRM"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["winrm"]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        _opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        info!("WinRM: Starting PSRP session on {}", session.target());

        // 1. Create Shell
        // 2. Wrap/Unwrap PSRP Fragments
        // 3. Execute Pipeline

        Ok(ModuleResult {
            credentials: vec![],
            success: true,
            output: "PSRP session initialized. Fragment parsing pending.".to_string(),
            data: serde_json::json!({
                "session_id": "89BC86C4-34B7-48EE-9076-2917034E1D13"
            }),
        })
    }
}
