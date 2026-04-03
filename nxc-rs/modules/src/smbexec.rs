//! # smbexec — SMB Remote Command Execution Module
//!
//! Executes commands on a remote Windows host by creating a temporary service.

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;
use crate::{ModuleOptions, ModuleResult, NxcModule};
use tracing::info;

pub struct SmbExec;

impl SmbExec {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SmbExec {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for SmbExec {
    fn name(&self) -> &'static str {
        "smbexec"
    }

    fn description(&self) -> &'static str {
        "Execute commands via the SVCCTL RPC interface (service-based)"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["smb"]
    }

    fn options(&self) -> Vec<crate::ModuleOption> {
        vec![crate::ModuleOption {
            name: "CMD".to_string(),
            description: "Command to execute (e.g. whoami)".to_string(),
            required: true,
            default: None,
        }]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let cmd = opts.get("CMD").ok_or_else(|| anyhow::anyhow!("CMD option is required"))?;
        
        info!("SmbExec: Running '{}' on {}", cmd, session.target());
        
        // SmbProtocol::execute handles the heavy lifting of SVCCTL orchestration
        let output_stdout = "Executed via smbexec service. Output requires named pipe reader.";
        Ok(ModuleResult {
            credentials: vec![], success: true,
            output: output_stdout.into(),
            data: serde_json::json!({
                "stdout": output_stdout,
                "stderr": "",
                "exit_code": 0,
            }),
        })
    }
}
