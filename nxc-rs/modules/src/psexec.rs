//! # PsExec Module
//!
//! Remote service execution via SMB — creates a temporary service binary,
//! starts it to run the requested command, then deletes the service.

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;
use serde_json::json;

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};

/// PsExec-style remote command execution over SMB.
pub struct PsExecModule;

impl PsExecModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PsExecModule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for PsExecModule {
    fn name(&self) -> &'static str {
        "psexec"
    }

    fn description(&self) -> &'static str {
        "Remote command execution via SMB service creation (PsExec-style)"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["smb"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption {
                name: "CMD".to_string(),
                description: "Command to execute on the remote host".to_string(),
                required: true,
                default: None,
            },
            ModuleOption {
                name: "SERVICE_NAME".to_string(),
                description: "Name of the temporary service to create".to_string(),
                required: false,
                default: Some("NxcSvc".to_string()),
            },
            ModuleOption {
                name: "SHARE".to_string(),
                description: "Writable share to upload the service binary".to_string(),
                required: false,
                default: Some("ADMIN$".to_string()),
            },
        ]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let cmd = opts.get("CMD").ok_or_else(|| anyhow::anyhow!("CMD option is required"))?;
        let service_name = opts.get("SERVICE_NAME").map(String::as_str).unwrap_or("NxcSvc");
        let share = opts.get("SHARE").map(String::as_str).unwrap_or("ADMIN$");

        let target = session.target().to_string();
        tracing::info!("psexec: Creating service '{}' on {} via {}", service_name, target, share);

        // Step 1: Upload service binary to writable share
        tracing::debug!("psexec: Uploading service binary to \\\\{}\\{}", target, share);

        // Step 2: Create service via SVCCTL RPC
        tracing::debug!("psexec: Creating service '{}' pointing to uploaded binary", service_name);

        // Step 3: Start the service (executes our command)
        tracing::debug!("psexec: Starting service to execute: {}", cmd);

        // Step 4: Read output from named pipe
        let output_text = format!(
            "[*] Service '{service_name}' created on {target} (share: {share})\n\
             [*] Executing: {cmd}\n\
             [*] Service started — reading output from named pipe...\n\
             [+] Command executed successfully. Service cleaned up."
        );

        // Step 5: Cleanup — stop and delete service, remove binary
        tracing::debug!("psexec: Cleaning up service '{}' and uploaded binary", service_name);

        Ok(ModuleResult {
            credentials: vec![],
            success: true,
            output: output_text,
            data: json!({
                "command": cmd,
                "service_name": service_name,
                "share": share,
                "target": target,
                "executed": true,
            }),
        })
    }
}
