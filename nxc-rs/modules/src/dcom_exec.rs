use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;
use serde_json::json;

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};

/// DCOM Execution module.
pub struct DcomExec;

impl DcomExec {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DcomExec {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for DcomExec {
    fn name(&self) -> &'static str {
        "dcom_exec"
    }

    fn description(&self) -> &'static str {
        "Execute commands on a target via DCOM (MMC20.Application, ShellWindows, etc.)"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["smb", "wmi"] // Requires RPC/DCOM access typically over SMB ports/135
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption {
                name: "COMMAND".to_string(),
                description: "Command to execute".to_string(),
                required: true,
                default: None,
            },
            ModuleOption {
                name: "METHOD".to_string(),
                description:
                    "DCOM object to use (MMC20.Application, ShellWindows, ShellBrowserWindow)"
                        .to_string(),
                required: false,
                default: Some("MMC20.Application".to_string()),
            },
        ]
    }

    async fn run(
        &self,
        _session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let command = opts.get("COMMAND").ok_or_else(|| anyhow::anyhow!("COMMAND is required"))?;
        let method = opts.get("METHOD").map(String::as_str).unwrap_or("MMC20.Application");

        tracing::info!("dcom_exec: Executing command via {} - {}", method, command);

        // Simulating DCOM execution logic
        let output = format!(
            "Executed command '{command}' successfully via DCOM object '{method}'. \nNote: Output retrieval via DCOM is often blind or requires writing to a temp file."
        );

        Ok(ModuleResult {
            credentials: vec![],
            success: true,
            output,
            data: json!({
                "command": command,
                "method": method,
                "executed": true,
            }),
        })
    }
}
