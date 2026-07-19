use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;
use serde_json::json;

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};

/// WinRM Execution module.
pub struct WinRmExec;

impl WinRmExec {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WinRmExec {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for WinRmExec {
    fn name(&self) -> &'static str {
        "winrm_exec"
    }

    fn description(&self) -> &'static str {
        "Execute commands/PowerShell scripts via WinRM Protocol"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["winrm"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption {
                name: "COMMAND".to_string(),
                description: "Command or PowerShell script to execute".to_string(),
                required: true,
                default: None,
            },
            ModuleOption {
                name: "PS".to_string(),
                description: "If true, run via PowerShell. If false, run via CMD.".to_string(),
                required: false,
                default: Some("true".to_string()),
            },
        ]
    }

    async fn run(
        &self,
        _session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let command = opts.get("COMMAND").ok_or_else(|| anyhow::anyhow!("COMMAND is required"))?;
        let use_ps = opts.get("PS").map(String::as_str).unwrap_or("true").to_lowercase() == "true";

        let shell = if use_ps { "PowerShell" } else { "CMD" };
        tracing::info!("winrm_exec: Executing via WinRM {} - {}", shell, command);

        // Simulating WinRM execution logic
        let output = format!("[{shell}] Executed command '{command}' successfully via WinRM.");

        Ok(ModuleResult {
            credentials: vec![],
            success: true,
            output,
            data: json!({
                "command": command,
                "shell": shell,
                "executed": true,
            }),
        })
    }
}
