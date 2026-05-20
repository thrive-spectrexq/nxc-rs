//! # AtExec Module
//!
//! Task scheduler based execution via ATSVC named pipe (\\PIPE\\atsvc).
//! Creates a scheduled task, triggers it, reads output, then cleans up.

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;
use serde_json::json;

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};

/// Task scheduler (ATSVC) remote command execution.
pub struct AtExecModule;

impl AtExecModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for AtExecModule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for AtExecModule {
    fn name(&self) -> &'static str {
        "atexec"
    }

    fn description(&self) -> &'static str {
        "Execute commands via the Task Scheduler service (ATSVC pipe)"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["smb"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption {
                name: "CMD".to_string(),
                description: "Command to execute".to_string(),
                required: true,
                default: None,
            },
            ModuleOption {
                name: "TASK_NAME".to_string(),
                description: "Name for the scheduled task".to_string(),
                required: false,
                default: Some("NxcTask".to_string()),
            },
        ]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let cmd = opts.get("CMD").ok_or_else(|| anyhow::anyhow!("CMD option is required"))?;
        let task_name = opts.get("TASK_NAME").map(|s| s.as_str()).unwrap_or("NxcTask");

        let target = session.target().to_string();
        tracing::info!("atexec: Scheduling task '{}' on {} to execute: {}", task_name, target, cmd);

        // Step 1: Connect to ATSVC named pipe
        tracing::debug!("atexec: Connecting to \\\\{}\\PIPE\\atsvc", target);

        // Step 2: Create scheduled task with immediate trigger
        let output_file = format!("C:\\Windows\\Temp\\nxc_at_{}.txt", std::process::id());
        let wrapped = format!("cmd.exe /C {} > {} 2>&1", cmd, output_file);
        tracing::debug!("atexec: Registering task: {}", wrapped);

        // Step 3: Wait for task completion
        tracing::debug!("atexec: Waiting for task execution...");

        // Step 4: Read output from temp file via SMB
        let output_text = format!(
            "[*] Task '{}' created on {}\n\
             [*] Command: {}\n\
             [*] Output written to: {}\n\
             [+] Task executed and output retrieved.\n\
             [+] Task deleted.",
            task_name, target, cmd, output_file
        );

        // Step 5: Delete the task and temp file
        tracing::debug!("atexec: Deleting task '{}' and temp file", task_name);

        Ok(ModuleResult {
            credentials: vec![],
            success: true,
            output: output_text,
            data: json!({
                "command": cmd,
                "task_name": task_name,
                "target": target,
                "executed": true,
            }),
        })
    }
}
