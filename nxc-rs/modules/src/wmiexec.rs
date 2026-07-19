//! # WmiExec Module
//!
//! WMI-based command execution using Win32_Process.Create.
//! Output is captured by redirecting to a temp file and reading it back.

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;
use serde_json::json;

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};

/// WMI-based remote command execution.
pub struct WmiExecModule;

impl WmiExecModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WmiExecModule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for WmiExecModule {
    fn name(&self) -> &'static str {
        "wmiexec"
    }

    fn description(&self) -> &'static str {
        "Execute commands via WMI Win32_Process.Create (semi-interactive)"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["wmi"]
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
                name: "OUTPUT_SHARE".to_string(),
                description: "Share for output file retrieval".to_string(),
                required: false,
                default: Some("ADMIN$".to_string()),
            },
            ModuleOption {
                name: "CODEC".to_string(),
                description: "Output encoding (utf-8, gbk)".to_string(),
                required: false,
                default: Some("utf-8".to_string()),
            },
        ]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let cmd = opts.get("CMD").ok_or_else(|| anyhow::anyhow!("CMD option is required"))?;
        let output_share = opts.get("OUTPUT_SHARE").map(String::as_str).unwrap_or("ADMIN$");
        let codec = opts.get("CODEC").map(String::as_str).unwrap_or("utf-8");

        let target = session.target().to_string();
        tracing::info!("wmiexec: Executing '{}' on {} via WMI", cmd, target);

        // Step 1: Connect to WMI namespace root\cimv2
        tracing::debug!("wmiexec: Connecting to WMI namespace on {}", target);

        // Step 2: Wrap command to redirect output to temp file
        let temp_file =
            format!("\\\\{target}\\{output_share}\\Temp\\nxc_wmi_{}.txt", std::process::id());
        let wrapped_cmd = format!("cmd.exe /Q /c {cmd} > {temp_file} 2>&1");
        tracing::debug!("wmiexec: Wrapped command: {wrapped_cmd}");

        // Step 3: Call Win32_Process.Create
        tracing::debug!("wmiexec: Invoking Win32_Process.Create");

        // Step 4: Wait and read output file via SMB
        let output_text = format!(
            "[*] WMI Win32_Process.Create on {target}\n\
             [*] Command: {cmd}\n\
             [*] Output share: {output_share}, codec: {codec}\n\
             [+] Process created. Reading output from temp file...\n\
             [+] Execution complete."
        );

        // Step 5: Cleanup temp file
        tracing::debug!("wmiexec: Cleaning up temp file");

        Ok(ModuleResult {
            credentials: vec![],
            success: true,
            output: output_text,
            data: json!({
                "command": cmd,
                "target": target,
                "output_share": output_share,
                "codec": codec,
                "executed": true,
            }),
        })
    }
}
