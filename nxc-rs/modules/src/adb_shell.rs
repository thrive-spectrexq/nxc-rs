use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::adb::AdbProtocol;
use nxc_protocols::{NxcProtocol, NxcSession};
use serde_json::json;

pub struct AdbShell;

impl AdbShell {
    pub fn new() -> Self {
        Self
    }
}

impl Default for AdbShell {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for AdbShell {
    fn name(&self) -> &'static str {
        "adb_shell"
    }

    fn description(&self) -> &'static str {
        "Execute a shell command on the Android device via ADB"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["adb"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![ModuleOption {
            name: "cmd".into(),
            description: "Command to execute".into(),
            required: true,
            default: None,
        }]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let cmd = opts
            .get("cmd")
            .ok_or_else(|| anyhow::anyhow!("The 'cmd' option is required for adb_shell module"))?;

        let protocol = AdbProtocol::new();
        match protocol.execute(session, cmd).await {
            Ok(output) => Ok(ModuleResult {
                credentials: vec![],
                success: true,
                output: output.stdout.clone(),
                data: json!({
                    "stdout": output.stdout,
                    "stderr": output.stderr,
                    "exit_code": output.exit_code,
                }),
            }),
            Err(e) => Ok(ModuleResult {
                credentials: vec![],
                success: false,
                output: format!("Failed to execute command: {}", e),
                data: json!({ "error": format!("{}", e) }),
            }),
        }
    }
}
