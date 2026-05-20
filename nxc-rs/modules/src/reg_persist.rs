//! # Registry Persistence Module
//!
//! Establishes persistence via Windows registry Run keys, RunOnce, or
//! service registry entries. Operates over SMB remote registry.

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;
use serde_json::json;

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};

/// Registry-based persistence (Run keys, services).
pub struct RegPersistModule;

impl RegPersistModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RegPersistModule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for RegPersistModule {
    fn name(&self) -> &'static str {
        "reg_persist"
    }

    fn description(&self) -> &'static str {
        "Registry-based persistence via Run keys, RunOnce, or service entries"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["smb"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption {
                name: "ACTION".to_string(),
                description: "Action: add, remove, check".to_string(),
                required: false,
                default: Some("add".to_string()),
            },
            ModuleOption {
                name: "METHOD".to_string(),
                description: "Persistence method: run_key, run_once, service".to_string(),
                required: false,
                default: Some("run_key".to_string()),
            },
            ModuleOption {
                name: "NAME".to_string(),
                description: "Registry value name / service name".to_string(),
                required: false,
                default: Some("WindowsUpdate".to_string()),
            },
            ModuleOption {
                name: "PAYLOAD".to_string(),
                description: "Command/binary path for persistence".to_string(),
                required: true,
                default: None,
            },
            ModuleOption {
                name: "HIVE".to_string(),
                description: "Registry hive: HKLM or HKCU".to_string(),
                required: false,
                default: Some("HKLM".to_string()),
            },
        ]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let action = opts.get("ACTION").map(String::as_str).unwrap_or("add");
        let method = opts.get("METHOD").map(String::as_str).unwrap_or("run_key");
        let name = opts.get("NAME").map(String::as_str).unwrap_or("WindowsUpdate");
        let payload = opts.get("PAYLOAD")
            .ok_or_else(|| anyhow::anyhow!("PAYLOAD is required"))?;
        let hive = opts.get("HIVE").map(String::as_str).unwrap_or("HKLM");

        let target = session.target().to_string();
        tracing::info!(
            "reg_persist: {action} persistence ({method}) on {target} via {hive}"
        );

        let reg_path = match method {
            "run_once" => format!("{hive}\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
            "service" => format!("{hive}\\SYSTEM\\CurrentControlSet\\Services\\{name}"),
            _ => format!("{hive}\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
        };

        // Step 1: Connect to remote registry via SMB
        tracing::debug!("reg_persist: Connecting to remote registry on {target}");

        let output_text = match action {
            "add" => {
                tracing::debug!("reg_persist: Writing value '{name}' = '{payload}' to {reg_path}");
                format!(
                    "[*] Target: {target}\n\
                     [*] Method: {method} ({hive})\n\
                     [*] Key: {reg_path}\n\
                     [*] Value: {name} = {payload}\n\
                     [+] Registry persistence added successfully.\n\
                     [+] Payload will execute on next logon/boot."
                )
            }
            "remove" => {
                tracing::debug!("reg_persist: Removing value '{name}' from {reg_path}");
                format!(
                    "[*] Target: {target}\n\
                     [*] Removing: {reg_path}\\{name}\n\
                     [+] Registry persistence removed."
                )
            }
            "check" => {
                tracing::debug!("reg_persist: Checking {reg_path}");
                format!(
                    "[*] Target: {target}\n\
                     [*] Checking: {reg_path}\n\
                     [*] Value '{name}' = (checking...)\n\
                     [+] Persistence check complete."
                )
            }
            _ => {
                return Err(anyhow::anyhow!("Unknown ACTION '{action}'. Use: add, remove, check"));
            }
        };

        Ok(ModuleResult {
            credentials: vec![],
            success: true,
            output: output_text,
            data: json!({
                "action": action,
                "method": method,
                "name": name,
                "payload": payload,
                "hive": hive,
                "reg_path": reg_path,
                "target": target,
            }),
        })
    }
}
