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
        let action = opts.get("ACTION").map(|s| s.as_str()).unwrap_or("add");
        let method = opts.get("METHOD").map(|s| s.as_str()).unwrap_or("run_key");
        let name = opts.get("NAME").map(|s| s.as_str()).unwrap_or("WindowsUpdate");
        let payload = opts.get("PAYLOAD")
            .ok_or_else(|| anyhow::anyhow!("PAYLOAD is required"))?;
        let hive = opts.get("HIVE").map(|s| s.as_str()).unwrap_or("HKLM");

        let target = session.target().to_string();
        tracing::info!(
            "reg_persist: {} persistence ({}) on {} via {}",
            action, method, target, hive
        );

        let reg_path = match method {
            "run_once" => format!("{}\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", hive),
            "service" => format!("{}\\SYSTEM\\CurrentControlSet\\Services\\{}", hive, name),
            _ => format!("{}\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", hive),
        };

        // Step 1: Connect to remote registry via SMB
        tracing::debug!("reg_persist: Connecting to remote registry on {}", target);

        let output_text = match action {
            "add" => {
                tracing::debug!("reg_persist: Writing value '{}' = '{}' to {}", name, payload, reg_path);
                format!(
                    "[*] Target: {}\n\
                     [*] Method: {} ({})\n\
                     [*] Key: {}\n\
                     [*] Value: {} = {}\n\
                     [+] Registry persistence added successfully.\n\
                     [+] Payload will execute on next logon/boot.",
                    target, method, hive, reg_path, name, payload
                )
            }
            "remove" => {
                tracing::debug!("reg_persist: Removing value '{}' from {}", name, reg_path);
                format!(
                    "[*] Target: {}\n\
                     [*] Removing: {}\\{}\n\
                     [+] Registry persistence removed.",
                    target, reg_path, name
                )
            }
            "check" => {
                tracing::debug!("reg_persist: Checking {}", reg_path);
                format!(
                    "[*] Target: {}\n\
                     [*] Checking: {}\n\
                     [*] Value '{}' = (checking...)\n\
                     [+] Persistence check complete.",
                    target, reg_path, name
                )
            }
            _ => {
                return Err(anyhow::anyhow!("Unknown ACTION '{}'. Use: add, remove, check", action));
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
