//! # dcshadow — Remote DCShadow (Protocol Smuggling) Module
//!
//! Orchestrates a DCShadow attack using fileless payload injection.
//! It constructs a PowerShell script that invokes Mimikatz (`lsadump::dcshadow`)
//! to temporarily register a rogue Domain Controller and push arbitrary AD attributes.

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;

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
                description: "The distinguished name or sAMAccountName of the target object"
                    .to_string(),
                required: true,
                default: None,
            },
            ModuleOption {
                name: "ATTRIBUTE".to_string(),
                description: "The AD attribute to modify (e.g., primaryGroupId, sidHistory)"
                    .to_string(),
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
                description: "URL to download Invoke-Mimikatz.ps1 (default uses a placeholder)"
                    .to_string(),
                required: false,
                default: Some("http://127.0.0.1/Invoke-Mimikatz.ps1".to_string()),
            },
        ]
    }

    async fn run(
        &self,
        _session: &mut dyn NxcSession,
        _opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        Err(anyhow::anyhow!("Module not yet implemented"))
    }
}
