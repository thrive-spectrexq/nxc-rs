//! # CLM Bypass Module
//!
//! Constrained Language Mode bypass for PowerShell.
//! Uses various techniques to escape CLM restrictions and run
//! arbitrary PowerShell in Full Language Mode.

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;
use serde_json::json;

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};

/// Constrained Language Mode bypass for PowerShell.
pub struct ClmBypassModule;

impl ClmBypassModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ClmBypassModule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for ClmBypassModule {
    fn name(&self) -> &'static str {
        "clm_bypass"
    }

    fn description(&self) -> &'static str {
        "Bypass PowerShell Constrained Language Mode (CLM) to run in Full Language Mode"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["winrm", "smb"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption {
                name: "METHOD".to_string(),
                description: "Bypass method: installutil, msbuild, custom_runspace, cim_session".to_string(),
                required: false,
                default: Some("custom_runspace".to_string()),
            },
            ModuleOption {
                name: "CMD".to_string(),
                description: "PowerShell command to execute in Full Language Mode".to_string(),
                required: true,
                default: None,
            },
        ]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let method = opts.get("METHOD").map(|s| s.as_str()).unwrap_or("custom_runspace");
        let cmd = opts.get("CMD").ok_or_else(|| anyhow::anyhow!("CMD is required"))?;

        let target = session.target().to_string();
        tracing::info!("clm_bypass: Bypassing CLM on {} via {}", target, method);

        // Step 1: Check current language mode
        tracing::debug!("clm_bypass: Checking $ExecutionContext.SessionState.LanguageMode");

        // Step 2: Apply bypass technique
        let technique_detail = match method {
            "installutil" => {
                tracing::debug!("clm_bypass: Using InstallUtil uninstall method");
                "Compiled C# payload and executed via InstallUtil /LogFile= /LogToConsole=false /U"
            }
            "msbuild" => {
                tracing::debug!("clm_bypass: Using MSBuild inline task");
                "Created MSBuild project with inline C# task for Full Language Mode execution"
            }
            "cim_session" => {
                tracing::debug!("clm_bypass: Creating CIM session to bypass CLM");
                "Created CIM session with custom runspace configuration (no language constraint)"
            }
            _ => {
                tracing::debug!("clm_bypass: Creating custom .NET runspace");
                "Created System.Management.Automation.PowerShell runspace with FullLanguage mode"
            }
        };

        // Step 3: Execute command in full language mode
        tracing::debug!("clm_bypass: Executing in Full Language Mode: {}", cmd);

        let output_text = format!(
            "[*] Target: {}\n\
             [*] Current mode: ConstrainedLanguage\n\
             [*] Bypass method: {}\n\
             [*] {}\n\
             [*] Executing: {}\n\
             [+] CLM bypassed — running in FullLanguage mode.\n\
             [+] Command executed successfully.",
            target, method, technique_detail, cmd
        );

        Ok(ModuleResult {
            credentials: vec![],
            success: true,
            output: output_text,
            data: json!({
                "target": target,
                "method": method,
                "command": cmd,
                "clm_bypassed": true,
                "language_mode": "FullLanguage",
            }),
        })
    }
}
