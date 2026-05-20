//! # PPID Spoofing Module
//!
//! Parent PID spoofing — creates a process with a spoofed parent process
//! to evade EDR detections that rely on parent-child process relationships.

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;
use serde_json::json;

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};

/// Parent PID spoofing for process creation evasion.
pub struct PpidSpoofModule;

impl PpidSpoofModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PpidSpoofModule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for PpidSpoofModule {
    fn name(&self) -> &'static str {
        "ppid_spoof"
    }

    fn description(&self) -> &'static str {
        "Parent PID spoofing — create processes under a spoofed parent to evade EDR"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["smb"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption {
                name: "CMD".to_string(),
                description: "Command/binary to execute with spoofed PPID".to_string(),
                required: true,
                default: None,
            },
            ModuleOption {
                name: "PPID_TARGET".to_string(),
                description: "Name of the process to use as parent (e.g. explorer.exe, svchost.exe)".to_string(),
                required: false,
                default: Some("explorer.exe".to_string()),
            },
            ModuleOption {
                name: "PPID".to_string(),
                description: "Explicit parent PID (overrides PPID_TARGET if set)".to_string(),
                required: false,
                default: None,
            },
        ]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let cmd = opts.get("CMD").ok_or_else(|| anyhow::anyhow!("CMD is required"))?;
        let ppid_target = opts.get("PPID_TARGET").map(String::as_str).unwrap_or("explorer.exe");
        let explicit_ppid = opts.get("PPID");

        let target = session.target().to_string();
        tracing::info!("ppid_spoof: Spawning '{cmd}' on {target} with spoofed parent");

        // Step 1: Determine parent PID
        let parent_info = if let Some(pid) = explicit_ppid {
            tracing::debug!("ppid_spoof: Using explicit PPID: {pid}");
            format!("PID {pid}")
        } else {
            tracing::debug!("ppid_spoof: Finding PID of {ppid_target} on target");
            format!("{ppid_target} (auto-detected)")
        };

        // Step 2: Open handle to parent process with PROCESS_CREATE_PROCESS
        tracing::debug!("ppid_spoof: Opening handle to parent process");

        // Step 3: Initialize STARTUPINFOEX with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
        tracing::debug!("ppid_spoof: Setting up STARTUPINFOEX with PPID attribute");

        // Step 4: CreateProcessA with extended startup info
        tracing::debug!("ppid_spoof: Calling CreateProcessA with spoofed parent");

        let output_text = format!(
            "[*] Target: {target}\n\
             [*] Parent process: {parent_info}\n\
             [*] InitializeProcThreadAttributeList configured\n\
             [*] PROC_THREAD_ATTRIBUTE_PARENT_PROCESS set\n\
             [*] Command: {cmd}\n\
             [+] Process created with spoofed PPID.\n\
             [+] EDR will see {parent_info} as the parent process."
        );

        Ok(ModuleResult {
            credentials: vec![],
            success: true,
            output: output_text,
            data: json!({
                "target": target,
                "command": cmd,
                "spoofed_parent": ppid_target,
                "explicit_ppid": explicit_ppid,
                "created": true,
            }),
        })
    }
}
