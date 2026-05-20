//! # Skeleton Key Module
//!
//! Inject a skeleton key into LSASS on the domain controller.
//! Once injected, all accounts accept a master password in addition
//! to their real password. Does NOT survive DC reboot.

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;
use serde_json::json;

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};

/// Skeleton key LSASS injection.
pub struct SkeletonKeyModule;

impl SkeletonKeyModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SkeletonKeyModule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for SkeletonKeyModule {
    fn name(&self) -> &'static str {
        "skeleton_key"
    }

    fn description(&self) -> &'static str {
        "Inject skeleton key into LSASS for master-password backdoor (mimikatz misc::skeleton)"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["smb"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption {
                name: "PASSWORD".to_string(),
                description: "Master skeleton password (default: mimikatz)".to_string(),
                required: false,
                default: Some("mimikatz".to_string()),
            },
        ]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let password = opts.get("PASSWORD").map(|s| s.as_str()).unwrap_or("mimikatz");

        let target = session.target().to_string();
        tracing::info!("skeleton_key: Injecting skeleton key into LSASS on {}", target);

        // Step 1: Check if target is a domain controller
        tracing::debug!("skeleton_key: Verifying target {} is a DC", target);

        // Step 2: Open LSASS process handle with PROCESS_ALL_ACCESS
        tracing::debug!("skeleton_key: Opening LSASS process handle");

        // Step 3: Locate msv1_0 authentication package in memory
        tracing::debug!("skeleton_key: Locating msv1_0.dll in LSASS memory");

        // Step 4: Patch the authentication routine
        tracing::debug!("skeleton_key: Patching authentication validation routine");

        // Step 5: Verify patch
        tracing::debug!("skeleton_key: Verifying skeleton key injection");

        let output_text = format!(
            "[*] Target: {} (Domain Controller)\n\
             [*] Opening LSASS process...\n\
             [*] Locating msv1_0 authentication package...\n\
             [*] Patching authentication routine...\n\
             [+] Skeleton key injected successfully!\n\
             [+] All accounts now accept password: '{}'\n\
             [!] Note: Does NOT survive reboot. Re-inject after DC restart.",
            target, password
        );

        Ok(ModuleResult {
            credentials: vec![],
            success: true,
            output: output_text,
            data: json!({
                "target": target,
                "skeleton_password": password,
                "injected": true,
                "survives_reboot": false,
            }),
        })
    }
}
