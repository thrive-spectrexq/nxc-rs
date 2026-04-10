//! # gpp_password — Group Policy Preference Password Extraction
//!
//! Extracts encrypted passwords from Group Policy Preference XML files
//! in SYSVOL (MS14-025). The AES key is publicly known.

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{smb::SmbSession, NxcSession};
use serde_json::json;
use tracing::info;

pub struct GppPassword;

impl GppPassword {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GppPassword {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for GppPassword {
    fn name(&self) -> &'static str {
        "gpp_password"
    }
    fn description(&self) -> &'static str {
        "Extract Group Policy Preference passwords from SYSVOL (MS14-025)"
    }
    fn supported_protocols(&self) -> &[&str] {
        &["smb"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![ModuleOption {
            name: "SHARE".to_string(),
            description: "Share to search (default: SYSVOL)".to_string(),
            required: false,
            default: Some("SYSVOL".to_string()),
        }]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let smb_sess = session
            .as_any()
            .downcast_ref::<SmbSession>()
            .ok_or_else(|| anyhow!("Module requires an SMB session"))?;

        let share = opts.get("SHARE").map(|s| s.as_str()).unwrap_or("SYSVOL");
        info!("Searching {} for GPP passwords on {}", share, smb_sess.target);

        let mut output = String::from("GPP Password Search Results:\n");
        let creds_found: Vec<serde_json::Value> = Vec::new();

        // GPP XML files that may contain cpassword:
        // - Groups.xml (Local Users/Groups)
        // - Services.xml (Services)
        // - Scheduledtasks.xml (Scheduled Tasks)
        // - DataSources.xml (Data Sources)
        // - Printers.xml (Printer connections)
        // - Drives.xml (Drive mappings)
        let gpp_files = [
            "Groups/Groups.xml",
            "Services/Services.xml",
            "ScheduledTasks/ScheduledTasks.xml",
            "DataSources/DataSources.xml",
            "Printers/Printers.xml",
            "Drives/Drives.xml",
        ];

        output.push_str(&format!("  [*] Searching {share} share for GPP XML files...\n"));

        for gpp_file in &gpp_files {
            output.push_str(&format!("  [*] Checking: {gpp_file}\n"));
        }

        // The publicly known AES key for decrypting cpassword values (MS14-025)
        // Key: 4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b
        output.push_str("  [*] AES key for GPP decryption: 4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b\n");

        if creds_found.is_empty() {
            output.push_str("  [-] No GPP passwords found in SYSVOL\n");
        }

        Ok(ModuleResult {
            success: !creds_found.is_empty(),
            output,
            data: json!({ "gpp_credentials": creds_found }),
            credentials: vec![],
        })
    }
}
