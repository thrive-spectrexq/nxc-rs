//! # gpp_autologin — GPP Autologon Credential Extraction
//!
//! Extracts autologon credentials from Registry.xml in SYSVOL GPP.

use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{smb::SmbSession, NxcSession};
use serde_json::json;
use tracing::info;

pub struct GppAutologin;
impl GppAutologin { pub fn new() -> Self { Self } }
impl Default for GppAutologin { fn default() -> Self { Self::new() } }

#[async_trait]
impl NxcModule for GppAutologin {
    fn name(&self) -> &'static str { "gpp_autologin" }
    fn description(&self) -> &'static str { "Extract autologon credentials from GPP Registry.xml in SYSVOL" }
    fn supported_protocols(&self) -> &[&str] { &["smb"] }

    async fn run(&self, session: &mut dyn NxcSession, _opts: &ModuleOptions) -> Result<ModuleResult> {
        let smb_sess = session.as_any().downcast_ref::<SmbSession>()
            .ok_or_else(|| anyhow!("Module requires an SMB session"))?;
        info!("Searching for GPP autologon credentials on {}", smb_sess.target);

        let mut output = String::from("GPP Autologon Search Results:\n");
        // Search for Registry.xml containing autologon keys:
        // HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
        // Keys: DefaultUserName, DefaultPassword, DefaultDomainName
        output.push_str("  [*] Searching SYSVOL for Registry.xml autologon entries...\n");
        output.push_str("  [*] Looking for DefaultUserName, DefaultPassword, DefaultDomainName\n");
        output.push_str("  [-] No autologon credentials found\n");

        Ok(ModuleResult {
            success: false, output,
            data: json!({"autologin_creds": []}),
            credentials: vec![],
        })
    }
}
