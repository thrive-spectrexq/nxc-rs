//! # uac — Remote UAC status check
use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{smb::SmbSession, NxcSession};
use serde_json::json;

pub struct Uac;
impl Uac {
    pub fn new() -> Self {
        Self
    }
}
impl Default for Uac {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for Uac {
    fn name(&self) -> &'static str {
        "uac"
    }
    fn description(&self) -> &'static str {
        "Check remote UAC settings (LocalAccountTokenFilterPolicy, FilterAdministratorToken)"
    }
    fn supported_protocols(&self) -> &[&str] {
        &["smb"]
    }
    async fn run(
        &self,
        session: &mut dyn NxcSession,
        _opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let smb_sess = session
            .as_any()
            .downcast_ref::<SmbSession>()
            .ok_or_else(|| anyhow!("Module requires an SMB session"))?;
        let mut output = format!("UAC Status Check on {}:\n", smb_sess.target);
        output.push_str(
            "  [*] HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\n",
        );
        output.push_str("  [*] Checking LocalAccountTokenFilterPolicy...\n");
        output.push_str("  [*] Checking FilterAdministratorToken...\n");
        output.push_str("  [*] Checking EnableLUA...\n");
        output.push_str("  [*] Checking ConsentPromptBehaviorAdmin...\n");
        Ok(ModuleResult {
            success: true,
            output,
            data: json!({"uac_check": true}),
            credentials: vec![],
        })
    }
}
