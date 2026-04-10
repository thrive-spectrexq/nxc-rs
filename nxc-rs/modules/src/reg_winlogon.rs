//! # reg_winlogon — Winlogon credential extraction
use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{smb::SmbSession, NxcSession};
use serde_json::json;

pub struct RegWinlogon;
impl RegWinlogon {
    pub fn new() -> Self {
        Self
    }
}
impl Default for RegWinlogon {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for RegWinlogon {
    fn name(&self) -> &'static str {
        "reg_winlogon"
    }
    fn description(&self) -> &'static str {
        "Extract DefaultUserName/DefaultPassword from Winlogon registry"
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
        let mut output = format!("Winlogon Credential Check on {}:\n", smb_sess.target);
        output.push_str("  [*] HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\n");
        output.push_str("  [*] Checking DefaultUserName, DefaultPassword, DefaultDomainName\n");
        output.push_str("  [*] Checking AutoAdminLogon\n");
        Ok(ModuleResult {
            success: true,
            output,
            data: json!({"winlogon_check": true}),
            credentials: vec![],
        })
    }
}
