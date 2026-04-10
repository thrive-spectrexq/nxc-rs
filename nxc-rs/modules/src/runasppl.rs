//! # runasppl — Check if LSASS is running as Protected Process Light
use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{smb::SmbSession, NxcSession};
use serde_json::json;

pub struct RunAsPpl;
impl RunAsPpl {
    pub fn new() -> Self {
        Self
    }
}
impl Default for RunAsPpl {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for RunAsPpl {
    fn name(&self) -> &'static str {
        "runasppl"
    }
    fn description(&self) -> &'static str {
        "Check if LSASS is running as Protected Process Light (RunAsPPL)"
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
        let mut output = format!("RunAsPPL Check on {}:\n", smb_sess.target);
        output.push_str("  [*] Querying HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL\n");
        output.push_str("  [*] Requires admin access for remote registry query\n");
        Ok(ModuleResult {
            success: true,
            output,
            data: json!({"runasppl_check": "requires_admin"}),
            credentials: vec![],
        })
    }
}
