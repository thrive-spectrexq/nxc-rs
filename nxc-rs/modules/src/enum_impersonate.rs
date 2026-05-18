//! # enum_impersonate — Impersonation Privilege Checker
use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;

pub struct EnumImpersonate;
impl EnumImpersonate {
    pub fn new() -> Self {
        Self
    }
}
impl Default for EnumImpersonate {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for EnumImpersonate {
    fn name(&self) -> &'static str {
        "enum_impersonate"
    }
    fn description(&self) -> &'static str {
        "Enumerate SeImpersonatePrivilege and SeAssignPrimaryTokenPrivilege for Potato attacks"
    }
    fn supported_protocols(&self) -> &[&str] {
        &["smb"]
    }
    async fn run(
        &self,
        _session: &mut dyn NxcSession,
        _opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        Err(anyhow::anyhow!("Module not yet implemented"))
    }
}
