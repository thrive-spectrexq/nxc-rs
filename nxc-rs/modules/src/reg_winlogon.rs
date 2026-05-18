//! # reg_winlogon — Winlogon credential extraction
use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;

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
        _session: &mut dyn NxcSession,
        _opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        Err(anyhow::anyhow!("Module not yet implemented"))
    }
}
