//! # sccm — SCCM/MECM reconnaissance
use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;

pub struct Sccm;
impl Sccm {
    pub fn new() -> Self {
        Self
    }
}
impl Default for Sccm {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for Sccm {
    fn name(&self) -> &'static str {
        "sccm"
    }
    fn description(&self) -> &'static str {
        "Enumerate SCCM/MECM client and server configuration"
    }
    fn supported_protocols(&self) -> &[&str] {
        &["smb", "ldap"]
    }
    async fn run(
        &self,
        _session: &mut dyn NxcSession,
        _opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        Err(anyhow::anyhow!("Module not yet implemented"))
    }
}
