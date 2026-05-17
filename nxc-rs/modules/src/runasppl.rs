//! # runasppl — Check if LSASS is running as Protected Process Light
use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;

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
        _session: &mut dyn NxcSession,
        _opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        Err(anyhow::anyhow!("Module not yet implemented"))
    }
}
