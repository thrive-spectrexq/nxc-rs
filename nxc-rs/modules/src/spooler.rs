//! # spooler — Print Spooler service detection
use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;

pub struct Spooler;
impl Spooler {
    pub fn new() -> Self {
        Self
    }
}
impl Default for Spooler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for Spooler {
    fn name(&self) -> &'static str {
        "spooler"
    }
    fn description(&self) -> &'static str {
        "Check if Print Spooler service is running (PrintNightmare pre-check)"
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
