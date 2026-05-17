//! # ntds_dump_raw — NTDS.dit raw extraction via Volume Shadow Copy
use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;

pub struct NtdsDumpRaw;
impl NtdsDumpRaw {
    pub fn new() -> Self {
        Self
    }
}
impl Default for NtdsDumpRaw {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for NtdsDumpRaw {
    fn name(&self) -> &'static str {
        "ntds_dump_raw"
    }
    fn description(&self) -> &'static str {
        "Extract NTDS.dit via Volume Shadow Copy without ntdsutil"
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
