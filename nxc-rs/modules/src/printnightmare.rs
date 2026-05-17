//! # printnightmare — CVE-2021-1675 PrintNightmare scanner
use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;

pub struct PrintNightmare;
impl PrintNightmare {
    pub fn new() -> Self {
        Self
    }
}
impl Default for PrintNightmare {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for PrintNightmare {
    fn name(&self) -> &'static str {
        "printnightmare"
    }
    fn description(&self) -> &'static str {
        "Scan for CVE-2021-1675 PrintNightmare vulnerability"
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
