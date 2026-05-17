use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;

/// NoPac (CVE-2021-42287) Kerberos check.
pub struct Nopac;

impl Nopac {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Nopac {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for Nopac {
    fn name(&self) -> &'static str {
        "nopac"
    }

    fn description(&self) -> &'static str {
        "Check if KDC is vulnerable to NoPac (CVE-2021-42287)"
    }

    fn supported_protocols(&self) -> &[&str] {
        ["smb"].as_slice()
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![]
    }

    async fn run(
        &self,
        _session: &mut dyn NxcSession,
        _opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        Err(anyhow::anyhow!("Module not yet implemented"))
    }
}
