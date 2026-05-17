//! # ntlmv1 — NTLMv1 downgrade detection
use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;

pub struct Ntlmv1;
impl Ntlmv1 {
    pub fn new() -> Self {
        Self
    }
}
impl Default for Ntlmv1 {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for Ntlmv1 {
    fn name(&self) -> &'static str {
        "ntlmv1"
    }
    fn description(&self) -> &'static str {
        "Check if target accepts NTLMv1 authentication (LmCompatibilityLevel)"
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
