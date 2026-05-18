//! # shadowcoerce — ShadowCoerce MS-FSRVP authentication coercion
use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;

pub struct ShadowCoerce;
impl ShadowCoerce {
    pub fn new() -> Self {
        Self
    }
}
impl Default for ShadowCoerce {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for ShadowCoerce {
    fn name(&self) -> &'static str {
        "shadowcoerce"
    }
    fn description(&self) -> &'static str {
        "Trigger authentication coercion via MS-FSRVP (File Server VSS Agent)"
    }
    fn supported_protocols(&self) -> &[&str] {
        &["smb"]
    }
    fn options(&self) -> Vec<ModuleOption> {
        vec![ModuleOption {
            name: "LISTENER".into(),
            description: "Listener IP for coerced auth".into(),
            required: true,
            default: None,
        }]
    }
    async fn run(
        &self,
        _session: &mut dyn NxcSession,
        _opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        Err(anyhow::anyhow!("Module not yet implemented"))
    }
}
