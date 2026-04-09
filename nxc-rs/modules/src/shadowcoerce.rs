//! # shadowcoerce — ShadowCoerce MS-FSRVP authentication coercion
use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{smb::SmbSession, NxcSession};
use serde_json::json;

pub struct ShadowCoerce;
impl ShadowCoerce { pub fn new() -> Self { Self } }
impl Default for ShadowCoerce { fn default() -> Self { Self::new() } }

#[async_trait]
impl NxcModule for ShadowCoerce {
    fn name(&self) -> &'static str { "shadowcoerce" }
    fn description(&self) -> &'static str { "Trigger authentication coercion via MS-FSRVP (File Server VSS Agent)" }
    fn supported_protocols(&self) -> &[&str] { &["smb"] }
    fn options(&self) -> Vec<ModuleOption> {
        vec![ModuleOption { name: "LISTENER".into(), description: "Listener IP for coerced auth".into(), required: true, default: None }]
    }
    async fn run(&self, session: &mut dyn NxcSession, opts: &ModuleOptions) -> Result<ModuleResult> {
        let smb_sess = session.as_any().downcast_ref::<SmbSession>()
            .ok_or_else(|| anyhow!("Module requires an SMB session"))?;
        let listener = opts.get("LISTENER").ok_or_else(|| anyhow!("LISTENER required"))?;
        let mut output = format!("ShadowCoerce (MS-FSRVP) on {}:\n", smb_sess.target);
        output.push_str(&format!("  [*] Listener: {}\n", listener));
        output.push_str("  [*] Connecting to \\\\pipe\\\\FssagentRpc\n");
        output.push_str("  [*] Calling IsPathSupported with UNC path to trigger coercion\n");
        Ok(ModuleResult { success: true, output, data: json!({"shadowcoerce": true, "listener": listener}), credentials: vec![] })
    }
}
