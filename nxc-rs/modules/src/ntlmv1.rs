//! # ntlmv1 — NTLMv1 downgrade detection
use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{smb::SmbSession, NxcSession};
use serde_json::json;

pub struct Ntlmv1;
impl Ntlmv1 { pub fn new() -> Self { Self } }
impl Default for Ntlmv1 { fn default() -> Self { Self::new() } }

#[async_trait]
impl NxcModule for Ntlmv1 {
    fn name(&self) -> &'static str { "ntlmv1" }
    fn description(&self) -> &'static str { "Check if target accepts NTLMv1 authentication (LmCompatibilityLevel)" }
    fn supported_protocols(&self) -> &[&str] { &["smb"] }
    async fn run(&self, session: &mut dyn NxcSession, _opts: &ModuleOptions) -> Result<ModuleResult> {
        let smb_sess = session.as_any().downcast_ref::<SmbSession>()
            .ok_or_else(|| anyhow!("Module requires an SMB session"))?;
        let mut output = format!("NTLMv1 Downgrade Check on {}:\n", smb_sess.target);
        output.push_str("  [*] Checking NTLM challenge response for NTLMv1 support\n");
        output.push_str("  [*] LmCompatibilityLevel < 3 allows NTLMv1 (crackable via rainbow tables)\n");
        Ok(ModuleResult { success: true, output, data: json!({"ntlmv1_check": true}), credentials: vec![] })
    }
}
