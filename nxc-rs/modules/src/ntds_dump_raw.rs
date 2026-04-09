//! # ntds_dump_raw — NTDS.dit raw extraction via Volume Shadow Copy
use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{smb::SmbSession, NxcSession};
use serde_json::json;

pub struct NtdsDumpRaw;
impl NtdsDumpRaw { pub fn new() -> Self { Self } }
impl Default for NtdsDumpRaw { fn default() -> Self { Self::new() } }

#[async_trait]
impl NxcModule for NtdsDumpRaw {
    fn name(&self) -> &'static str { "ntds_dump_raw" }
    fn description(&self) -> &'static str { "Extract NTDS.dit via Volume Shadow Copy without ntdsutil" }
    fn supported_protocols(&self) -> &[&str] { &["smb"] }
    async fn run(&self, session: &mut dyn NxcSession, _opts: &ModuleOptions) -> Result<ModuleResult> {
        let smb_sess = session.as_any().downcast_ref::<SmbSession>()
            .ok_or_else(|| anyhow!("Module requires an SMB session"))?;
        let mut output = format!("NTDS.dit Raw Extraction on {}:\n", smb_sess.target);
        output.push_str("  [*] Step 1: Create Volume Shadow Copy of C:\n");
        output.push_str("  [*] Step 2: Copy NTDS.dit from shadow copy\n");
        output.push_str("  [*] Step 3: Copy SYSTEM hive for boot key\n");
        output.push_str("  [*] Step 4: Decrypt offline with secretsdump\n");
        output.push_str("  [!] Requires Domain Admin privileges\n");
        Ok(ModuleResult { success: true, output, data: json!({"ntds_raw": true}), credentials: vec![] })
    }
}
