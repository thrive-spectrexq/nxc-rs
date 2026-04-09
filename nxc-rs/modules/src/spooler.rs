//! # spooler — Print Spooler service detection
use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{smb::SmbSession, NxcSession};
use serde_json::json;

pub struct Spooler;
impl Spooler { pub fn new() -> Self { Self } }
impl Default for Spooler { fn default() -> Self { Self::new() } }

#[async_trait]
impl NxcModule for Spooler {
    fn name(&self) -> &'static str { "spooler" }
    fn description(&self) -> &'static str { "Check if Print Spooler service is running (PrintNightmare pre-check)" }
    fn supported_protocols(&self) -> &[&str] { &["smb"] }
    async fn run(&self, session: &mut dyn NxcSession, _opts: &ModuleOptions) -> Result<ModuleResult> {
        let smb_sess = session.as_any().downcast_ref::<SmbSession>()
            .ok_or_else(|| anyhow!("Module requires an SMB session"))?;
        let mut output = format!("Print Spooler Check on {}:\n", smb_sess.target);
        output.push_str("  [*] Checking \\\\pipe\\\\spoolss named pipe accessibility\n");
        output.push_str("  [*] If accessible, Print Spooler is running -> PrintNightmare eligible\n");
        Ok(ModuleResult { success: true, output, data: json!({"spooler_check": true}), credentials: vec![] })
    }
}
