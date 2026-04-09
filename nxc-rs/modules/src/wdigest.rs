//! # wdigest — WDigest plaintext credential caching toggle
use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{smb::SmbSession, NxcSession};
use serde_json::json;

pub struct Wdigest;
impl Wdigest { pub fn new() -> Self { Self } }
impl Default for Wdigest { fn default() -> Self { Self::new() } }

#[async_trait]
impl NxcModule for Wdigest {
    fn name(&self) -> &'static str { "wdigest" }
    fn description(&self) -> &'static str { "Enable/disable WDigest plaintext credential caching (UseLogonCredential)" }
    fn supported_protocols(&self) -> &[&str] { &["smb"] }
    fn options(&self) -> Vec<ModuleOption> {
        vec![ModuleOption { name: "ACTION".into(), description: "check, enable, or disable".into(), required: false, default: Some("check".into()) }]
    }
    async fn run(&self, session: &mut dyn NxcSession, opts: &ModuleOptions) -> Result<ModuleResult> {
        let smb_sess = session.as_any().downcast_ref::<SmbSession>()
            .ok_or_else(|| anyhow!("Module requires an SMB session"))?;
        let action = opts.get("ACTION").map(|s| s.as_str()).unwrap_or("check");
        let mut output = format!("WDigest {} on {}:\n", action, smb_sess.target);
        output.push_str("  [*] Registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential\n");
        match action {
            "enable" => output.push_str("  [*] Would set UseLogonCredential = 1 (requires admin + reboot)\n"),
            "disable" => output.push_str("  [*] Would set UseLogonCredential = 0 (requires admin + reboot)\n"),
            _ => output.push_str("  [*] Checking current WDigest status (requires admin)\n"),
        }
        Ok(ModuleResult { success: true, output, data: json!({"action": action}), credentials: vec![] })
    }
}
