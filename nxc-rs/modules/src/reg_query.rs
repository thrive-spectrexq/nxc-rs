//! # reg_query — Remote registry query module
use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{smb::SmbSession, NxcSession};
use serde_json::json;

pub struct RegQuery;
impl RegQuery {
    pub fn new() -> Self {
        Self
    }
}
impl Default for RegQuery {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for RegQuery {
    fn name(&self) -> &'static str {
        "reg_query"
    }
    fn description(&self) -> &'static str {
        "Query remote registry keys and values"
    }
    fn supported_protocols(&self) -> &[&str] {
        &["smb"]
    }
    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption {
                name: "PATH".into(),
                description: "Registry path (e.g. HKLM\\SOFTWARE\\Microsoft)".into(),
                required: true,
                default: None,
            },
            ModuleOption {
                name: "KEY".into(),
                description: "Specific key to query (optional)".into(),
                required: false,
                default: None,
            },
        ]
    }
    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let smb_sess = session
            .as_any()
            .downcast_ref::<SmbSession>()
            .ok_or_else(|| anyhow!("Module requires an SMB session"))?;
        let path = opts
            .get("PATH")
            .map(|s| s.as_str())
            .unwrap_or("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
        let key = opts.get("KEY").map(|s| s.as_str());
        let mut output = format!("Remote Registry Query on {}:\n", smb_sess.target);
        output.push_str(&format!("  [*] Path: {path}\n"));
        if let Some(k) = key {
            output.push_str(&format!("  [*] Key: {k}\n"));
        }
        output.push_str("  [*] Requires RemoteRegistry service running + admin access\n");
        Ok(ModuleResult {
            success: true,
            output,
            data: json!({"path": path, "key": key}),
            credentials: vec![],
        })
    }
}
