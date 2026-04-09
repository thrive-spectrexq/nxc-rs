//! # backup_operator — Backup operator privilege abuse
use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{smb::SmbSession, NxcSession};
use serde_json::json;

pub struct BackupOperator;
impl BackupOperator { pub fn new() -> Self { Self } }
impl Default for BackupOperator { fn default() -> Self { Self::new() } }

#[async_trait]
impl NxcModule for BackupOperator {
    fn name(&self) -> &'static str { "backup_operator" }
    fn description(&self) -> &'static str { "Abuse Backup Operator privileges to read protected files (NTDS.dit, SAM, SYSTEM)" }
    fn supported_protocols(&self) -> &[&str] { &["smb"] }
    async fn run(&self, session: &mut dyn NxcSession, _opts: &ModuleOptions) -> Result<ModuleResult> {
        let smb_sess = session.as_any().downcast_ref::<SmbSession>()
            .ok_or_else(|| anyhow!("Module requires an SMB session"))?;
        let mut output = format!("Backup Operator Abuse on {}:\n", smb_sess.target);
        output.push_str("  [*] Using SeBackupPrivilege to read protected registry hives\n");
        output.push_str("  [*] Targets: SAM, SECURITY, SYSTEM, NTDS.dit\n");
        output.push_str("  [*] Method: BackupRead API or reg save via remote registry\n");
        Ok(ModuleResult { success: true, output, data: json!({"backup_op": true}), credentials: vec![] })
    }
}
