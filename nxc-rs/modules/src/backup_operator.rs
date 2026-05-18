//! # backup_operator — Backup operator privilege abuse
use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;

pub struct BackupOperator;
impl BackupOperator {
    pub fn new() -> Self {
        Self
    }
}
impl Default for BackupOperator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for BackupOperator {
    fn name(&self) -> &'static str {
        "backup_operator"
    }
    fn description(&self) -> &'static str {
        "Abuse Backup Operator privileges to read protected files (NTDS.dit, SAM, SYSTEM)"
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
