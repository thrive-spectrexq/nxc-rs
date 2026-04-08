use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::snmp::{SnmpProtocol, SnmpSession};
use nxc_protocols::NxcSession;

pub struct SnmpEnum;

impl SnmpEnum {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl NxcModule for SnmpEnum {
    fn name(&self) -> &'static str {
        "snmp_enum"
    }

    fn description(&self) -> &'static str {
        "Enumerate SNMP system information"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["snmp"]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        _opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let snmp_sess = session
            .as_any()
            .downcast_ref::<SnmpSession>()
            .ok_or_else(|| anyhow::anyhow!("Invalid session type"))?;

        let protocol = SnmpProtocol::new();
        let report = protocol.enumerate(snmp_sess).await?;

        Ok(ModuleResult {
            credentials: vec![],
            success: true,
            output: report.clone(),
            data: serde_json::json!({ "report": report }),
        })
    }
}
