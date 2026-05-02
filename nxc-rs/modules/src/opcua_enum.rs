use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::opcua::{OpcUaProtocol, OpcUaSession};
use nxc_protocols::NxcProtocol;
use nxc_protocols::NxcSession;

pub struct OpcUaEnum;

impl Default for OpcUaEnum {
    fn default() -> Self {
        Self::new()
    }
}

impl OpcUaEnum {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl NxcModule for OpcUaEnum {
    fn name(&self) -> &'static str {
        "opcua_enum"
    }

    fn description(&self) -> &'static str {
        "Enumerate OPC-UA server status and metadata"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["opcua"]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        _opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let _opcua_sess = session
            .as_any()
            .downcast_ref::<OpcUaSession>()
            .ok_or_else(|| anyhow::anyhow!("Invalid session type"))?;

        let protocol = OpcUaProtocol::new();
        // NxcProtocol::execute() already performs basic enumeration for OPC-UA
        let output = protocol.execute(session, "enum").await?;

        Ok(ModuleResult {
            credentials: vec![],
            success: true,
            output: output.stdout.clone(),
            data: serde_json::json!({ "metadata": output.stdout }),
        })
    }
}
