//! # Enum Pipes Module
//!
//! Enumerates named pipes over SMB (IPC$) to identify available RPC services.

use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;
use tracing::info;

pub struct EnumPipesModule;

impl Default for EnumPipesModule {
    fn default() -> Self {
        Self::new()
    }
}

impl EnumPipesModule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl NxcModule for EnumPipesModule {
    fn name(&self) -> &'static str {
        "enum_pipes"
    }

    fn description(&self) -> &'static str {
        "Enumerate named pipes on the remote host via SMB"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["smb"]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        _opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        info!("SMB: Enumerating named pipes on {}", session.target());

        let smb_sess = session
            .as_any()
            .downcast_ref::<nxc_protocols::smb::SmbSession>()
            .ok_or_else(|| anyhow::anyhow!("Not an SMB session"))?;

        let protocol = nxc_protocols::smb::SmbProtocol::new();
        let pipes = protocol.enumerate_named_pipes(smb_sess).await?;

        let mut output = String::new();
        output.push_str("[+] Discovered Named Pipes:\n");
        for pipe in &pipes {
            output.push_str(&format!("  - {pipe}\n"));
        }

        if pipes.is_empty() {
            output.push_str("  (None found)\n");
        }

        Ok(ModuleResult {
            credentials: vec![],
            success: true,
            output,
            data: serde_json::json!({
                "pipes": pipes,
            }),
        })
    }
}
