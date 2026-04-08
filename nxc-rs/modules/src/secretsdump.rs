use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;
use tracing::info;

pub struct SecretsDumpModule;

impl SecretsDumpModule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl NxcModule for SecretsDumpModule {
    fn name(&self) -> &'static str {
        "secretsdump"
    }

    fn description(&self) -> &'static str {
        "Enumerate and dump SAM/LSA/NTDS secrets from the target"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["smb"]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        _opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        info!(
            "SMB: Starting SecretsDump execution on {}...",
            session.target()
        );

        if let Some(smb_sess) = session
            .as_any()
            .downcast_ref::<nxc_protocols::smb::SmbSession>()
        {
            let protocol = nxc_protocols::smb::SmbProtocol::new();
            match protocol.secrets_dump(smb_sess).await {
                Ok(output) => {
                    return Ok(ModuleResult {
                        credentials: vec![],
                        success: true,
                        output,
                        data: serde_json::json!({}),
                    });
                }
                Err(e) => {
                    return Ok(ModuleResult {
                        credentials: vec![],
                        success: false,
                        output: format!("SecretsDump Error: {}", e),
                        data: serde_json::json!({}),
                    });
                }
            }
        }

        Ok(ModuleResult {
            credentials: vec![],
            success: false,
            output: "Invalid session type for secretsdump".to_string(),
            data: serde_json::json!({}),
        })
    }
}
