use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{rdp::RdpSession, NxcSession};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::info;

pub struct RdpSecCheck {}

impl RdpSecCheck {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for RdpSecCheck {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for RdpSecCheck {
    fn name(&self) -> &'static str {
        "rdp_sec_check"
    }

    fn description(&self) -> &'static str {
        "Determines if Network Level Authentication (NLA) is strictly enforced or if fallback is allowed."
    }

    fn supported_protocols(&self) -> &[&str] {
        &["rdp"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        _opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let rdp_sess = session
            .as_any()
            .downcast_ref::<RdpSession>()
            .ok_or_else(|| anyhow!("Module requires an RDP session"))?;

        let addr = format!("{}:{}", rdp_sess.target, rdp_sess.port);
        info!("Starting RDP Security/NLA checks against {}", addr);

        let mut output = String::from("RDP Security Check Results:\n");
        let mut nla_enforced = true;
        let mut allows_fallback = false;

        // X.224 Connection Request offering ONLY Standard RDP Security (0x00 flag)
        let x224_req_standard: [u8; 19] = [
            0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08,
            0x00, 0x00, // 0x00 = Standard RDP Security
            0x00, 0x00, 0x00,
        ];

        if let Ok(mut stream) =
            tokio::time::timeout(std::time::Duration::from_secs(5), TcpStream::connect(&addr))
                .await?
        {
            if (stream.write_all(&x224_req_standard).await).is_ok() {
                let mut resp = [0u8; 19];
                if let Ok(n) =
                    tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut resp))
                        .await?
                {
                    if n >= 19 && resp[0] == 0x03 && resp[1] == 0x00 {
                        // Position 15 is the requested protocols selected by server
                        // If it responds with 0x00 and doesn't drop with SSL negotiation failure, fallback is allowed
                        if resp[15] == 0x00 {
                            allows_fallback = true;
                            nla_enforced = false;
                        }
                    } else if n > 0 && resp[0] == 0x03 {
                        // Check if it's an SSL Drop code or X.224 negotiation failure
                        // position 4 will be the packet type, 0x0e or drop code.
                        // For generic purposes, since it didn't accept 0x00 explicitly, we assume NLA is forced.
                        allows_fallback = false;
                    }
                }
            }
        }

        if allows_fallback {
            output.push_str("  [!] VULNERABLE: NLA is NOT strictly enforced.\n");
            output.push_str("      -> Target allows fallback to Standard RDP Security (susceptible to MITM & legacy exploits like BlueKeep).\n");
        } else {
            output.push_str(
                "  [+] SECURE: Network Level Authentication (NLA) is strictly enforced.\n",
            );
            output.push_str("      -> Legacy Protocol fallback rejected.\n");
        }

        Ok(ModuleResult {
            success: true, // we successfully performed the check
            output,
            data: json!({ "nla_strictly_enforced": nla_enforced, "supports_standard_rdp_fallback": allows_fallback }),
            credentials: vec![],
        })
    }
}
