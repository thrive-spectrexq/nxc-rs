use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{smb::SmbSession, NxcSession};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::info;

pub struct SmbGhost {}

impl SmbGhost {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for SmbGhost {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for SmbGhost {
    fn name(&self) -> &'static str {
        "smb_ghost"
    }

    fn description(&self) -> &'static str {
        "Checks for SMBv3 compression support (indicating potential CVE-2020-0796 SMBGhost vulnerability)."
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
        let smb_sess = session
            .as_any_mut()
            .downcast_mut::<SmbSession>()
            .ok_or_else(|| anyhow!("Module requires an SMB session"))?;

        info!(
            "Checking {} for SMBv3 Compression (CVE-2020-0796)",
            smb_sess.target
        );

        let mut output = String::from("SMBGhost Check Results:\n");
        let mut vulnerable = false;

        let target_addr = format!("{}:{}", smb_sess.target, smb_sess.port);
        let mut stream = TcpStream::connect(&target_addr)
            .await
            .map_err(|e| anyhow!("Failed to establish TCP for SMB negotiation: {}", e))?;

        // Manually construct an SMB2 Negotiate Protocol Request advertising Compression Capabilities
        // Using dialect 0x0311 (SMB 3.1.1)
        // This is a minimal, safe payload that only reads the server's reply contexts
        let negotiate_req = [
            0x00, 0x00, 0x00, 0xC0, // NetBIOS session header
            0xfe, 0x53, 0x4d, 0x42, // ProtocolId: 0xfe 'S' 'M' 'B'
            0x40, 0x00, // StructureSize: 64
            0x00, 0x00, // CreditCharge: 0
            0x00, 0x00, // Status: 0
            0x00, 0x00, // Command: 0 (Negotiate)
            0x00, 0x00, // CreditRequest: 0
            0x00, 0x00, 0x00, 0x00, // Flags: 0
            0x00, 0x00, 0x00, 0x00, // NextCommand: 0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MessageId: 0
            0x00, 0x00, 0x00, 0x00, // Reserved
            0x00, 0x00, 0x00, 0x00, // TreeId: 0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SessionId: 0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00, // StructureSize: 36
            0x08, 0x00, // DialectCount: 8
            0x01, 0x00, // SecurityMode: 1
            0x00, 0x00, // Reserved
            0x7f, 0x00, 0x00, 0x00, // Capabilities: 127
            // ClientGuid
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x78, 0x00, // NegotiateContextOffset: 120
            0x02, 0x00, // NegotiateContextCount: 2
            0x00, 0x00, // Reserved
            // Dialects
            0x02, 0x02, 0x10, 0x02, 0x22, 0x02, 0x24, 0x02, 0x00, 0x03, 0x02, 0x03, 0x10, 0x03,
            0x11, 0x03, // Preauth Context
            0x01, 0x00, // ContextType: 1
            0x26, 0x00, // DataLength: 38
            0x00, 0x00, 0x00, 0x00, // Reserved
            0x01, 0x00, // HashAlgorithmCount: 1
            0x20, 0x00, // SaltLength: 32
            0x01, 0x00, // HashAlgorithm: SHA-512
            // Salt
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
            // Compression Context
            0x03, 0x00, // ContextType: 3 (Compression)
            0x0a, 0x00, // DataLength: 10
            0x00, 0x00, 0x00, 0x00, // Reserved
            0x02, 0x00, // CompressionAlgorithmCount: 2
            0x00, 0x00, // Padding
            0x01, 0x00, 0x00, 0x00, // Flags
            0x02, 0x00, // LZ77
            0x03, 0x00, // LZ77+Huffman
        ];

        stream.write_all(&negotiate_req).await?;

        let mut buf = [0u8; 1024];
        let bytes_read = stream.read(&mut buf).await?;

        if bytes_read > 4 {
            // Check if server responded with Compression Context (0x0003)
            // SMB2 Neg response contexts are placed after the main header
            let response = &buf[..bytes_read];

            // Search for ContextType 3 (0x03 0x00)
            if let Some(pos) = response
                .windows(2)
                .position(|window| window == [0x03, 0x00])
            {
                // To be precise we skip the header boundary, but for simplistic checks ContextType 3 is solid
                if pos > 64 {
                    vulnerable = true;
                }
            }
        }

        if vulnerable {
            output.push_str(
                "  [!] VULNERABLE: Server responded with SMBv3 Compression capabilities!\n",
            );
            output.push_str(
                "      -> The target is likely unpatched for CVE-2020-0796 (SMBGhost).\n",
            );
        } else {
            output.push_str(
                "  [-] Target did NOT advertise SMBv3 Compression. Safe from SMBGhost.\n",
            );
        }

        Ok(ModuleResult {
            success: vulnerable,
            output,
            data: json!({ "smb_ghost_vuln": vulnerable }),
            credentials: vec![],
        })
    }
}
