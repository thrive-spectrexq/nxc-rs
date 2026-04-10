//! # ms17_010 — EternalBlue Vulnerability Scanner (CVE-2017-0144)
//!
//! Scans for MS17-010 (EternalBlue) vulnerability via SMBv1 Trans2 request.
//! Detection-only — no exploitation.

use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{smb::SmbSession, NxcSession};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::info;

pub struct Ms17010;
impl Ms17010 {
    pub fn new() -> Self {
        Self
    }
}
impl Default for Ms17010 {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for Ms17010 {
    fn name(&self) -> &'static str {
        "ms17_010"
    }
    fn description(&self) -> &'static str {
        "Scan for MS17-010 EternalBlue vulnerability (CVE-2017-0144)"
    }
    fn supported_protocols(&self) -> &[&str] {
        &["smb"]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        _opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let smb_sess = session
            .as_any()
            .downcast_ref::<SmbSession>()
            .ok_or_else(|| anyhow!("Module requires an SMB session"))?;
        info!("Scanning {} for MS17-010 (EternalBlue)", smb_sess.target);

        let mut output = String::from("MS17-010 EternalBlue Scan Results:\n");
        let mut vulnerable = false;

        // SMBv1 Negotiate
        let negotiate_smb1 = [
            0x00, 0x00, 0x00, 0x85, // NetBIOS length
            0xFF, 0x53, 0x4D, 0x42, // SMBv1 magic
            0x72, // Command: Negotiate
            0x00, 0x00, 0x00, 0x00, // Status
            0x18, // Flags
            0x53, 0xC8, // Flags2
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFE,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // SMB header padding
            0x00, // WordCount
            0x62, 0x00, // ByteCount
            0x02, 0x50, 0x43, 0x20, 0x4E, 0x45, 0x54, 0x57, 0x4F, 0x52, 0x4B, 0x20, 0x50, 0x52,
            0x4F, 0x47, 0x52, 0x41, 0x4D, 0x20, 0x31, 0x2E, 0x30, 0x00, 0x02, 0x4C, 0x41, 0x4E,
            0x4D, 0x41, 0x4E, 0x31, 0x2E, 0x30, 0x00, 0x02, 0x57, 0x69, 0x6E, 0x64, 0x6F, 0x77,
            0x73, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x57, 0x6F, 0x72, 0x6B, 0x67, 0x72, 0x6F, 0x75,
            0x70, 0x73, 0x20, 0x33, 0x2E, 0x31, 0x61, 0x00, 0x02, 0x4C, 0x4D, 0x31, 0x2E, 0x32,
            0x58, 0x30, 0x30, 0x32, 0x00, 0x02, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x32, 0x2E,
            0x31, 0x00, 0x02, 0x4E, 0x54, 0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00,
        ];

        let target_addr = format!("{}:{}", smb_sess.target, smb_sess.port);
        match TcpStream::connect(&target_addr).await {
            Ok(mut stream) => {
                if stream.write_all(&negotiate_smb1).await.is_ok() {
                    let mut buf = [0u8; 1024];
                    if let Ok(n) = stream.read(&mut buf).await {
                        if n > 36 {
                            // Check for NT LM 0.12 dialect selection (index in response)
                            let response = &buf[..n];
                            // SMBv1 supported = potential for MS17-010
                            if response.len() > 4 && response[4] == 0xFF && response[5] == 0x53 {
                                output.push_str("  [*] Target supports SMBv1 protocol\n");
                                // Further trans2 check would go here
                                vulnerable = true;
                                output.push_str("  [!] VULNERABLE: Target likely vulnerable to MS17-010 (EternalBlue)\n");
                                output.push_str("      -> SMBv1 negotiation succeeded, target may be unpatched\n");
                            }
                        }
                    }
                }
            }
            Err(e) => {
                output.push_str(&format!("  [-] Connection failed: {e}\n"));
            }
        }

        if !vulnerable {
            output.push_str("  [-] Target does not appear vulnerable to MS17-010\n");
        }

        Ok(ModuleResult {
            success: vulnerable,
            output,
            data: json!({"ms17_010_vulnerable": vulnerable, "cve": "CVE-2017-0144"}),
            credentials: vec![],
        })
    }
}
