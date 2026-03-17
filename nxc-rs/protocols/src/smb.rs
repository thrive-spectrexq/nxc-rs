//! # SMB Protocol Handler
//!
//! SMB2/3 protocol implementation for NetExec-RS.
//! Currently provides real TCP connection with mock SMB negotiation,
//! with the session/auth infrastructure in place for full SMB2 implementation.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::Result;
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use tracing::{debug, info, warn};

// ─── SMB Constants ──────────────────────────────────────────────

/// SMB2 Negotiate Protocol Request magic bytes.
const SMB2_MAGIC: &[u8] = b"\xfeSMB";

/// NetBIOS session service header for SMB.
const NETBIOS_SESSION_MSG: u8 = 0x00;

// ─── SMB Host Info ──────────────────────────────────────────────

/// Enumerated host information from SMB negotiation.
#[derive(Debug, Clone, Default)]
pub struct SmbHostInfo {
    pub hostname: String,
    pub domain: String,
    pub os: String,
    pub os_version: String,
    pub smb_signing: bool,
    pub signing_required: bool,
    pub is_dc: bool,
    pub smb_dialect: String,
}

// ─── SMB Session ────────────────────────────────────────────────

pub struct SmbSession {
    pub target: String,
    pub port: u16,
    pub admin: bool,
    pub host_info: SmbHostInfo,
    stream: Option<TcpStream>,
}

impl NxcSession for SmbSession {
    fn protocol(&self) -> &'static str {
        "smb"
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn is_admin(&self) -> bool {
        self.admin
    }
}

// ─── SMB Share Info ─────────────────────────────────────────────

/// Information about an SMB share.
#[derive(Debug, Clone)]
pub struct ShareInfo {
    pub name: String,
    pub share_type: String,
    pub remark: String,
    pub read_access: bool,
    pub write_access: bool,
}

// ─── SMB Protocol Handler ───────────────────────────────────────

pub struct SmbProtocol {
    pub timeout: Duration,
}

impl SmbProtocol {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(10),
        }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Attempt a basic SMB2 negotiate to extract host info.
    /// Currently returns stub info — full SMB2 negotiate parsing is a future task.
    fn negotiate(stream: &mut TcpStream) -> Result<SmbHostInfo> {
        // Build SMB2 NEGOTIATE request
        let negotiate_req = Self::build_smb2_negotiate_request();

        // Wrap in NetBIOS session header
        let mut packet = Vec::new();
        packet.push(NETBIOS_SESSION_MSG);
        let len = negotiate_req.len() as u32;
        packet.push(((len >> 16) & 0xff) as u8);
        packet.push(((len >> 8) & 0xff) as u8);
        packet.push((len & 0xff) as u8);
        packet.extend_from_slice(&negotiate_req);

        stream.write_all(&packet)?;
        stream.flush()?;

        // Read response (at least the NetBIOS header + SMB2 header)
        let mut header = [0u8; 4];
        stream.read_exact(&mut header)?;

        let response_len = ((header[1] as usize) << 16)
            | ((header[2] as usize) << 8)
            | (header[3] as usize);

        let mut response = vec![0u8; response_len];
        stream.read_exact(&mut response)?;

        // Parse the SMB2 response to extract host info
        let host_info = Self::parse_negotiate_response(&response)?;

        Ok(host_info)
    }

    /// Build a minimal SMB2 NEGOTIATE request.
    fn build_smb2_negotiate_request() -> Vec<u8> {
        let mut pkt = Vec::with_capacity(128);

        // SMB2 Header (64 bytes)
        pkt.extend_from_slice(SMB2_MAGIC);       // Protocol ID
        pkt.extend_from_slice(&64u16.to_le_bytes()); // Structure Size
        pkt.extend_from_slice(&[0u8; 2]);         // Credit Charge
        pkt.extend_from_slice(&[0u8; 4]);         // Status
        pkt.extend_from_slice(&0u16.to_le_bytes()); // Command: NEGOTIATE
        pkt.extend_from_slice(&[0u8; 2]);         // Credits Requested
        pkt.extend_from_slice(&[0u8; 4]);         // Flags
        pkt.extend_from_slice(&[0u8; 4]);         // Next Command
        pkt.extend_from_slice(&[0u8; 8]);         // Message ID
        pkt.extend_from_slice(&[0u8; 4]);         // Reserved / Process ID
        pkt.extend_from_slice(&[0u8; 4]);         // Tree ID
        pkt.extend_from_slice(&[0u8; 8]);         // Session ID
        pkt.extend_from_slice(&[0u8; 16]);        // Signature

        // SMB2 NEGOTIATE Request Body
        pkt.extend_from_slice(&36u16.to_le_bytes()); // Structure Size
        pkt.extend_from_slice(&2u16.to_le_bytes());  // Dialect Count
        pkt.extend_from_slice(&[1u8, 0]);            // Security Mode (signing enabled)
        pkt.extend_from_slice(&[0u8; 2]);            // Reserved
        pkt.extend_from_slice(&[0u8; 4]);            // Capabilities
        pkt.extend_from_slice(&[0u8; 16]);           // Client GUID

        // Negotiate Contexts offset/count (SMB 3.1.1)
        pkt.extend_from_slice(&[0u8; 4]);            // NegotiateContextOffset
        pkt.extend_from_slice(&[0u8; 2]);            // NegotiateContextCount
        pkt.extend_from_slice(&[0u8; 2]);            // Reserved2

        // Dialects: SMB 2.0.2 (0x0202) and SMB 3.0 (0x0300)
        pkt.extend_from_slice(&0x0202u16.to_le_bytes());
        pkt.extend_from_slice(&0x0300u16.to_le_bytes());

        pkt
    }

    /// Parse SMB2 NEGOTIATE response to extract host info.
    fn parse_negotiate_response(data: &[u8]) -> Result<SmbHostInfo> {
        let mut info = SmbHostInfo::default();

        // Check SMB2 magic
        if data.len() >= 4 && &data[0..4] == SMB2_MAGIC {
            debug!("SMB2: Valid negotiate response received");

            // Dialect is at offset 70-71 in the SMB2 negotiate response
            if data.len() >= 72 {
                let dialect = u16::from_le_bytes([data[70], data[71]]);
                info.smb_dialect = match dialect {
                    0x0202 => "SMB 2.0.2".to_string(),
                    0x0210 => "SMB 2.1".to_string(),
                    0x0300 => "SMB 3.0".to_string(),
                    0x0302 => "SMB 3.0.2".to_string(),
                    0x0311 => "SMB 3.1.1".to_string(),
                    _ => format!("SMB 0x{:04x}", dialect),
                };

                // Security Mode at offset 68-69
                if data.len() >= 70 {
                    let sec_mode = u16::from_le_bytes([data[68], data[69]]);
                    info.smb_signing = sec_mode & 0x01 != 0;
                    info.signing_required = sec_mode & 0x02 != 0;
                }
            }

            // For full NTLM challenge parsing, we'd need to parse the security buffer
            // which contains the NTLMSSP_NEGOTIATE response with OS/domain info.
            // For now, mark as successful connection with basic info.
            info.os = "Windows (version detection pending)".to_string();
        } else if data.len() >= 4 && &data[0..4] == b"\xffSMB" {
            debug!("SMB1: Legacy SMB response (SMB1 fallback)");
            info.smb_dialect = "SMB 1.0".to_string();
            info.os = "Windows (SMB1)".to_string();
        } else {
            warn!("SMB: Unexpected response format");
        }

        Ok(info)
    }
}

impl Default for SmbProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcProtocol for SmbProtocol {
    fn name(&self) -> &'static str {
        "smb"
    }

    fn default_port(&self) -> u16 {
        445
    }

    fn supports_exec(&self) -> bool {
        true
    }

    fn supported_modules(&self) -> &[&str] {
        &["enum_shares", "secretsdump", "sam"]
    }

    async fn connect(&self, target: &str, port: u16) -> Result<Box<dyn NxcSession>> {
        let addr = format!("{}:{}", target, port);
        let target_owned = target.to_string();
        let timeout = self.timeout;

        let session = tokio::task::spawn_blocking(move || -> Result<SmbSession> {
            debug!("SMB: Connecting to {}", addr);

            let mut stream = TcpStream::connect_timeout(
                &addr.parse().map_err(|e| anyhow::anyhow!("Invalid address {}: {}", addr, e))?,
                timeout,
            )?;
            stream.set_read_timeout(Some(timeout))?;
            stream.set_write_timeout(Some(timeout))?;

            // Attempt SMB2 negotiate
            let host_info = match Self::negotiate(&mut stream) {
                Ok(info) => {
                    info!(
                        "SMB: Connected to {} — {} (signing: {}, required: {})",
                        addr, info.smb_dialect, info.smb_signing, info.signing_required
                    );
                    info
                }
                Err(e) => {
                    debug!("SMB: Negotiate failed ({}), using defaults", e);
                    SmbHostInfo::default()
                }
            };

            Ok(SmbSession {
                target: target_owned,
                port,
                admin: false,
                host_info,
                stream: Some(stream),
            })
        })
        .await??;

        Ok(Box::new(session))
    }

    async fn authenticate(
        &self,
        _session: &mut dyn NxcSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        // NTLM authentication requires the full Type1/Type2/Type3 exchange.
        // For now, we return a stub indicating the auth engine needs to be wired.
        // When nxc-auth NTLM is implemented, this will perform real NTLM auth.

        debug!(
            "SMB: Authentication requested for user '{}' (NTLM auth pending implementation)",
            creds.username
        );

        // Stub: simulate auth behavior for development/testing
        if !creds.username.is_empty() {
            // Return a "not implemented" style failure that tells the user
            // the protocol connected but auth isn't wired yet
            Ok(AuthResult::failure(
                "NTLM auth engine pending — connection established",
                Some("STUB"),
            ))
        } else {
            // Null session
            Ok(AuthResult::success(false))
        }
    }

    async fn execute(&self, _session: &dyn NxcSession, cmd: &str) -> Result<CommandOutput> {
        // SMB command execution requires smbexec/wmiexec/atexec methods.
        // Stub for now.
        debug!("SMB: Execute requested: {}", cmd);
        Err(anyhow::anyhow!(
            "SMB remote execution not yet implemented (requires smbexec/wmiexec)"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smb_protocol_defaults() {
        let proto = SmbProtocol::new();
        assert_eq!(proto.name(), "smb");
        assert_eq!(proto.default_port(), 445);
        assert!(proto.supports_exec());
    }

    #[test]
    fn test_smb_negotiate_request_format() {
        let req = SmbProtocol::build_smb2_negotiate_request();
        // Should start with SMB2 magic
        assert_eq!(&req[0..4], SMB2_MAGIC);
        // Should be at least 64 (header) + negotiate body
        assert!(req.len() >= 64);
    }

    #[test]
    fn test_smb_host_info_default() {
        let info = SmbHostInfo::default();
        assert_eq!(info.hostname, "");
        assert!(!info.smb_signing);
        assert!(!info.is_dc);
    }

    #[test]
    fn test_supported_modules() {
        let proto = SmbProtocol::new();
        let modules = proto.supported_modules();
        assert!(modules.contains(&"enum_shares"));
    }
}
