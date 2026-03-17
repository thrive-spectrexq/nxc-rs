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
use crate::rpc::{DcerpcHeader, PacketType};
use std::sync::Mutex;
use tracing::debug;

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

// ─── SMB2 Header ──────────────────────────────────────────────

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Smb2Header {
    pub protocol_id: [u8; 4],
    pub structure_size: u16,
    pub credit_charge: u16,
    pub status: u32,
    pub command: u16,
    pub credits_requested: u16,
    pub flags: u32,
    pub next_command: u32,
    pub message_id: u64,
    pub reserved: u32,
    pub tree_id: u32,
    pub session_id: u64,
    pub signature: [u8; 16],
}

impl Smb2Header {
    pub fn new(command: u16) -> Self {
        Self {
            protocol_id: SMB2_MAGIC.try_into().unwrap(),
            structure_size: 64,
            credit_charge: 0,
            status: 0,
            command,
            credits_requested: 0,
            flags: 0,
            next_command: 0,
            message_id: 0,
            reserved: 0,
            tree_id: 0,
            session_id: 0,
            signature: [0u8; 16],
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&self.protocol_id);
        buf.extend_from_slice(&self.structure_size.to_le_bytes());
        buf.extend_from_slice(&self.credit_charge.to_le_bytes());
        buf.extend_from_slice(&self.status.to_le_bytes());
        buf.extend_from_slice(&self.command.to_le_bytes());
        buf.extend_from_slice(&self.credits_requested.to_le_bytes());
        buf.extend_from_slice(&self.flags.to_le_bytes());
        buf.extend_from_slice(&self.next_command.to_le_bytes());
        buf.extend_from_slice(&self.message_id.to_le_bytes());
        buf.extend_from_slice(&self.reserved.to_le_bytes());
        buf.extend_from_slice(&self.tree_id.to_le_bytes());
        buf.extend_from_slice(&self.session_id.to_le_bytes());
        buf.extend_from_slice(&self.signature);
        buf
    }
}

// ─── SMB Session ────────────────────────────────────────────────

pub struct SmbSession {
    pub target: String,
    pub port: u16,
    pub admin: bool,
    pub host_info: SmbHostInfo,
    pub session_id: u64,
    pub stream: Mutex<Option<TcpStream>>,
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

    /// List shares on the target host.
    pub async fn list_shares(&self, session: &SmbSession) -> Result<Vec<ShareInfo>> {
        debug!("SMB: Enumerating shares on {}", session.target);
        
        let mut shares = Vec::new();
        let common_shares = ["IPC$", "ADMIN$", "C$", "SYSVOL", "NETLOGON"];
        
        for share in &common_shares {
            match self.tree_connect(session, share).await {
                Ok(_) => {
                    shares.push(ShareInfo {
                        name: share.to_string(),
                        share_type: "DISK".to_string(),
                        remark: "".to_string(),
                        read_access: true,
                        write_access: share.ends_with('$') && share != &"IPC$",
                    });
                }
                Err(_) => debug!("SMB: Could not connect to share {}", share),
            }
        }
        
        Ok(shares)
    }

    /// Perform a DCE/RPC call over an SMB Named Pipe.
    pub async fn call_rpc(&self, session: &SmbSession, pipe: &str, ptype: PacketType, call_id: u32, data: Vec<u8>) -> Result<Vec<u8>> {
        debug!("SMB: RPC Call on {} ptype={:?}", pipe, ptype);
        
        // 1. Ensure connected to IPC$
        self.tree_connect(session, "IPC$").await?;

        // 2. Open the Named Pipe (SMB2 CREATE)
        let _fid = self.open_pipe(session, pipe).await?;

        // 3. Write DCE/RPC Packet (SMB2 WRITE)
        let header = DcerpcHeader::new(ptype, call_id, (data.len() + 16) as u16);
        let mut pkt = header.to_bytes();
        pkt.extend_from_slice(&data);

        self.write_pipe(session, _fid, pkt).await?;

        // 4. Read Response (SMB2 READ)
        let resp = self.read_pipe(session, _fid).await?;
        
        Ok(resp)
    }

    async fn open_pipe(&self, _session: &SmbSession, pipe: &str) -> Result<u32> {
        debug!("SMB: Opening named pipe {}", pipe);
        Ok(0x42) // Stub FileID
    }

    async fn write_pipe(&self, _session: &SmbSession, _fid: u32, data: Vec<u8>) -> Result<()> {
        debug!("SMB: Writing {} bytes to pipe", data.len());
        Ok(())
    }

    async fn read_pipe(&self, _session: &SmbSession, _fid: u32) -> Result<Vec<u8>> {
        debug!("SMB: Reading from pipe");
        // Mock Response: BindAck or RPC Response
        Ok(vec![0x05, 0x00, 0x0c, 0x03, 0x10, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00])
    }

    /// Perform an SMB2 TREE_CONNECT.
    async fn tree_connect(&self, session: &SmbSession, share: &str) -> Result<u32> {
        let path = format!("\\\\{}\\{}", session.target, share);
        let _packet = Self::build_smb2_tree_connect_request(&path);
        
        let mut stream_lock = session.stream.lock().map_err(|_| anyhow::anyhow!("Failed to lock stream"))?;
        if let Some(ref mut _stream) = *stream_lock {
            // Real network I/O logic would go here
            debug!("SMB: Stub TreeConnect to {}", path);
            Ok(0x1) 
        } else {
            Err(anyhow::anyhow!("No active stream"))
        }
    }

    /// Attempt a basic SMB2 negotiate to extract host info.
    fn negotiate(stream: &mut TcpStream) -> Result<SmbHostInfo> {
        let negotiate_req = Self::build_smb2_negotiate_request();
        let mut packet = Vec::new();
        packet.push(NETBIOS_SESSION_MSG);
        let len = negotiate_req.len() as u32;
        packet.push(((len >> 16) & 0xff) as u8);
        packet.push(((len >> 8) & 0xff) as u8);
        packet.push((len & 0xff) as u8);
        packet.extend_from_slice(&negotiate_req);

        stream.write_all(&packet)?;
        stream.flush()?;

        let mut header = [0u8; 4];
        stream.read_exact(&mut header)?;
        let response_len = ((header[1] as usize) << 16) | ((header[2] as usize) << 8) | (header[3] as usize);
        let mut response = vec![0u8; response_len];
        stream.read_exact(&mut response)?;

        Self::parse_negotiate_response(&response)
    }

    fn build_smb2_negotiate_request() -> Vec<u8> {
        let header = Smb2Header::new(0x0000); // NEGOTIATE
        let mut pkt = header.to_bytes();
        pkt.extend_from_slice(&36u16.to_le_bytes()); // Structure Size
        pkt.extend_from_slice(&2u16.to_le_bytes());  // Dialect Count
        pkt.extend_from_slice(&[1u8, 0]);            // Security Mode
        pkt.extend_from_slice(&[0u8; 2]);            // Reserved
        pkt.extend_from_slice(&[0u8; 4]);            // Capabilities
        pkt.extend_from_slice(&[0u8; 16]);           // Client GUID
        pkt.extend_from_slice(&[0u8; 4]);            // NegotiateContextOffset
        pkt.extend_from_slice(&[0u8; 2]);            // NegotiateContextCount
        pkt.extend_from_slice(&[0u8; 2]);            // Reserved2
        pkt.extend_from_slice(&0x0202u16.to_le_bytes());
        pkt.extend_from_slice(&0x0300u16.to_le_bytes());
        pkt
    }

    fn build_smb2_tree_connect_request(path: &str) -> Vec<u8> {
        let header = Smb2Header::new(0x0003); // TREE_CONNECT
        let mut pkt = header.to_bytes();
        let path_utf16: Vec<u16> = path.encode_utf16().collect();
        let path_bytes: Vec<u8> = path_utf16.iter().flat_map(|&u| u.to_le_bytes()).collect();

        pkt.extend_from_slice(&9u16.to_le_bytes());   // Structure Size
        pkt.extend_from_slice(&[0u8; 2]);             // Reserved
        pkt.extend_from_slice(&72u16.to_le_bytes());  // Path Offset
        pkt.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes()); // Path Length
        pkt.extend_from_slice(&path_bytes);
        pkt
    }

    fn parse_negotiate_response(data: &[u8]) -> Result<SmbHostInfo> {
        let mut info = SmbHostInfo::default();
        if data.len() >= 4 && &data[0..4] == SMB2_MAGIC {
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
                info.smb_signing = data[68] & 0x01 != 0;
                info.signing_required = data[68] & 0x02 != 0;
            }
            info.os = "Windows (version detection pending)".to_string();
        }
        Ok(info)
    }
}

impl Default for SmbProtocol {
    fn default() -> Self { Self::new() }
}

#[async_trait]
impl NxcProtocol for SmbProtocol {
    fn name(&self) -> &'static str { "smb" }
    fn default_port(&self) -> u16 { 445 }
    fn supports_exec(&self) -> bool { true }
    fn supported_modules(&self) -> &[&str] {
        &["enum_shares", "secretsdump", "sam"]
    }

    async fn connect(&self, target: &str, port: u16) -> Result<Box<dyn NxcSession>> {
        let addr = format!("{}:{}", target, port);
        let target_owned = target.to_string();
        let timeout = self.timeout;

        let session = tokio::task::spawn_blocking(move || -> Result<SmbSession> {
            let mut stream = TcpStream::connect_timeout(
                &addr.parse().map_err(|e| anyhow::anyhow!("Invalid address {}: {}", addr, e))?,
                timeout,
            )?;
            stream.set_read_timeout(Some(timeout))?;
            stream.set_write_timeout(Some(timeout))?;

            let host_info = Self::negotiate(&mut stream).unwrap_or_default();
            Ok(SmbSession {
                target: target_owned,
                port,
                admin: false,
                host_info,
                session_id: 0,
                stream: Mutex::new(Some(stream)),
            })
        }).await??;

        Ok(Box::new(session))
    }

    async fn authenticate(&self, _session: &mut dyn NxcSession, creds: &Credentials) -> Result<AuthResult> {
        if !creds.username.is_empty() {
            Ok(AuthResult::failure("NTLM auth engine pending", Some("STUB")))
        } else {
            Ok(AuthResult::success(false))
        }
    }

    async fn execute(&self, _session: &dyn NxcSession, _cmd: &str) -> Result<CommandOutput> {
        Err(anyhow::anyhow!("SMB remote execution not yet implemented"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_smb_protocol_defaults() {
        let proto = SmbProtocol::new();
        assert_eq!(proto.name(), "smb");
    }
}
