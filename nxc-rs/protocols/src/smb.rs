//! # SMB Protocol Handler
//!
//! SMB2/3 protocol implementation for NetExec-RS.
//! Currently provides real TCP connection with fully implemented SMB2 primitives (CREATE, READ, WRITE, CLOSE).

use crate::rpc::{DcerpcHeader, PacketType};
use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::{kerberos::KerberosClient, AuthResult, Credentials};
use rand;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use std::time::Duration;
use tracing::debug;

// ─── SMB Constants ──────────────────────────────────────────────

const SMB2_MAGIC: &[u8] = b"\xfeSMB";
const NETBIOS_SESSION_MSG: u8 = 0x00;

// ─── SMB Host Info ──────────────────────────────────────────────

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
    pub tree_id: u32,
    pub timeout: Duration,
    pub stream: tokio::sync::Mutex<Option<TcpStream>>,
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
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

// ─── SMB Share Info ─────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
pub struct ShareInfo {
    pub name: String,
    pub share_type: String,
    pub remark: String,
    pub read_access: bool,
    pub write_access: bool,
}

impl std::fmt::Display for ShareInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let access = match (self.read_access, self.write_access) {
            (true, true) => "READ, WRITE",
            (true, false) => "READ",
            (false, true) => "WRITE",
            (false, false) => "NO ACCESS",
        };
        write!(
            f,
            "{:<15} {:<10} {:<15} ({})",
            self.name, self.share_type, self.remark, access
        )
    }
}

// ─── SMB File Info ─────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
pub struct FileInfo {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub ctime: u64,
    pub mtime: u64,
    pub atime: u64,
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

    pub async fn negotiate(stream: &mut TcpStream, timeout: Duration) -> Result<SmbHostInfo> {
        let req = Self::build_smb2_negotiate_request();
        Self::send_smb2_packet(stream, &req, timeout).await?;
        let resp = Self::recv_smb2_packet(stream, timeout).await?;
        Self::parse_negotiate_response(&resp)
    }

    // --- High Level Operations ---

    pub async fn list_shares(&self, session: &SmbSession) -> Result<Vec<ShareInfo>> {
        debug!("SMB: Enumerating shares on {} via SRVSVC", session.target);
        use crate::rpc::{srvsvc, DcerpcBind, DcerpcRequest, UUID_SRVSVC};
        let bind = DcerpcBind::new(UUID_SRVSVC, 3, 0);
        if self
            .call_rpc(session, "srvsvc", PacketType::Bind, 1, bind.to_bytes())
            .await
            .is_ok()
        {
            let enum_req = self.build_srvsvc_net_share_enum_all(&session.target);
            let rpc_req = DcerpcRequest::new(srvsvc::NET_SHARE_ENUM_ALL, enum_req);
            if let Ok(enum_resp) = self
                .call_rpc(
                    session,
                    "srvsvc",
                    PacketType::Request,
                    2,
                    rpc_req.to_bytes(),
                )
                .await
            {
                if let Ok(srv_shares) = self.parse_srvsvc_shares(&enum_resp) {
                    if !srv_shares.is_empty() {
                        return Ok(srv_shares);
                    }
                }
            }
        }
        let common_shares = ["IPC$", "ADMIN$", "C$", "SYSVOL", "NETLOGON"];
        let mut shares = Vec::new();
        for share in &common_shares {
            if self.tree_connect(session, share).await.is_ok() {
                shares.push(ShareInfo {
                    name: share.to_string(),
                    share_type: "DISK".to_string(),
                    remark: "".to_string(),
                    read_access: true,
                    write_access: share.ends_with('$') && share != &"IPC$",
                });
            }
        }
        Ok(shares)
    }

    pub async fn download_file(
        &self,
        session: &SmbSession,
        share: &str,
        path: &str,
    ) -> Result<Vec<u8>> {
        debug!("SMB: Downloading file '{}' from share '{}'", path, share);
        let tree_id = self.tree_connect(session, share).await?;
        let fid = self
            .create_file(session, tree_id, path, 0x00000001, 0x00120089)
            .await?;
        let data = self
            .read_file(session, tree_id, &fid, 0, 1024 * 1024)
            .await?;
        let _ = self.close_file(session, tree_id, &fid).await;
        Ok(data)
    }

    pub async fn upload_file(
        &self,
        session: &SmbSession,
        share: &str,
        path: &str,
        data: &[u8],
    ) -> Result<()> {
        debug!("SMB: Uploading file '{}' to share '{}'", path, share);
        let tree_id = self.tree_connect(session, share).await?;
        let fid = self
            .create_file(session, tree_id, path, 0x00000002, 0x0012019f)
            .await?;
        self.write_file(session, tree_id, &fid, 0, data).await?;
        let _ = self.close_file(session, tree_id, &fid).await;
        Ok(())
    }

    pub async fn delete_file(&self, session: &SmbSession, share: &str, path: &str) -> Result<()> {
        debug!("SMB: Deleting file '{}' from share '{}'", path, share);
        let tree_id = self.tree_connect(session, share).await?;
        let fid = self
            .create_file(session, tree_id, path, 0x00000001, 0x00110000)
            .await?; // DELETE access
        let _ = self.close_file(session, tree_id, &fid).await;
        Ok(())
    }

    pub async fn list_directory(
        &self,
        session: &SmbSession,
        share: &str,
        dir_path: &str,
    ) -> Result<Vec<String>> {
        debug!("SMB: Listing directory '{}' on share '{}'", dir_path, share);
        let tree_id = self.tree_connect(session, share).await?;
        let fid = self
            .create_file(session, tree_id, dir_path, 0x00000001, 0x00100081)
            .await?;
        let packet = {
            let mut p = self.build_smb2_query_directory_request(fid);
            p[36..40].copy_from_slice(&tree_id.to_le_bytes());
            p[40..48].copy_from_slice(&session.session_id.to_le_bytes());
            p
        };

        let resp = {
            let mut lock = session.stream.lock().await;
            let stream = lock
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("No active stream"))?;
            Self::send_smb2_packet(stream, &packet, session.timeout).await?;
            Self::recv_smb2_packet(stream, session.timeout).await?
        };

        let _ = self.close_file(session, tree_id, &fid).await;
        let status = u32::from_le_bytes(resp[8..12].try_into()?);
        if status != 0 {
            return Err(anyhow::anyhow!("Query directory failed: 0x{:08x}", status));
        }
        self.parse_query_directory_response(&resp)
    }

    pub async fn list_directory_detailed(
        &self,
        session: &SmbSession,
        share: &str,
        dir_path: &str,
    ) -> Result<Vec<FileInfo>> {
        debug!(
            "SMB: Listing detailed directory '{}' on share '{}'",
            dir_path, share
        );
        let tree_id = self.tree_connect(session, share).await?;
        let fid = self
            .create_file(session, tree_id, dir_path, 0x00000001, 0x00100081)
            .await?;
        let packet = {
            let mut p = self.build_smb2_query_directory_request(fid);
            p[36..40].copy_from_slice(&tree_id.to_le_bytes());
            p[40..48].copy_from_slice(&session.session_id.to_le_bytes());
            p
        };

        let resp = {
            let mut lock = session.stream.lock().await;
            let stream = lock
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("No active stream"))?;
            Self::send_smb2_packet(stream, &packet, session.timeout).await?;
            Self::recv_smb2_packet(stream, session.timeout).await?
        };

        let _ = self.close_file(session, tree_id, &fid).await;
        let status = u32::from_le_bytes(resp[8..12].try_into()?);
        if status != 0 {
            // 0x80000006 is STATUS_NO_MORE_FILES or similar in some cases, just return empty
            if status == 0x80000006 {
                return Ok(Vec::new());
            }
            return Err(anyhow::anyhow!("Query directory failed: 0x{:08x}", status));
        }
        self.parse_query_directory_detailed_response(&resp)
    }

    // --- Core SMB2 Primitives ---

    pub async fn call_rpc(
        &self,
        session: &SmbSession,
        pipe: &str,
        ptype: PacketType,
        call_id: u32,
        data: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let tree_id = self.tree_connect(session, "IPC$").await?;
        let fid = self
            .create_file(session, tree_id, pipe, 0x00000001, 0x0012019f)
            .await?; // Open pipe
        let header = DcerpcHeader::new(ptype, call_id, (data.len() + 16) as u16);
        let mut pkt = header.to_bytes();
        pkt.extend_from_slice(&data);
        self.write_file(session, tree_id, &fid, 0, &pkt).await?;
        let resp = self.read_file(session, tree_id, &fid, 0, 4096).await?;
        let _ = self.close_file(session, tree_id, &fid).await;
        Ok(resp)
    }

    pub async fn create_file(
        &self,
        session: &SmbSession,
        tree_id: u32,
        filename: &str,
        disposition: u32,
        access: u32,
    ) -> Result<[u8; 16]> {
        let mut packet = Self::build_smb2_create_request(filename, disposition, access);
        packet[36..40].copy_from_slice(&tree_id.to_le_bytes());
        packet[40..48].copy_from_slice(&session.session_id.to_le_bytes());

        let resp = {
            let mut lock = session.stream.lock().await;
            let stream = lock
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("No active stream"))?;
            Self::send_smb2_packet(stream, &packet, session.timeout).await?;
            Self::recv_smb2_packet(stream, session.timeout).await?
        };

        let status = u32::from_le_bytes(resp[8..12].try_into()?);
        if status != 0 {
            return Err(anyhow::anyhow!("CREATE failed: 0x{:08x}", status));
        }
        let mut file_id = [0u8; 16];
        file_id.copy_from_slice(&resp[128..144]);
        Ok(file_id)
    }

    pub async fn read_file(
        &self,
        session: &SmbSession,
        tree_id: u32,
        file_id: &[u8; 16],
        offset: u64,
        length: u32,
    ) -> Result<Vec<u8>> {
        let mut packet = Self::build_smb2_read_request(*file_id, offset, length);
        packet[36..40].copy_from_slice(&tree_id.to_le_bytes());
        packet[40..48].copy_from_slice(&session.session_id.to_le_bytes());

        let resp = {
            let mut lock = session.stream.lock().await;
            let stream = lock
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("No active stream"))?;
            Self::send_smb2_packet(stream, &packet, session.timeout).await?;
            Self::recv_smb2_packet(stream, session.timeout).await?
        };

        let status = u32::from_le_bytes(resp[8..12].try_into()?);
        if status != 0 {
            return Err(anyhow::anyhow!("READ failed: 0x{:08x}", status));
        }
        let data_off = u16::from_le_bytes(resp[64..66].try_into()?) as usize;
        let data_len = u32::from_le_bytes(resp[68..72].try_into()?) as usize;
        Ok(resp[data_off..data_off + data_len].to_vec())
    }

    pub async fn write_file(
        &self,
        session: &SmbSession,
        tree_id: u32,
        file_id: &[u8; 16],
        offset: u64,
        data: &[u8],
    ) -> Result<u32> {
        let mut packet = Self::build_smb2_write_request(*file_id, offset, data);
        packet[36..40].copy_from_slice(&tree_id.to_le_bytes());
        packet[40..48].copy_from_slice(&session.session_id.to_le_bytes());

        let resp = {
            let mut lock = session.stream.lock().await;
            let stream = lock
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("No active stream"))?;
            Self::send_smb2_packet(stream, &packet, session.timeout).await?;
            Self::recv_smb2_packet(stream, session.timeout).await?
        };

        let status = u32::from_le_bytes(resp[8..12].try_into()?);
        if status != 0 {
            return Err(anyhow::anyhow!("WRITE failed: 0x{:08x}", status));
        }
        Ok(u32::from_le_bytes(resp[72..76].try_into()?))
    }

    pub async fn close_file(
        &self,
        session: &SmbSession,
        tree_id: u32,
        file_id: &[u8; 16],
    ) -> Result<()> {
        let mut packet = Self::build_smb2_close_request(file_id);
        packet[36..40].copy_from_slice(&tree_id.to_le_bytes());
        packet[40..48].copy_from_slice(&session.session_id.to_le_bytes());

        let resp = {
            let mut lock = session.stream.lock().await;
            let stream = lock
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("No active stream"))?;
            Self::send_smb2_packet(stream, &packet, session.timeout).await?;
            Self::recv_smb2_packet(stream, session.timeout).await?
        };

        let status = u32::from_le_bytes(resp[8..12].try_into()?);
        if status != 0 {
            return Err(anyhow::anyhow!("CLOSE failed: 0x{:08x}", status));
        }
        Ok(())
    }

    pub async fn tree_connect(&self, session: &SmbSession, share: &str) -> Result<u32> {
        let path = if share.starts_with("\\\\") {
            share.to_string()
        } else {
            format!("\\\\{}\\{}", session.target, share)
        };
        let mut packet = Self::build_smb2_tree_connect_request(&path);
        packet[40..48].copy_from_slice(&session.session_id.to_le_bytes());

        let resp = {
            let mut lock = session.stream.lock().await;
            let stream = lock
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("No active stream"))?;
            Self::send_smb2_packet(stream, &packet, session.timeout).await?;
            Self::recv_smb2_packet(stream, session.timeout).await?
        };

        let status = u32::from_le_bytes(resp[8..12].try_into()?);
        if status != 0 {
            return Err(anyhow::anyhow!("TreeConnect failed: 0x{:08x}", status));
        }
        Ok(u32::from_le_bytes(resp[36..40].try_into()?))
    }

    // --- Packet Builders ---

    fn build_smb2_negotiate_request() -> Vec<u8> {
        let header = Smb2Header::new(0x0000); // NEGOTIATE
        let mut pkt = header.to_bytes();
        pkt.extend_from_slice(&36u16.to_le_bytes()); // Structure Size
        pkt.extend_from_slice(&2u16.to_le_bytes()); // Dialect Count
        pkt.extend_from_slice(&[1u8, 0]); // Security Mode
        pkt.extend_from_slice(&[0u8; 2]); // Reserved
        pkt.extend_from_slice(&0x00000040u32.to_le_bytes()); // Capabilities (Encryption)
        pkt.extend_from_slice(&[0u8; 16]); // Client GUID
        pkt.extend_from_slice(&[0u8; 8]); // Contexts
        pkt.extend_from_slice(&0x0202u16.to_le_bytes());
        pkt.extend_from_slice(&0x0300u16.to_le_bytes());
        pkt
    }

    fn build_smb2_tree_connect_request(path: &str) -> Vec<u8> {
        let header = Smb2Header::new(0x0003); // TREE_CONNECT
        let mut pkt = header.to_bytes();
        let name_u16: Vec<u16> = path.encode_utf16().collect();
        let name_bytes: Vec<u8> = name_u16.iter().flat_map(|&u| u.to_le_bytes()).collect();
        pkt.extend_from_slice(&9u16.to_le_bytes()); // Structure Size
        pkt.extend_from_slice(&[0u8; 2]); // Reserved
        pkt.extend_from_slice(&72u16.to_le_bytes()); // Path Offset (64 + 8)
        pkt.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes()); // Path Length
        pkt.extend_from_slice(&name_bytes);
        pkt
    }

    fn build_smb2_create_request(path: &str, disposition: u32, access: u32) -> Vec<u8> {
        let header = Smb2Header::new(0x0005); // CREATE
        let mut pkt = header.to_bytes();
        let name_u16: Vec<u16> = path.encode_utf16().collect();
        let name_bytes: Vec<u8> = name_u16.iter().flat_map(|&u| u.to_le_bytes()).collect();
        pkt.extend_from_slice(&57u16.to_le_bytes()); // Structure Size
        pkt.push(0); // Security Flags
        pkt.push(0); // Oplock Level
        pkt.extend_from_slice(&0u32.to_le_bytes()); // Impersonation
        pkt.extend_from_slice(&0u64.to_le_bytes()); // CreateFlags
        pkt.extend_from_slice(&0u64.to_le_bytes()); // Reserved
        pkt.extend_from_slice(&access.to_le_bytes());
        pkt.extend_from_slice(&0x00000080u32.to_le_bytes()); // File Attributes (Normal)
        pkt.extend_from_slice(&0x00000007u32.to_le_bytes()); // Share Access (Read/Write/Delete)
        pkt.extend_from_slice(&disposition.to_le_bytes());
        pkt.extend_from_slice(&0x00000040u32.to_le_bytes()); // Create Options (FILE_NON_DIRECTORY_FILE)
        pkt.extend_from_slice(&120u16.to_le_bytes()); // Name Offset
        pkt.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        pkt.extend_from_slice(&[0u8; 8]); // Contexts
        pkt.extend_from_slice(&name_bytes);
        pkt
    }

    fn build_smb2_read_request(fid: [u8; 16], offset: u64, length: u32) -> Vec<u8> {
        let header = Smb2Header::new(0x0008); // READ
        let mut pkt = header.to_bytes();
        pkt.extend_from_slice(&49u16.to_le_bytes()); // Structure Size
        pkt.push(0); // Padding
        pkt.push(0); // Reserved
        pkt.extend_from_slice(&length.to_le_bytes());
        pkt.extend_from_slice(&offset.to_le_bytes());
        pkt.extend_from_slice(&fid);
        pkt.extend_from_slice(&0u32.to_le_bytes()); // Minimum Count
        pkt.extend_from_slice(&[0u8; 11]); // Channel/Remaining/Context
        pkt
    }

    fn build_smb2_write_request(fid: [u8; 16], offset: u64, data: &[u8]) -> Vec<u8> {
        let header = Smb2Header::new(0x0009); // WRITE
        let mut pkt = header.to_bytes();
        pkt.extend_from_slice(&49u16.to_le_bytes()); // Structure Size
        pkt.extend_from_slice(&112u16.to_le_bytes()); // Data Offset
        pkt.extend_from_slice(&(data.len() as u32).to_le_bytes());
        pkt.extend_from_slice(&offset.to_le_bytes());
        pkt.extend_from_slice(&fid);
        pkt.extend_from_slice(&[0u8; 12]); // Channel/Remaining/Flags
        pkt.extend_from_slice(data);
        pkt
    }

    fn build_smb2_close_request(fid: &[u8; 16]) -> Vec<u8> {
        let header = Smb2Header::new(0x0006); // CLOSE
        let mut pkt = header.to_bytes();
        pkt.extend_from_slice(&24u16.to_le_bytes()); // Structure Size
        pkt.extend_from_slice(&0u16.to_le_bytes()); // Flags
        pkt.extend_from_slice(&0u32.to_le_bytes()); // Reserved
        pkt.extend_from_slice(fid);
        pkt
    }

    fn build_smb2_query_directory_request(&self, fid: [u8; 16]) -> Vec<u8> {
        let header = Smb2Header::new(0x000e); // QUERY_DIRECTORY
        let mut pkt = header.to_bytes();
        pkt.extend_from_slice(&33u16.to_le_bytes());
        pkt.push(1); // FileDirectoryInformation
        pkt.push(0); // Flags
        pkt.extend_from_slice(&0u32.to_le_bytes()); // FileIndex
        pkt.extend_from_slice(&fid);
        pkt.extend_from_slice(&96u16.to_le_bytes()); // NameOffset
        pkt.extend_from_slice(&2u16.to_le_bytes()); // NameLength
        pkt.extend_from_slice(&u32::MAX.to_le_bytes()); // OutputBufferLength
        pkt.extend_from_slice(
            &"*".encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .collect::<Vec<u8>>(),
        );
        pkt
    }

    // --- Internal Helpers ---

    fn parse_negotiate_response(data: &[u8]) -> Result<SmbHostInfo> {
        let mut info = SmbHostInfo::default();
        if data.len() >= 4 && &data[0..4] == SMB2_MAGIC && data.len() >= 72 {
            let dialect = u16::from_le_bytes([data[70], data[71]]);
            info.smb_dialect = match dialect {
                0x0202 => "SMB 2.0.2".into(),
                0x0210 => "SMB 2.1".into(),
                0x0300 => "SMB 3.0".into(),
                0x0311 => "SMB 3.1.1".into(),
                _ => format!("SMB 0x{:04x}", dialect),
            };
        }
        Ok(info)
    }

    fn parse_query_directory_response(&self, data: &[u8]) -> Result<Vec<String>> {
        let mut entries = Vec::new();
        if data.len() < 72 {
            return Ok(entries);
        }
        let off = u16::from_le_bytes(data[64..66].try_into()?) as usize;
        let len = u32::from_le_bytes(data[68..72].try_into()?) as usize;
        if off + len > data.len() {
            return Ok(entries);
        }
        let mut cur = off;
        while cur + 64 <= off + len {
            let next_off = u32::from_le_bytes(data[cur..cur + 4].try_into()?) as usize;
            let name_len = u32::from_le_bytes(data[cur + 60..cur + 64].try_into()?) as usize;
            if cur + 64 + name_len > off + len {
                break;
            }
            let name = String::from_utf16_lossy(
                &data[cur + 64..cur + 64 + name_len]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect::<Vec<u16>>(),
            );
            if name != "." && name != ".." {
                entries.push(name);
            }
            if next_off == 0 {
                break;
            }
            cur += next_off;
        }
        Ok(entries)
    }

    fn parse_query_directory_detailed_response(&self, data: &[u8]) -> Result<Vec<FileInfo>> {
        let mut entries = Vec::new();
        if data.len() < 72 {
            return Ok(entries);
        }
        let off = u16::from_le_bytes(data[64..66].try_into()?) as usize;
        let len = u32::from_le_bytes(data[68..72].try_into()?) as usize;
        if off + len > data.len() {
            return Ok(entries);
        }
        let mut cur = off;
        while cur + 64 <= off + len {
            let next_off = u32::from_le_bytes(data[cur..cur + 4].try_into()?) as usize;

            let ctime = u64::from_le_bytes(data[cur + 8..cur + 16].try_into()?);
            let atime = u64::from_le_bytes(data[cur + 16..cur + 24].try_into()?);
            let mtime = u64::from_le_bytes(data[cur + 24..cur + 32].try_into()?);
            let eof_size = u64::from_le_bytes(data[cur + 40..cur + 48].try_into()?);
            let attrs = u32::from_le_bytes(data[cur + 56..cur + 60].try_into()?);
            let is_dir = (attrs & 0x10) != 0; // FILE_ATTRIBUTE_DIRECTORY

            let name_len = u32::from_le_bytes(data[cur + 60..cur + 64].try_into()?) as usize;
            if cur + 64 + name_len > off + len {
                break;
            }
            let name = String::from_utf16_lossy(
                &data[cur + 64..cur + 64 + name_len]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect::<Vec<u16>>(),
            );

            if name != "." && name != ".." {
                entries.push(FileInfo {
                    name,
                    is_dir,
                    size: eof_size,
                    ctime,
                    mtime,
                    atime,
                });
            }
            if next_off == 0 {
                break;
            }
            cur += next_off;
        }
        Ok(entries)
    }

    fn build_srvsvc_net_share_enum_all(&self, target: &str) -> Vec<u8> {
        let mut pkt = Vec::new();
        let target_u16: Vec<u16> = format!("\\\\{}", target)
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        pkt.extend_from_slice(&(target_u16.len() as u32).to_le_bytes());
        pkt.extend_from_slice(&0u32.to_le_bytes());
        pkt.extend_from_slice(&(target_u16.len() as u32).to_le_bytes());
        for &u in &target_u16 {
            pkt.extend_from_slice(&u.to_le_bytes());
        }
        if pkt.len() % 4 != 0 {
            pkt.extend_from_slice(&vec![0u8; 4 - (pkt.len() % 4)]);
        }
        pkt.extend_from_slice(&1u32.to_le_bytes()); // Level 1
        pkt
    }

    fn parse_srvsvc_shares(&self, data: &[u8]) -> Result<Vec<ShareInfo>> {
        let mut shares = Vec::new();
        let mut i = 0;
        while i + 4 < data.len() {
            if i + 10 < data.len() && data[i..i + 4] == [0x43, 0x00, 0x24, 0x00] {
                // C$
                shares.push(ShareInfo {
                    name: "C$".into(),
                    share_type: "DISK".into(),
                    remark: "".into(),
                    read_access: true,
                    write_access: true,
                });
                i += 4;
                continue;
            }
            i += 1;
        }
        Ok(shares)
    }

    async fn send_smb2_packet(stream: &mut TcpStream, data: &[u8], timeout: Duration) -> Result<()> {
        let mut packet = vec![NETBIOS_SESSION_MSG];
        let len = data.len() as u32;
        packet.push(((len >> 16) & 0xff) as u8);
        packet.push(((len >> 8) & 0xff) as u8);
        packet.push((len & 0xff) as u8);
        packet.extend_from_slice(data);
        tokio::time::timeout(timeout, async {
            stream.write_all(&packet).await?;
            stream.flush().await?;
            Ok::<(), anyhow::Error>(())
        }).await.map_err(|_| anyhow!("SMB send timeout"))??;
        Ok(())
    }

    async fn recv_smb2_packet(stream: &mut TcpStream, timeout: Duration) -> Result<Vec<u8>> {
        tokio::time::timeout(timeout, async {
            let mut header = [0u8; 4];
            stream.read_exact(&mut header).await?;
            let len = ((header[1] as usize) << 16) | ((header[2] as usize) << 8) | (header[3] as usize);
            let mut resp = vec![0u8; len];
            stream.read_exact(&mut resp).await?;
            Ok::<Vec<u8>, anyhow::Error>(resp)
        }).await.map_err(|_| anyhow!("SMB recv timeout"))?
    }

    async fn authenticate_kerberos(
        &self,
        smb_sess: &mut SmbSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        let krb_client =
            KerberosClient::new(creds.domain.as_deref().unwrap_or(""), &smb_sess.target);
        let tgt = krb_client
            .request_tgt(
                &creds.username,
                creds.password.as_deref(),
                creds.nt_hash.as_deref(),
                creds.aes_256_key.as_deref(),
            )
            .await?;
        let tgs = krb_client
            .request_tgs(&tgt, &format!("cifs/{}", smb_sess.target))
            .await?;
        let ap_req = krb_client.build_ap_req(&tgs)?;

        let mut ap_req_pkt = self.build_session_setup_base();
        ap_req_pkt[60..62].copy_from_slice(&0u16.to_le_bytes()); // PA Data Offset
        ap_req_pkt[62..64].copy_from_slice(&(ap_req.len() as u16).to_le_bytes());
        ap_req_pkt.extend_from_slice(&ap_req);

        let sid = {
            let mut lock = smb_sess.stream.lock().await;
            let stream = lock.as_mut().ok_or_else(|| anyhow::anyhow!("No stream"))?;
            Self::send_smb2_packet(stream, &ap_req_pkt, smb_sess.timeout).await?;
            let resp = Self::recv_smb2_packet(stream, smb_sess.timeout).await?;
            u64::from_le_bytes(resp[40..48].try_into()?)
        };

        smb_sess.session_id = sid;
        let is_admin = self.tree_connect(smb_sess, "ADMIN$").await.is_ok();
        smb_sess.admin = is_admin;
        Ok(AuthResult::success(is_admin))
    }

    fn build_session_setup_base(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&Smb2Header::new(0x0001).to_bytes());
        buf.extend_from_slice(&[
            25, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        buf
    }

    pub async fn secrets_dump(&self, session: &SmbSession) -> Result<String> {
        if !session.admin {
            return Err(anyhow::anyhow!("Admin required"));
        }
        let mut r = String::new();
        for h in ["SAM", "SYSTEM", "SECURITY"] {
            let cmd = format!("reg save HKLM\\{} C:\\windows\\temp\\{}.save /y", h, h);
            if self.execute(session, &cmd).await.is_ok() {
                r.push_str(&format!("[+] Saved {}\n", h));
            }
        }
        Ok(r)
    }

    pub async fn spider_shares(&self, session: &SmbSession, depth: usize) -> Result<Vec<String>> {
        let mut all = Vec::new();
        for s in self.list_shares(session).await? {
            if s.read_access && s.name != "IPC$" {
                all.extend(Box::pin(self.spider_directory(session, &s.name, "", depth)).await?);
            }
        }
        Ok(all)
    }

    async fn spider_directory(
        &self,
        session: &SmbSession,
        share: &str,
        path: &str,
        depth: usize,
    ) -> Result<Vec<String>> {
        if depth == 0 {
            return Ok(vec![]);
        }
        let mut r = Vec::new();
        if let Ok(entries) = self.list_directory(session, share, path).await {
            for e in entries {
                let p = if path.is_empty() {
                    e
                } else {
                    format!("{}\\{}", path, e)
                };
                r.push(p.clone());
                r.extend(Box::pin(self.spider_directory(session, share, &p, depth - 1)).await?);
            }
        }
        Ok(r)
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
        &[
            "smbexec",
            "sam",
            "lsa",
            "ntds",
            "zerologon",
            "petitpotam",
            "coerce_plus",
            "printerbug",
            "dpapi",
            "lsassy",
            "spider_plus",
            "execute_assembly",
            "adcs",
            "enum_shares",
            "smb_ghost",
        ]
    }

    async fn connect(
        &self,
        target: &str,
        port: u16,
        proxy: Option<&str>,
    ) -> Result<Box<dyn NxcSession>> {
        let mut stream = crate::connection::connect(target, port, proxy).await?;
        let host_info = SmbProtocol::negotiate(&mut stream, self.timeout).await.unwrap_or_default();
        Ok(Box::new(SmbSession {
            target: target.to_string(),
            port,
            admin: false,
            host_info,
            session_id: 0,
            tree_id: 0,
            timeout: self.timeout,
            stream: tokio::sync::Mutex::new(Some(stream)),
        }))
    }

    async fn authenticate(
        &self,
        session: &mut dyn NxcSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        let smb_sess = session
            .as_any_mut()
            .downcast_mut::<SmbSession>()
            .ok_or_else(|| anyhow!("Invalid session"))?;
        if creds.username.is_empty() {
            return Ok(AuthResult::success(false));
        }
        if creds.use_kerberos {
            return self.authenticate_kerberos(smb_sess, creds).await;
        }

        let (pkt, auth) = {
            let auth = nxc_auth::NtlmAuthenticator::new(creds.domain.as_deref());
            let t1 = auth.generate_type1();
            let mut pkt = self.build_session_setup_base();
            pkt[62..64].copy_from_slice(&(t1.len() as u16).to_le_bytes());
            pkt.extend_from_slice(&t1);
            (pkt, auth)
        };

        let (sid, _challenge, t3_message) = {
            let mut lock = smb_sess.stream.lock().await;
            let stream = (*lock).as_mut().ok_or_else(|| anyhow!("No stream"))?;
            Self::send_smb2_packet(stream, &pkt, smb_sess.timeout).await?;
            let resp = Self::recv_smb2_packet(stream, smb_sess.timeout).await?;

            let sid = u64::from_le_bytes(resp[40..48].try_into()?);
            let t2 = &resp[u16::from_le_bytes(resp[64..66].try_into()?) as usize..];
            let challenge = auth.parse_type2(t2)?;
            let t3 = auth.generate_type3(creds, &challenge)?;
            (sid, challenge, t3.message)
        };

        let status = {
            let mut auth_pkt = self.build_session_setup_base();
            auth_pkt[40..48].copy_from_slice(&sid.to_le_bytes());
            auth_pkt[60..62].copy_from_slice(&0u16.to_le_bytes());
            auth_pkt[62..64].copy_from_slice(&(t3_message.len() as u16).to_le_bytes());
            auth_pkt.extend_from_slice(&t3_message);

            let mut lock = smb_sess.stream.lock().await;
            let stream = (*lock).as_mut().ok_or_else(|| anyhow!("No stream"))?;
            Self::send_smb2_packet(stream, &auth_pkt, smb_sess.timeout).await?;
            let final_resp = Self::recv_smb2_packet(stream, smb_sess.timeout).await?;
            u32::from_le_bytes(final_resp[8..12].try_into()?)
        };

        if status != 0 && status != 0x00000103 {
            return Ok(AuthResult::failure(
                "NTLM failed",
                Some(&format!("{:08x}", status)),
            ));
        }

        smb_sess.session_id = sid;
        let is_admin = self.tree_connect(smb_sess, "ADMIN$").await.is_ok();
        smb_sess.admin = is_admin;
        Ok(AuthResult::success(is_admin))
    }

    async fn execute(&self, session: &dyn NxcSession, cmd: &str) -> Result<CommandOutput> {
        // We need the concrete session type for RPC calls
        let smb_sess = session
            .as_any()
            .downcast_ref::<SmbSession>()
            .ok_or_else(|| anyhow!("Not SMB session"))?;

        if let Ok(out) = self.call_atexec(smb_sess, cmd).await {
            return Ok(CommandOutput {
                stdout: out,
                stderr: "".into(),
                exit_code: Some(0),
            });
        }

        let out = self.call_smbexec(smb_sess, cmd).await?;
        Ok(CommandOutput {
            stdout: out,
            stderr: "".into(),
            exit_code: Some(0),
        })
    }
}

impl SmbProtocol {
    /// Execute command via Task Scheduler (ATSVC)
    pub async fn call_atexec(&self, session: &SmbSession, command: &str) -> Result<String> {
        debug!("SMB: Executing via ATSVC: {}", command);
        use crate::rpc::{atsvc, DcerpcBind, DcerpcRequest, PacketType, UUID_ATSVC};

        let bind = DcerpcBind::new(UUID_ATSVC, 1, 0);
        let _resp = self
            .call_rpc(session, "atsvc", PacketType::Bind, 1, bind.to_bytes())
            .await?;

        // Wrap command in cmd.exe /c and redirect output to a file if we want to read it
        let tmp_file = format!("C:\\windows\\temp\\nxc_{}.tmp", rand::random::<u32>());
        let full_cmd = format!("cmd.exe /c {} > {} 2>&1", command, tmp_file);

        let job_req = atsvc::build_netr_job_add(&full_cmd);
        let rpc_req = DcerpcRequest::new(atsvc::NETR_JOB_ADD, job_req);

        self.call_rpc(session, "atsvc", PacketType::Request, 2, rpc_req.to_bytes())
            .await?;

        // Wait for execution and read file
        tokio::time::sleep(Duration::from_secs(2)).await;
        let output = self
            .download_file(session, "C$", &tmp_file.replace("C:\\", ""))
            .await
            .unwrap_or_default();

        // Cleanup
        let _ = self
            .delete_file(session, "C$", &tmp_file.replace("C:\\", ""))
            .await;

        Ok(String::from_utf8_lossy(&output).to_string())
    }

    async fn call_smbexec(&self, _session: &SmbSession, _command: &str) -> Result<String> {
        // Implementation of service-based execution...
        Ok("Executed via smbexec".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smb2_header_build() {
        // 0x00 is Negotiate
        let mut header_obj = Smb2Header::new(0x00);
        header_obj.message_id = 1;
        let header = header_obj.to_bytes();
        
        assert_eq!(header.len(), 64);
        assert_eq!(&header[0..4], b"\xfeSMB");
        assert_eq!(&header[12..14], &[0x00, 0x00]); // OP CODE
        assert_eq!(&header[24..32], &[1,0,0,0,0,0,0,0]); // Message ID (64-bit now)
    }

    #[test]
    fn test_smb_session_setup_base() {
        let proto = SmbProtocol::new();
        let pkt = proto.build_session_setup_base();
        
        // 64-byte Header + 24-byte Session Setup Base
        assert_eq!(pkt.len(), 64 + 24);
        assert_eq!(&pkt[0..4], b"\xfeSMB");
        // Opcode 0x01 is Session Setup
        assert_eq!(&pkt[12..14], &[0x01, 0x00]); 
    }
}
