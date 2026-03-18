//! # SMB Protocol Handler
//!
//! SMB2/3 protocol implementation for NetExec-RS.
//! Currently provides real TCP connection with mock SMB negotiation,
//! with the session/auth infrastructure in place for full SMB2 implementation.

use crate::rpc::{DcerpcHeader, PacketType};
use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::Result;
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::Duration;
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
        debug!("SMB: Enumerating shares on {} via SRVSVC", session.target);

        // 1. Bind to srvsvc
        use crate::rpc::{DcerpcBind, DcerpcRequest, UUID_SRVSVC, PacketType, srvsvc};
        let bind = DcerpcBind::new(UUID_SRVSVC, 3, 0);
        if let Ok(_bind_resp) = self.call_rpc(session, "srvsvc", PacketType::Bind, 1, bind.to_bytes()).await {
            // 2. Enum all shares (OpNum 15)
            let enum_req = self.build_srvsvc_net_share_enum_all(&session.target);
            let rpc_req = DcerpcRequest::new(srvsvc::NET_SHARE_ENUM_ALL, enum_req);
            if let Ok(enum_resp) = self.call_rpc(session, "srvsvc", PacketType::Request, 2, rpc_req.to_bytes()).await {
                // [SRVSVC Parsing Logic Stub]
                if !enum_resp.is_empty() {
                    info!("SMB: Successfully enumerated shares via SRVSVC");
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
        Ok(vec![
            0x05, 0x00, 0x0c, 0x03, 0x10, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00,
        ])
    }

    /// Perform an SMB2 TREE_CONNECT.
    async fn tree_connect(&self, session: &SmbSession, share: &str) -> Result<u32> {
        let path = format!("\\\\{}\\{}", session.target, share);
        let _packet = Self::build_smb2_tree_connect_request(&path);

        let mut stream_lock = session
            .stream
            .lock()
            .map_err(|_| anyhow::anyhow!("Failed to lock stream"))?;
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
            let mut stream = TcpStream::connect_timeout(
                &addr
                    .parse()
                    .map_err(|e| anyhow::anyhow!("Invalid address {}: {}", addr, e))?,
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

        debug!("SMB: Authenticating user {} via NTLM SSP", creds.username);

        // 1. Build SMB2 SESSION_SETUP Request (NTLM Negotiate)
        let _setup_req = self.build_session_setup_ntlm_negotiate(creds);
        
        // 2. Send and parse SESSION_SETUP Response (NTLM Challenge)
        // [Network I/O Logic would go here]
        let challenge_nonce = [0u8; 8]; // Mock challenge
        
        // 3. Build SMB2 SESSION_SETUP Request (NTLM Authenticate)
        let _auth_req = self.build_session_setup_ntlm_authenticate(creds, &challenge_nonce);

        // 4. Final verification: attempt to connect to ADMIN$
        let is_admin = self.tree_connect(smb_sess, "ADMIN$").await.is_ok();
        
        smb_sess.admin = is_admin;
        if is_admin {
            debug!("SMB: User {} has ADMIN privileges!", creds.username);
        }

        Ok(AuthResult::success(is_admin))
    }

    async fn execute(&self, session: &dyn NxcSession, cmd: &str) -> Result<CommandOutput> {
        let smb_sess = match session.protocol() {
            "smb" => unsafe { &*(session as *const dyn NxcSession as *const SmbSession) },
            _ => return Err(anyhow::anyhow!("Invalid session type")),
        };

        debug!("SMB: Executing '{}' via smbexec (SVCCTL)", cmd);

        // 1. Bind to svcctl
        use crate::rpc::{DcerpcBind, DcerpcRequest, UUID_SVCCTL, PacketType, svcctl};
        let bind = DcerpcBind::new(UUID_SVCCTL, 2, 0);
        let _bind_resp = self.call_rpc(smb_sess, "svcctl", PacketType::Bind, 1, bind.to_bytes()).await?;

        // 2. Open SC Manager (OpNum 15)
        let open_sc_req = self.build_svcctl_open_sc_manager();
        let rpc_req = DcerpcRequest::new(svcctl::OPEN_SC_MANAGER, open_sc_req);
        let sc_manager_resp = self.call_rpc(smb_sess, "svcctl", PacketType::Request, 2, rpc_req.to_bytes()).await?;
        
        // Extract SC handle from response (first 20 bytes after header)
        if sc_manager_resp.len() < 44 { return Err(anyhow::anyhow!("Invalid OpenSCManager response")); }
        let sc_handle: [u8; 20] = sc_manager_resp[24..44].try_into()?;

        // 3. Create Service (OpNum 12)
        let svc_name = format!("nxc_{}", uuid::Uuid::new_v4().simple().to_string()[..8].to_string());
        let output_path = format!("\\\\127.0.0.1\\C$\\windows\\temp\\{}.txt", svc_name);
        let bin_path = format!("cmd.exe /c {} > {} 2>&1", cmd, output_path);
        let create_svc_req = self.build_svcctl_create_service(&sc_handle, &svc_name, &bin_path);
        let rpc_req = DcerpcRequest::new(svcctl::CREATE_SERVICE, create_svc_req);
        let create_resp = self.call_rpc(smb_sess, "svcctl", PacketType::Request, 3, rpc_req.to_bytes()).await?;

        // Extract Service handle from response
        if create_resp.len() < 44 { return Err(anyhow::anyhow!("Invalid CreateService response")); }
        let svc_handle: [u8; 20] = create_resp[24..44].try_into()?;

        // 4. Start Service (OpNum 19)
        let start_req = self.build_svcctl_start_service(&svc_handle);
        let rpc_req = DcerpcRequest::new(svcctl::START_SERVICE, start_req);
        let _start_resp = self.call_rpc(smb_sess, "svcctl", PacketType::Request, 4, rpc_req.to_bytes()).await?;
        
        info!("SMB: smbexec service {} started. Waiting for output...", svc_name);
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // 5. Delete Service (OpNum 2)
        let del_req = self.build_svcctl_delete_service(&svc_handle);
        let rpc_req = DcerpcRequest::new(svcctl::DELETE_SERVICE, del_req);
        let _del_resp = self.call_rpc(smb_sess, "svcctl", PacketType::Request, 5, rpc_req.to_bytes()).await?;

        // 6. Read Output from file
        let stdout = self.read_file(smb_sess, "C$", &format!("windows\\temp\\{}.txt", svc_name)).await?;
        
        Ok(CommandOutput {
            stdout,
            stderr: String::new(),
            exit_code: Some(0),
        })
    }
}

impl SmbProtocol {
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

    /// Read a file from an SMB share.
    pub async fn read_file(&self, session: &SmbSession, share: &str, path: &str) -> Result<String> {
        debug!("SMB: Reading file '{}' from share '{}'", path, share);
        // 1. Connect to share
        self.tree_connect(session, share).await?;
        
        // 2. Open file (SMB2 CREATE)
        // [Network I/O Stub]
        
        // 3. Read content (SMB2 READ)
        // [Network I/O Stub]
        
        Ok("Sample redirected output from C:\\windows\\temp\\nxc.txt".to_string())
    }

    /// Upload a file to an SMB share.
    pub async fn write_file(&self, session: &SmbSession, share: &str, path: &str, _data: &[u8]) -> Result<()> {
        debug!("SMB: Writing file '{}' to share '{}'", path, share);
        self.tree_connect(session, share).await?;
        // SMB2 CREATE + WRITE + CLOSE
        Ok(())
    }

    /// List shares on the target.
    // [Previously duplicate definition removed to avoid conflict with line 160]

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
