//! # DCE/RPC Protocol
//!
//! Implementation of DCE/RPC headers and structures for communication with
//! Windows services over SMB Named Pipes.

// ─── DCE/RPC Service UUIDs ──────────────────────────────────────

pub const UUID_SAMR: [u8; 16] = [
    0x78, 0x57, 0x34, 0x12, 0x34, 0x12, 0xcd, 0x11, 0xef, 0xaf, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92,
];

pub const UUID_LSARPC: [u8; 16] = [
    0x78, 0x57, 0x34, 0x12, 0x34, 0x12, 0xcd, 0x11, 0xef, 0xaf, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92,
];

pub const UUID_EPM: [u8; 16] = [
    0x08, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11, 0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa,
];

pub const UUID_WMI_LOGIN: [u8; 16] = [
    0x18, 0xad, 0x09, 0xf3, 0x6a, 0xd8, 0xd0, 0x11, 0xa0, 0x75, 0x00, 0xc0, 0x4f, 0xb6, 0x88, 0x20,
];

pub const UUID_WMI_SERVICES: [u8; 16] = [
    0x99, 0xdc, 0x56, 0x95, 0x8c, 0x82, 0xcf, 0x11, 0xae, 0x37, 0x00, 0xaa, 0x00, 0xa8, 0x75, 0x32,
];

// Service Control Manager (SVCCTL)
pub const UUID_SVCCTL: [u8; 16] = [
    0x81, 0xbb, 0xcb, 0x36, 0xbb, 0x9a, 0x1a, 0x18, 0x01, 0xc1, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00,
];

// Task Scheduler (ATSVC)
pub const UUID_ATSVC: [u8; 16] = [
    0x82, 0x06, 0xf7, 0x1f, 0x51, 0x0a, 0xe8, 0x30, 0x07, 0x6d, 0x74, 0x0b, 0xe8, 0xce, 0xe9, 0x8b,
];

pub mod svcctl {
    pub const OPEN_SC_MANAGER: u16 = 15;
    pub const CREATE_SERVICE: u16 = 12;
    pub const START_SERVICE: u16 = 19;
    pub const DELETE_SERVICE: u16 = 2;
    pub const QUERY_SERVICE_STATUS: u16 = 6;
    pub const CLOSE_SERVICE_HANDLE: u16 = 0;
    pub const OPEN_SERVICE: u16 = 16;

    pub fn build_open_sc_manager(target: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        // MachineName (Pointer)
        buf.extend_from_slice(&0x00020000u32.to_le_bytes()); 
        let target_utf16: Vec<u16> = target.encode_utf16().chain(std::iter::once(0)).collect();
        buf.extend_from_slice(&(target_utf16.len() as u32).to_le_bytes()); // Max count
        buf.extend_from_slice(&0u32.to_le_bytes()); // Offset
        buf.extend_from_slice(&(target_utf16.len() as u32).to_le_bytes()); // Actual count
        for u in target_utf16 {
            buf.extend_from_slice(&u.to_le_bytes());
        }
        // Padding for 4-byte alignment
        while buf.len() % 4 != 0 { buf.push(0); }
        
        // DatabaseName (NULL pointer)
        buf.extend_from_slice(&0u32.to_le_bytes());
        // DesiredAccess (SC_MANAGER_ALL_ACCESS = 0x000f003f)
        buf.extend_from_slice(&0x000F003Fu32.to_le_bytes());
        buf
    }

    pub fn build_create_service(h_mgr: &[u8; 20], service_name: &str, _display_name: &str, command_path: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(h_mgr);
        
        // ServiceName
        let name_utf16: Vec<u16> = service_name.encode_utf16().chain(std::iter::once(0)).collect();
        buf.extend_from_slice(&(name_utf16.len() as u32).to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&(name_utf16.len() as u32).to_le_bytes());
        for u in name_utf16 { buf.extend_from_slice(&u.to_le_bytes()); }
        while buf.len() % 4 != 0 { buf.push(0); }

        // DisplayName (NULL)
        buf.extend_from_slice(&0u32.to_le_bytes());
        // DesiredAccess (SERVICE_ALL_ACCESS = 0x000f01ff)
        buf.extend_from_slice(&0x000F01FFu32.to_le_bytes());
        // ServiceType (SERVICE_WIN32_OWN_PROCESS = 0x10)
        buf.extend_from_slice(&0x00000010u32.to_le_bytes());
        // StartType (SERVICE_DEMAND_START = 0x03)
        buf.extend_from_slice(&0x00000003u32.to_le_bytes());
        // ErrorControl (SERVICE_ERROR_NORMAL = 0x01)
        buf.extend_from_slice(&0x00000001u32.to_le_bytes());
        
        // BinaryPathName
        let path_utf16: Vec<u16> = command_path.encode_utf16().chain(std::iter::once(0)).collect();
        buf.extend_from_slice(&(path_utf16.len() as u32).to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&(path_utf16.len() as u32).to_le_bytes());
        for u in path_utf16 { buf.extend_from_slice(&u.to_le_bytes()); }
        while buf.len() % 4 != 0 { buf.push(0); }

        // LoadOrderGroup (NULL)
        buf.extend_from_slice(&0u32.to_le_bytes());
        // TagId (0)
        buf.extend_from_slice(&0u32.to_le_bytes());
        // Dependencies (NULL)
        buf.extend_from_slice(&0u32.to_le_bytes());
        // ServiceStartName (NULL)
        buf.extend_from_slice(&0u32.to_le_bytes());
        // Password (NULL)
        buf.extend_from_slice(&0u32.to_le_bytes());
        // PasswordSize (0)
        buf.extend_from_slice(&0u32.to_le_bytes());
        
        buf
    }

    pub fn build_start_service(h_svc: &[u8; 20]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(h_svc);
        buf.extend_from_slice(&0u32.to_le_bytes()); // argc
        buf.extend_from_slice(&0u32.to_le_bytes()); // argv pointer
        buf
    }

    pub fn build_delete_service(h_svc: &[u8; 20]) -> Vec<u8> {
        h_svc.to_vec()
    }
}

pub mod samr {
    pub const CONNECT: u16 = 57;
    pub const ENUM_DOMAINS: u16 = 6;
    pub const LOOKUP_DOMAIN: u16 = 5;
    pub const OPEN_DOMAIN: u16 = 7;
    pub const ENUM_DOMAIN_USERS: u16 = 13;
    pub const CLOSE_HANDLE: u16 = 1;

    pub fn build_connect(server: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        // ServerName (Unicode pointer)
        buf.extend_from_slice(&0x00020000u32.to_le_bytes());
        let s_u16: Vec<u16> = format!("\\\\{}", server).encode_utf16().chain(std::iter::once(0)).collect();
        buf.extend_from_slice(&(s_u16.len() as u32).to_le_bytes()); // Max
        buf.extend_from_slice(&0u32.to_le_bytes()); // Offset
        buf.extend_from_slice(&(s_u16.len() as u32).to_le_bytes()); // Actual
        for u in s_u16 { buf.extend_from_slice(&u.to_le_bytes()); }
        while buf.len() % 4 != 0 { buf.push(0); }
        // DesiredAccess (SAM_SERVER_ALL_ACCESS = 0x000F003F)
        buf.extend_from_slice(&0x000F003Fu32.to_le_bytes());
        buf
    }

    pub fn build_lookup_domain(h_conn: &[u8; 20], domain: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(h_conn);
        // DomainName (RPC_UNICODE_STRING)
        let d_u16: Vec<u16> = domain.encode_utf16().collect();
        buf.extend_from_slice(&((d_u16.len() * 2) as u16).to_le_bytes()); // Length
        buf.extend_from_slice(&((d_u16.len() * 2) as u16).to_le_bytes()); // MaxLength
        buf.extend_from_slice(&0x00020004u32.to_le_bytes()); // Pointer
        buf.extend_from_slice(&(d_u16.len() as u32).to_le_bytes()); // Max
        buf.extend_from_slice(&0u32.to_le_bytes()); // Offset
        buf.extend_from_slice(&(d_u16.len() as u32).to_le_bytes()); // Actual
        for u in d_u16 { buf.extend_from_slice(&u.to_le_bytes()); }
        while buf.len() % 4 != 0 { buf.push(0); }
        buf
    }

    pub fn build_open_domain(h_conn: &[u8; 20], sid_bytes: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(h_conn);
        // DesiredAccess (DOMAIN_ALL_ACCESS = 0x000F07FF)
        buf.extend_from_slice(&0x000F07FFu32.to_le_bytes());
        // DomainSid (Pointer and SID)
        buf.extend_from_slice(&0x00020008u32.to_le_bytes());
        buf.extend_from_slice(sid_bytes);
        while buf.len() % 4 != 0 { buf.push(0); }
        buf
    }

    pub fn build_enum_domain_users(h_dom: &[u8; 20]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(h_dom);
        buf.extend_from_slice(&0u32.to_le_bytes()); // EnumerationContext
        buf.extend_from_slice(&0u32.to_le_bytes()); // UserAccountControl
        buf.extend_from_slice(&0xFFFFu32.to_le_bytes()); // PreferedMaximumLength
        buf
    }
}


pub mod srvsvc {
    pub const NET_SHARE_ENUM_ALL: u16 = 15;
}

pub mod atsvc {
    pub const NETR_JOB_ADD: u16 = 0;
    pub const NETR_JOB_DEL: u16 = 1;

    pub fn build_netr_job_add(command: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        // ServerName (NULL)
        buf.extend_from_slice(&0u32.to_le_bytes());
        
        // AT_INFO Structure
        // JobTime (0: Run as soon as possible)
        buf.extend_from_slice(&0u32.to_le_bytes());
        // DaysOfMonth (0)
        buf.extend_from_slice(&0u32.to_le_bytes());
        // DaysOfWeek (0)
        buf.extend_from_slice(&0u8.to_le_bytes());
        // Flags (0x01: JOB_RUN_PERIODICALLY - No, we want once)
        buf.extend_from_slice(&0x00u8.to_le_bytes());
        // Padding for 4-byte align
        buf.extend_from_slice(&[0, 0]);

        // Command (Pointer)
        buf.extend_from_slice(&0x00020000u32.to_le_bytes());
        let cmd_u16: Vec<u16> = command.encode_utf16().chain(std::iter::once(0)).collect();
        buf.extend_from_slice(&(cmd_u16.len() as u32).to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&(cmd_u16.len() as u32).to_le_bytes());
        for u in cmd_u16 { buf.extend_from_slice(&u.to_le_bytes()); }
        
        buf
    }
}

// Directory Replication Service (DRSUAPI)
pub const UUID_DRSUAPI: [u8; 16] = [
    0x35, 0x42, 0x51, 0xe3, 0x06, 0x4b, 0xd1, 0x11, 0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2,
];

pub mod drsuapi {
    pub const DRS_BIND: u16 = 0;
    pub const DRS_GET_NC_CHANGES: u16 = 3;
}

// Server Service (SRVSVC)
pub const UUID_SRVSVC: [u8; 16] = [
    0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88,
];

// Print System Asynchronous Protocol (SPOOLSS)
pub const UUID_SPOOLSS: [u8; 16] = [
    0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0xcd, 0x11, 0xef, 0xaf, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92,
];

// ─── DCE/RPC Headers ───────────────────────────────────────────

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum PacketType {
    Request = 0,
    Response = 2,
    Fault = 3,
    Bind = 11,
    BindAck = 12,
    BindNak = 13,
}

pub struct DcerpcHeader {
    pub rpc_ver: u8,
    pub rpc_ver_minor: u8,
    pub ptype: PacketType,
    pub pfc_flags: u8,
    pub packed_drep: [u8; 4],
    pub frag_len: u16,
    pub auth_len: u16,
    pub call_id: u32,
}

impl DcerpcHeader {
    pub fn new(ptype: PacketType, call_id: u32, frag_len: u16) -> Self {
        Self {
            rpc_ver: 5,
            rpc_ver_minor: 0,
            ptype,
            pfc_flags: 0x03,                       // First + Last frag
            packed_drep: [0x10, 0x00, 0x00, 0x00], // Little Endian
            frag_len,
            auth_len: 0,
            call_id,
        }
    }

    pub fn with_auth(mut self, auth_len: u16) -> Self {
        self.auth_len = auth_len;
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![
            self.rpc_ver,
            self.rpc_ver_minor,
            self.ptype as u8,
            self.pfc_flags,
        ];
        buf.extend_from_slice(&self.packed_drep);
        buf.extend_from_slice(&self.frag_len.to_le_bytes());
        buf.extend_from_slice(&self.auth_len.to_le_bytes());
        buf.extend_from_slice(&self.call_id.to_le_bytes());
        buf
    }
}

// ─── DCE/RPC Auth Verifier ────────────────────────────────────

pub struct DcerpcAuth {
    pub auth_type: u8,   // 0x0a for NTLM
    pub auth_level: u8,  // 0x06 for Privacy, 0x05 for Integrity
    pub auth_pad_len: u8,
    pub auth_reserved: u8,
    pub auth_context_id: u32,
    pub auth_data: Vec<u8>,
}

impl DcerpcAuth {
    pub fn new(auth_type: u8, auth_level: u8, auth_data: Vec<u8>) -> Self {
        Self {
            auth_type,
            auth_level,
            auth_pad_len: 0,
            auth_reserved: 0,
            auth_context_id: 0,
            auth_data,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![
            self.auth_type,
            self.auth_level,
            self.auth_pad_len,
            self.auth_reserved,
        ];
        buf.extend_from_slice(&self.auth_context_id.to_le_bytes());
        buf.extend_from_slice(&self.auth_data);
        buf
    }
}

// ─── DCE/RPC Bind ─────────────────────────────────────────────

pub struct DcerpcBind {
    pub max_xmit_frag: u16,
    pub max_recv_frag: u16,
    pub assoc_group_id: u32,
    pub num_ctx_items: u32,
    pub ctx_id: u16,
    pub num_trans_items: u16,
    pub abstract_syntax_uuid: [u8; 16],
    pub abstract_syntax_ver_major: u16,
    pub abstract_syntax_ver_minor: u16,
    pub transfer_syntax_uuid: [u8; 16],
    pub transfer_syntax_ver: u32,
}

impl DcerpcBind {
    pub fn new(uuid: [u8; 16], major: u16, minor: u16) -> Self {
        Self {
            max_xmit_frag: 5840,
            max_recv_frag: 5840,
            assoc_group_id: 0,
            num_ctx_items: 1,
            ctx_id: 0,
            num_trans_items: 1,
            abstract_syntax_uuid: uuid,
            abstract_syntax_ver_major: major,
            abstract_syntax_ver_minor: minor,
            transfer_syntax_uuid: [
                0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10,
                0x48, 0x60,
            ], // NDR UUID
            transfer_syntax_ver: 2,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.max_xmit_frag.to_le_bytes());
        buf.extend_from_slice(&self.max_recv_frag.to_le_bytes());
        buf.extend_from_slice(&self.assoc_group_id.to_le_bytes());
        buf.extend_from_slice(&self.num_ctx_items.to_le_bytes());
        buf.extend_from_slice(&self.ctx_id.to_le_bytes());
        buf.extend_from_slice(&self.num_trans_items.to_le_bytes());
        buf.extend_from_slice(&self.abstract_syntax_uuid);
        buf.extend_from_slice(&self.abstract_syntax_ver_major.to_le_bytes());
        buf.extend_from_slice(&self.abstract_syntax_ver_minor.to_le_bytes());
        buf.extend_from_slice(&self.transfer_syntax_uuid);
        buf.extend_from_slice(&self.transfer_syntax_ver.to_le_bytes());
        buf
    }
}

// ─── DCE/RPC Request ──────────────────────────────────────────

pub struct DcerpcRequest {
    pub alloc_hint: u32,
    pub p_cont_id: u16,
    pub opnum: u16,
    pub payload: Vec<u8>,
}

impl DcerpcRequest {
    pub fn new(opnum: u16, payload: Vec<u8>) -> Self {
        Self {
            alloc_hint: payload.len() as u32,
            p_cont_id: 0,
            opnum,
            payload,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.alloc_hint.to_le_bytes());
        buf.extend_from_slice(&self.p_cont_id.to_le_bytes());
        buf.extend_from_slice(&self.opnum.to_le_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }
}
