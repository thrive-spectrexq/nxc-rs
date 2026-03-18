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
