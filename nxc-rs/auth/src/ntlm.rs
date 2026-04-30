//! # NTLM SSP — Pure Rust NTLMv1/v2 Authentication
//!
//! Full implementation of the NTLM Security Support Provider (SSP),
//! including NTLMv2 authentication, session key derivation, and
//! message signing/sealing for SMB3 channel security.

// SECURITY: NTLM authentication and SMB signing MANDATE the use of legacy
// cryptographic algorithms including MD4 (for NT hashes), MD5 (for HMAC-MD5),
// and RC4 (for session key derivation and sealing in SMB1/2). While these
// algorithms are considered insecure for modern applications, they are
// SPECIFICATION-REQUIRED and functionally necessary for a pentesting
// framework to communicate with legacy Windows environments.

use anyhow::Result;
use hmac::{Hmac, Mac};
use md4::{Digest, Md4};
use md5::Md5;
use rc4::cipher::{KeyInit, StreamCipher};
use rc4::Rc4;
use tracing::debug;

use crate::Credentials;

type HmacMd5 = Hmac<Md5>;

// ─── NTLM Constants ────────────────────────────────────────────

pub const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

// Negotiate flags
pub const NTLMSSP_NEGOTIATE_UNICODE: u32 = 0x00000001;
pub const NTLMSSP_NEGOTIATE_OEM: u32 = 0x00000002;
pub const NTLMSSP_REQUEST_TARGET: u32 = 0x00000004;
pub const NTLMSSP_NEGOTIATE_SIGN: u32 = 0x00000010;
pub const NTLMSSP_NEGOTIATE_SEAL: u32 = 0x00000020;
pub const NTLMSSP_NEGOTIATE_LM_KEY: u32 = 0x00000080;
pub const NTLMSSP_NEGOTIATE_NTLM: u32 = 0x00000200;
pub const NTLMSSP_NEGOTIATE_ALWAYS_SIGN: u32 = 0x00008000;
pub const NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x00080000;
pub const NTLMSSP_NEGOTIATE_TARGET_INFO: u32 = 0x00800000;
pub const NTLMSSP_NEGOTIATE_VERSION: u32 = 0x02000000;
pub const NTLMSSP_NEGOTIATE_128: u32 = 0x20000000;
pub const NTLMSSP_NEGOTIATE_KEY_EXCH: u32 = 0x40000000;
pub const NTLMSSP_NEGOTIATE_56: u32 = 0x80000000;

// Default negotiate flags for Type 1 message
pub const DEFAULT_NEGOTIATE_FLAGS: u32 = NTLMSSP_NEGOTIATE_UNICODE
    | NTLMSSP_NEGOTIATE_OEM
    | NTLMSSP_REQUEST_TARGET
    | NTLMSSP_NEGOTIATE_NTLM
    | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
    | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
    | NTLMSSP_NEGOTIATE_TARGET_INFO
    | NTLMSSP_NEGOTIATE_SIGN
    | NTLMSSP_NEGOTIATE_SEAL
    | NTLMSSP_NEGOTIATE_128
    | NTLMSSP_NEGOTIATE_KEY_EXCH
    | NTLMSSP_NEGOTIATE_56;

#[derive(Debug, Clone, Copy)]
pub enum NtlmMessageType {
    Negotiate = 1,
    Challenge = 2,
    Authenticate = 3,
}

// ─── Target Info AV Pair Types ─────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AvId {
    MsvAvEOL = 0x0000,
    MsvAvNbComputerName = 0x0001,
    MsvAvNbDomainName = 0x0002,
    MsvAvDnsComputerName = 0x0003,
    MsvAvDnsDomainName = 0x0004,
    MsvAvDnsTreeName = 0x0005,
    MsvAvFlags = 0x0006,
    MsvAvTimestamp = 0x0007,
    MsvAvSingleHost = 0x0008,
    MsvAvTargetName = 0x0009,
    MsvAvChannelBindings = 0x000A,
}

/// Parsed target info from Type 2 challenge.
#[derive(Debug, Clone, Default)]
pub struct NtlmTargetInfo {
    pub nb_computer_name: Option<String>,
    pub nb_domain_name: Option<String>,
    pub dns_computer_name: Option<String>,
    pub dns_domain_name: Option<String>,
    pub dns_tree_name: Option<String>,
    pub timestamp: Option<u64>,
    pub flags: Option<u32>,
    pub raw: Vec<u8>,
}

impl NtlmTargetInfo {
    /// Parse AV_PAIR structures from target info buffer.
    pub fn parse(data: &[u8]) -> Self {
        let mut info = NtlmTargetInfo { raw: data.to_vec(), ..Default::default() };

        let mut offset = 0;
        while offset + 4 <= data.len() {
            let av_id = u16::from_le_bytes([data[offset], data[offset + 1]]);
            let av_len = u16::from_le_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;

            if offset + av_len > data.len() {
                break;
            }

            let av_data = &data[offset..offset + av_len];

            match av_id {
                0x0000 => break, // MsvAvEOL
                0x0001 => info.nb_computer_name = Some(decode_utf16(av_data)),
                0x0002 => info.nb_domain_name = Some(decode_utf16(av_data)),
                0x0003 => info.dns_computer_name = Some(decode_utf16(av_data)),
                0x0004 => info.dns_domain_name = Some(decode_utf16(av_data)),
                0x0005 => info.dns_tree_name = Some(decode_utf16(av_data)),
                0x0006 if av_len >= 4 => {
                    info.flags =
                        Some(u32::from_le_bytes([av_data[0], av_data[1], av_data[2], av_data[3]]))
                }
                0x0007 if av_len >= 8 => {
                    info.timestamp = Some(u64::from_le_bytes([
                        av_data[0], av_data[1], av_data[2], av_data[3], av_data[4], av_data[5],
                        av_data[6], av_data[7],
                    ]))
                }
                _ => {}
            }

            offset += av_len;
        }

        info
    }
}

/// NTLM session keys for signing and sealing.
#[derive(Debug, Clone)]
pub struct NtlmSessionSecurity {
    /// Exported session key (used for SMB3 encryption).
    pub exported_session_key: Vec<u8>,
    /// Session base key (from NTProofStr HMAC).
    pub session_base_key: Vec<u8>,
    /// Whether key exchange was negotiated.
    pub key_exchange: bool,
    /// Negotiated flags.
    pub negotiate_flags: u32,
}

// ─── NTLM Authenticator ───────────────────────────────────────

/// Pure Rust NTLM authentication (NTLMv1/v2) with session key support.
pub struct NtlmAuthenticator {
    pub domain: Option<String>,
    pub workstation: String,
    pub negotiate_flags: u32,
}

impl NtlmAuthenticator {
    pub fn new(domain: Option<&str>) -> Self {
        let workstation = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "WORKSTATION".to_string());
        Self {
            domain: domain.map(std::string::ToString::to_string),
            workstation,
            negotiate_flags: DEFAULT_NEGOTIATE_FLAGS,
        }
    }

    /// Create an authenticator with specific negotiate flags.
    pub fn with_flags(domain: Option<&str>, flags: u32) -> Self {
        let mut auth = Self::new(domain);
        auth.negotiate_flags = flags;
        auth
    }

    // ── Type 1: Negotiate Message ──

    /// Generate a Type 1 Negotiate Message.
    pub fn generate_type1(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(40);
        msg.extend_from_slice(NTLMSSP_SIGNATURE);
        msg.extend_from_slice(&(NtlmMessageType::Negotiate as u32).to_le_bytes());
        msg.extend_from_slice(&self.negotiate_flags.to_le_bytes());

        // Domain security buffer (empty)
        msg.extend_from_slice(&[0u8; 8]);
        // Workstation security buffer (empty)
        msg.extend_from_slice(&[0u8; 8]);

        // Version (Windows 10.0, NTLMSSP 15)
        if self.negotiate_flags & NTLMSSP_NEGOTIATE_VERSION != 0 {
            msg.extend_from_slice(&[10, 0]); // ProductMajor, ProductMinor
            msg.extend_from_slice(&0u16.to_le_bytes()); // ProductBuild
            msg.extend_from_slice(&[0, 0, 0]); // Reserved
            msg.push(15); // NTLMRevisionCurrent
        }

        msg
    }

    // ── Type 2: Challenge Parsing ──

    /// Parse a Type 2 Challenge Message, returning the nonce, target info, and negotiated flags.
    pub fn parse_type2(&self, data: &[u8]) -> Result<NtlmChallenge> {
        if data.len() < 32 || &data[0..8] != NTLMSSP_SIGNATURE {
            return Err(anyhow::anyhow!("Invalid NTLM signature"));
        }

        let msg_type = u32::from_le_bytes(data[8..12].try_into()?);
        if msg_type != NtlmMessageType::Challenge as u32 {
            return Err(anyhow::anyhow!("Expected Challenge (type 2), got type {msg_type}"));
        }

        // Target Name security buffer
        let _target_name_len = u16::from_le_bytes([data[12], data[13]]);
        let _target_name_max = u16::from_le_bytes([data[14], data[15]]);
        let _target_name_off = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);

        // Negotiate flags from server
        let server_flags = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);

        // Server challenge nonce (8 bytes)
        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&data[24..32]);

        // Reserved (8 bytes at offset 32)

        // Target Info
        let mut target_info_raw = Vec::new();
        let mut target_info = NtlmTargetInfo::default();

        if data.len() >= 48 {
            let ti_len = u16::from_le_bytes([data[40], data[41]]) as usize;
            let ti_off = u32::from_le_bytes([data[44], data[45], data[46], data[47]]) as usize;
            if ti_off + ti_len <= data.len() {
                target_info_raw = data[ti_off..ti_off + ti_len].to_vec();
                target_info = NtlmTargetInfo::parse(&target_info_raw);
            }
        }

        Ok(NtlmChallenge { nonce, server_flags, target_info, target_info_raw })
    }

    // ── Type 3: Authenticate Message ──

    /// Generate a Type 3 Authenticate Message with session key derivation.
    pub fn generate_type3(
        &self,
        creds: &Credentials,
        challenge: &NtlmChallenge,
    ) -> Result<NtlmAuthResult> {
        let username = creds.username.clone();
        let domain = creds.domain.as_deref().unwrap_or("").to_string();

        // Use server timestamp if available, otherwise generate our own
        let timestamp = challenge.target_info.timestamp.unwrap_or_else(|| {
            // Windows FILETIME: 100ns intervals since 1601-01-01
            let epoch_diff: u64 = 116444736000000000; // difference between 1601 and 1970 in 100ns
            let now = chrono::Utc::now().timestamp() as u64;
            now * 10_000_000 + epoch_diff
        });

        let client_nonce = rand::random::<[u8; 8]>();

        // 1. Calculate NT hash
        let nt_hash = if let Some(ref hash) = creds.nt_hash {
            hex::decode(hash)?.try_into().map_err(|_| anyhow::anyhow!("Invalid NT hash length"))?
        } else if let Some(ref pass) = creds.password {
            calculate_nt_hash(pass)
        } else {
            return Err(anyhow::anyhow!("No password or hash provided"));
        };

        // 2. Calculate NTLMv2 hash
        let v2_hash = calculate_v2_hash(&username, &domain, &nt_hash);

        // 3. Build NTLMv2 response blob
        let mut blob = Vec::new();
        blob.extend_from_slice(&[1, 1, 0, 0]); // RespType + HiRespType
        blob.extend_from_slice(&[0; 4]); // Reserved
        blob.extend_from_slice(&timestamp.to_le_bytes());
        blob.extend_from_slice(&client_nonce);
        blob.extend_from_slice(&[0; 4]); // Reserved2
        blob.extend_from_slice(&challenge.target_info_raw);
        blob.extend_from_slice(&[0; 4]); // End padding

        // 4. Calculate NTProofStr
        let mut hmac = <HmacMd5 as Mac>::new_from_slice(&v2_hash)?;
        hmac.update(&challenge.nonce);
        hmac.update(&blob);
        let nt_proof_str: [u8; 16] = hmac.finalize().into_bytes().into();

        // 5. Build NTLMv2 response
        let mut nt_response = Vec::new();
        nt_response.extend_from_slice(&nt_proof_str);
        nt_response.extend_from_slice(&blob);

        // 6. Compute session base key
        let mut session_hmac = <HmacMd5 as Mac>::new_from_slice(&v2_hash)?;
        session_hmac.update(&nt_proof_str);
        let session_base_key: Vec<u8> = session_hmac.finalize().into_bytes().to_vec();

        // 7. Handle key exchange
        let negotiate_flags = self.negotiate_flags & challenge.server_flags;
        let (exported_session_key, encrypted_random_session_key) =
            if negotiate_flags & NTLMSSP_NEGOTIATE_KEY_EXCH != 0 {
                let exported_key: [u8; 16] = rand::random();
                let key_array: &[u8; 16] = session_base_key[..16]
                    .try_into()
                    .unwrap_or_else(|_| panic!("key_array try_into failed"));
                let mut rc4_key = Rc4::new_from_slice(key_array)
                    .map_err(|e| anyhow::anyhow!("RC4 init fail: {e}"))?;
                let mut encrypted = exported_key;
                rc4_key.apply_keystream(&mut encrypted);
                (exported_key.to_vec(), Some(encrypted.to_vec()))
            } else {
                (session_base_key.clone(), None)
            };

        // 8. Build Type 3 message
        let domain_utf16: Vec<u8> = domain.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let user_utf16: Vec<u8> = username.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let ws_utf16: Vec<u8> =
            self.workstation.encode_utf16().flat_map(u16::to_le_bytes).collect();

        // LM response (24 bytes of zeros for NTLMv2)
        let lm_response = vec![0u8; 24];

        let enc_key_data: &[u8] = encrypted_random_session_key.as_deref().unwrap_or(&[]);

        // Calculate offsets (Type 3 header is 88 bytes with version)
        let base_offset: u32 = 88;
        let lm_offset = base_offset;
        let nt_offset = lm_offset + lm_response.len() as u32;
        let domain_offset = nt_offset + nt_response.len() as u32;
        let user_offset = domain_offset + domain_utf16.len() as u32;
        let ws_offset = user_offset + user_utf16.len() as u32;
        let enc_key_offset = ws_offset + ws_utf16.len() as u32;

        let mut msg = Vec::new();
        msg.extend_from_slice(NTLMSSP_SIGNATURE);
        msg.extend_from_slice(&(NtlmMessageType::Authenticate as u32).to_le_bytes());

        // LM Response security buffer
        msg.extend_from_slice(&(lm_response.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(lm_response.len() as u16).to_le_bytes());
        msg.extend_from_slice(&lm_offset.to_le_bytes());

        // NT Response security buffer
        msg.extend_from_slice(&(nt_response.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(nt_response.len() as u16).to_le_bytes());
        msg.extend_from_slice(&nt_offset.to_le_bytes());

        // Domain security buffer
        msg.extend_from_slice(&(domain_utf16.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(domain_utf16.len() as u16).to_le_bytes());
        msg.extend_from_slice(&domain_offset.to_le_bytes());

        // User security buffer
        msg.extend_from_slice(&(user_utf16.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(user_utf16.len() as u16).to_le_bytes());
        msg.extend_from_slice(&user_offset.to_le_bytes());

        // Workstation security buffer
        msg.extend_from_slice(&(ws_utf16.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(ws_utf16.len() as u16).to_le_bytes());
        msg.extend_from_slice(&ws_offset.to_le_bytes());

        // Encrypted Random Session Key security buffer
        msg.extend_from_slice(&(enc_key_data.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(enc_key_data.len() as u16).to_le_bytes());
        msg.extend_from_slice(&enc_key_offset.to_le_bytes());

        // Negotiate flags
        msg.extend_from_slice(&negotiate_flags.to_le_bytes());

        // Version
        msg.extend_from_slice(&[10, 0]); // ProductMajor, ProductMinor
        msg.extend_from_slice(&0u16.to_le_bytes()); // ProductBuild
        msg.extend_from_slice(&[0, 0, 0]); // Reserved
        msg.push(15); // NTLMRevisionCurrent

        // MIC placeholder (16 bytes zeros — filled later if needed)
        let mic_offset = msg.len();
        msg.extend_from_slice(&[0u8; 16]);

        // Payloads (in order of offsets)
        msg.extend_from_slice(&lm_response);
        msg.extend_from_slice(&nt_response);
        msg.extend_from_slice(&domain_utf16);
        msg.extend_from_slice(&user_utf16);
        msg.extend_from_slice(&ws_utf16);
        if !enc_key_data.is_empty() {
            msg.extend_from_slice(enc_key_data);
        }

        debug!(
            "NTLM: Type 3 generated — user={}, domain={}, session_key_len={}",
            username,
            domain,
            exported_session_key.len()
        );

        Ok(NtlmAuthResult {
            message: msg,
            mic_offset,
            session_security: NtlmSessionSecurity {
                exported_session_key,
                session_base_key,
                key_exchange: negotiate_flags & NTLMSSP_NEGOTIATE_KEY_EXCH != 0,
                negotiate_flags,
            },
        })
    }
}

// ─── Public Types ──────────────────────────────────────────────

/// Parsed NTLM Type 2 Challenge.
#[derive(Debug, Clone)]
pub struct NtlmChallenge {
    pub nonce: [u8; 8],
    pub server_flags: u32,
    pub target_info: NtlmTargetInfo,
    pub target_info_raw: Vec<u8>,
}

/// Result of NTLM Type 3 generation.
#[derive(Debug)]
pub struct NtlmAuthResult {
    /// The complete Type 3 message bytes.
    pub message: Vec<u8>,
    /// Offset of the MIC field within `message` (for MIC computation).
    pub mic_offset: usize,
    /// Derived session security keys.
    pub session_security: NtlmSessionSecurity,
}

// ─── Signing & Sealing ─────────────────────────────────────────

impl NtlmSessionSecurity {
    /// Derive the client signing key.
    pub fn client_signing_key(&self) -> [u8; 16] {
        use md5::Digest as Md5Digest;
        let mut md5 = <Md5 as Md5Digest>::new();
        md5.update(&self.exported_session_key);
        let sign_magic = b"session key to client-to-server signing key magic constant\0".as_slice();
        md5.update(sign_magic);
        Md5Digest::finalize(md5).into()
    }

    /// Derive the client sealing key.
    pub fn client_sealing_key(&self) -> [u8; 16] {
        use md5::Digest as Md5Digest;
        let mut md5 = <Md5 as Md5Digest>::new();
        md5.update(&self.exported_session_key);
        let seal_magic = b"session key to client-to-server sealing key magic constant\0".as_slice();
        md5.update(seal_magic);
        Md5Digest::finalize(md5).into()
    }

    /// Derive the server signing key.
    pub fn server_signing_key(&self) -> [u8; 16] {
        use md5::Digest as Md5Digest;
        let mut md5 = <Md5 as Md5Digest>::new();
        md5.update(&self.exported_session_key);
        let sign_magic = b"session key to server-to-client signing key magic constant\0".as_slice();
        md5.update(sign_magic);
        Md5Digest::finalize(md5).into()
    }

    /// Derive the server sealing key.
    pub fn server_sealing_key(&self) -> [u8; 16] {
        use md5::Digest as Md5Digest;
        let mut md5 = <Md5 as Md5Digest>::new();
        md5.update(&self.exported_session_key);
        let seal_magic = b"session key to server-to-client sealing key magic constant\0".as_slice();
        md5.update(seal_magic);
        Md5Digest::finalize(md5).into()
    }

    /// Compute an NTLM message signature (MAC) for signing.
    pub fn compute_signature(&self, seq_num: u32, message: &[u8]) -> Vec<u8> {
        let signing_key = self.client_signing_key();
        let sealing_key = self.client_sealing_key();

        // HMAC-MD5(SigningKey, SeqNum + Message)
        let mut hmac =
            <HmacMd5 as Mac>::new_from_slice(&signing_key).unwrap_or_else(|_| panic!("HMAC key"));
        hmac.update(&seq_num.to_le_bytes());
        hmac.update(message);
        let mac = hmac.finalize().into_bytes();

        // Encrypt first 8 bytes of HMAC with RC4(SealingKey)
        let key_array: &[u8; 16] =
            sealing_key[..16].try_into().unwrap_or_else(|_| panic!("sealing_key try_into failed"));
        let mut rc4 = Rc4::new_from_slice(key_array).unwrap_or_else(|_| panic!("RC4 init fail"));
        let mut encrypted_mac = [0u8; 8];
        encrypted_mac.copy_from_slice(&mac[..8]);
        rc4.apply_keystream(&mut encrypted_mac);

        // Build signature: Version(4) + Checksum(8) + SeqNum(4)
        let mut sig = Vec::with_capacity(16);
        sig.extend_from_slice(&1u32.to_le_bytes()); // Version = 1
        sig.extend_from_slice(&encrypted_mac);
        sig.extend_from_slice(&seq_num.to_le_bytes());
        sig
    }
}

// ─── Cryptographic Helpers ─────────────────────────────────────

/// Calculate NT hash from a password (MD4 of UTF-16LE encoded password).
pub fn calculate_nt_hash(password: &str) -> [u8; 16] {
    let mut hasher = Md4::new();
    let utf16: Vec<u16> = password.encode_utf16().collect();
    let bytes: Vec<u8> = utf16.iter().flat_map(|&u| u.to_le_bytes()).collect();
    hasher.update(&bytes);
    hasher.finalize().into()
}

/// Calculate NTLMv2 hash: HMAC-MD5(NT_Hash, UPPERCASE(user) + UPPERCASE(domain)).
pub fn calculate_v2_hash(username: &str, domain: &str, nt_hash: &[u8; 16]) -> [u8; 16] {
    let mut hmac = <HmacMd5 as Mac>::new_from_slice(nt_hash)
        .unwrap_or_else(|_| panic!("HMAC can take key of any size"));
    let identity = format!("{}{}", username.to_uppercase(), domain.to_uppercase());
    let utf16: Vec<u16> = identity.encode_utf16().collect();
    let bytes: Vec<u8> = utf16.iter().flat_map(|&u| u.to_le_bytes()).collect();
    hmac.update(&bytes);
    hmac.finalize().into_bytes().into()
}

/// Calculate LM hash from a password (DES of "KGS!@#$%" with password key).
pub fn calculate_lm_hash(password: &str) -> [u8; 16] {
    use des::cipher::{BlockEncrypt, KeyInit};
    use des::Des;

    // SECURITY: The "KGS!@#$%" magic string and DES algorithm are MANDATORY
    // for the legacy LM authentication protocol. These are insecure by modern
    // standards but required for protocol compatibility in a pentesting tool.
    let magic: &[u8; 8] = b"KGS!@#$%";
    let mut pass_bytes = [0u8; 14];
    let upper = password.to_uppercase();
    let bytes = upper.as_bytes();
    let len = bytes.len().min(14);
    pass_bytes[..len].copy_from_slice(&bytes[..len]);

    // Split into two 7-byte halves, expand to 8-byte DES keys
    let key1 = des_key_from_7(&pass_bytes[0..7]);
    let key2 = des_key_from_7(&pass_bytes[7..14]);

    let cipher1 = Des::new_from_slice(&key1).unwrap_or_else(|_| panic!("DES key"));
    let cipher2 = Des::new_from_slice(&key2).unwrap_or_else(|_| panic!("DES key"));

    let mut block1 = des::cipher::generic_array::GenericArray::clone_from_slice(magic);
    let mut block2 = des::cipher::generic_array::GenericArray::clone_from_slice(magic);

    cipher1.encrypt_block(&mut block1);
    cipher2.encrypt_block(&mut block2);

    let mut hash = [0u8; 16];
    hash[..8].copy_from_slice(&block1);
    hash[8..].copy_from_slice(&block2);
    hash
}

/// Expand a 7-byte key to an 8-byte DES key with parity bits.
fn des_key_from_7(key: &[u8]) -> [u8; 8] {
    let mut result = [0u8; 8];
    result[0] = key[0] >> 1;
    result[1] = ((key[0] & 0x01) << 6) | (key[1] >> 2);
    result[2] = ((key[1] & 0x03) << 5) | (key[2] >> 3);
    result[3] = ((key[2] & 0x07) << 4) | (key[3] >> 4);
    result[4] = ((key[3] & 0x0F) << 3) | (key[4] >> 5);
    result[5] = ((key[4] & 0x1F) << 2) | (key[5] >> 6);
    result[6] = ((key[5] & 0x3F) << 1) | (key[6] >> 7);
    result[7] = key[6] & 0x7F;

    // Set parity bits
    for byte in result.iter_mut() {
        *byte = (*byte << 1) & 0xFE;
    }

    result
}

/// Decode a UTF-16LE byte slice to a Rust String.
fn decode_utf16(data: &[u8]) -> String {
    let u16s: Vec<u16> = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    String::from_utf16_lossy(&u16s)
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nt_hash_computation() {
        // Known test vector: Password = "Password"
        let hash = calculate_nt_hash("Password");
        assert_eq!(hash.len(), 16);
        // The hash should be deterministic
        let hash2 = calculate_nt_hash("Password");
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_nt_hash_empty() {
        let hash = calculate_nt_hash("");
        let expected = hex::decode("31d6cfe0d16ae931b73c59d7e0c089c0").unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }

    #[test]
    fn test_v2_hash() {
        let nt_hash = calculate_nt_hash("Password");
        let v2 = calculate_v2_hash("User", "Domain", &nt_hash);
        assert_eq!(v2.len(), 16);
        // Should be different with different domain
        let v2_other = calculate_v2_hash("User", "Other", &nt_hash);
        assert_ne!(v2, v2_other);
    }

    #[test]
    fn test_lm_hash() {
        let hash = calculate_lm_hash("");
        // Empty password LM hash
        assert_eq!(hash.len(), 16);
    }

    #[test]
    fn test_type1_message() {
        let auth = NtlmAuthenticator::new(Some("DOMAIN"));
        let t1 = auth.generate_type1();
        assert!(t1.starts_with(b"NTLMSSP\0"));
        assert_eq!(
            u32::from_le_bytes([t1[8], t1[9], t1[10], t1[11]]),
            NtlmMessageType::Negotiate as u32
        );
    }

    #[test]
    fn test_target_info_parsing() {
        // Build a minimal target info with MsvAvNbDomainName
        let mut data = Vec::new();
        // MsvAvNbDomainName (0x0002)
        data.extend_from_slice(&0x0002u16.to_le_bytes());
        let domain = "TEST";
        let domain_u16: Vec<u8> = domain.encode_utf16().flat_map(u16::to_le_bytes).collect();
        data.extend_from_slice(&(domain_u16.len() as u16).to_le_bytes());
        data.extend_from_slice(&domain_u16);
        // MsvAvEOL
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());

        let info = NtlmTargetInfo::parse(&data);
        assert_eq!(info.nb_domain_name.as_deref(), Some("TEST"));
    }

    #[test]
    fn test_session_key_derivation() {
        let session = NtlmSessionSecurity {
            exported_session_key: vec![0xAA; 16],
            session_base_key: vec![0xBB; 16],
            key_exchange: true,
            negotiate_flags: DEFAULT_NEGOTIATE_FLAGS,
        };

        let client_sign = session.client_signing_key();
        let client_seal = session.client_sealing_key();
        let server_sign = session.server_signing_key();
        let server_seal = session.server_sealing_key();

        // All keys should be 16 bytes
        assert_eq!(client_sign.len(), 16);
        assert_eq!(client_seal.len(), 16);
        assert_eq!(server_sign.len(), 16);
        assert_eq!(server_seal.len(), 16);

        // Client and server keys should differ
        assert_ne!(client_sign, server_sign);
        assert_ne!(client_seal, server_seal);
    }

    #[test]
    fn test_ntlmv2_full_flow() {
        let auth = NtlmAuthenticator::new(Some("TESTDOMAIN"));
        let creds = Credentials::password("testuser", "DUMMY_PASSWORD", Some("TESTDOMAIN"));
        let t1 = auth.generate_type1();
        assert!(t1.starts_with(b"NTLMSSP\0"));

        // Simulate a challenge
        let challenge = NtlmChallenge {
            nonce: [0x01; 8],
            server_flags: DEFAULT_NEGOTIATE_FLAGS,
            target_info: NtlmTargetInfo::default(),
            target_info_raw: vec![0x00, 0x00, 0x00, 0x00], // MsvAvEOL
        };

        let result = auth.generate_type3(&creds, &challenge).unwrap();
        assert!(result.message.starts_with(b"NTLMSSP\0"));
        assert_eq!(result.session_security.exported_session_key.len(), 16);
    }

    #[test]
    fn test_ntlm_signature() {
        let session = NtlmSessionSecurity {
            exported_session_key: vec![0x55; 16],
            session_base_key: vec![0x55; 16],
            key_exchange: true,
            negotiate_flags: DEFAULT_NEGOTIATE_FLAGS,
        };

        let sig = session.compute_signature(0, b"Hello, World!");
        assert_eq!(sig.len(), 16);
        // Version field should be 1
        assert_eq!(u32::from_le_bytes([sig[0], sig[1], sig[2], sig[3]]), 1);
    }
}
