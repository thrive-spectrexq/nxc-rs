//! # nxc-auth — NetExec-RS Authentication Engine
//!
//! Pure Rust implementation of NTLM, Kerberos, and certificate-based
//! authentication for all NetExec-RS protocol handlers.

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

// ─── Credential Types ───────────────────────────────────────────

/// All supported authentication methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    Password,
    NtHash,
    LmNtHash,
    KerberosTgt,
    KerberosTgs,
    Certificate,
    AesKey,
    NullSession,
    Guest,
}

/// Credentials container — zeroized on drop for security.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct Credentials {
    pub domain: Option<String>,
    pub username: String,
    pub password: Option<String>,
    pub nt_hash: Option<String>,
    pub lm_hash: Option<String>,
    pub aes_128_key: Option<String>,
    pub aes_256_key: Option<String>,
    pub ccache_path: Option<String>,
    pub pfx_path: Option<String>,
}

impl Credentials {
    /// Create simple password credentials.
    pub fn password(username: &str, password: &str, domain: Option<&str>) -> Self {
        Self {
            domain: domain.map(|s| s.to_string()),
            username: username.to_string(),
            password: Some(password.to_string()),
            nt_hash: None,
            lm_hash: None,
            aes_128_key: None,
            aes_256_key: None,
            ccache_path: None,
            pfx_path: None,
        }
    }

    /// Create pass-the-hash credentials.
    pub fn nt_hash(username: &str, hash: &str, domain: Option<&str>) -> Self {
        Self {
            domain: domain.map(|s| s.to_string()),
            username: username.to_string(),
            password: None,
            nt_hash: Some(hash.to_string()),
            lm_hash: None,
            aes_128_key: None,
            aes_256_key: None,
            ccache_path: None,
            pfx_path: None,
        }
    }

    /// Create null session (anonymous) credentials.
    pub fn null_session() -> Self {
        Self {
            domain: None,
            username: String::new(),
            password: None,
            nt_hash: None,
            lm_hash: None,
            aes_128_key: None,
            aes_256_key: None,
            ccache_path: None,
            pfx_path: None,
        }
    }
}

// ─── Auth Result Types ──────────────────────────────────────────

/// Result of an authentication attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    pub success: bool,
    pub admin: bool,
    pub message: String,
    pub error_code: Option<String>,
}

impl AuthResult {
    pub fn success(admin: bool) -> Self {
        Self {
            success: true,
            admin,
            message: if admin {
                "Pwn3d!".to_string()
            } else {
                "Authenticated".to_string()
            },
            error_code: None,
        }
    }

    pub fn failure(message: &str, code: Option<&str>) -> Self {
        Self {
            success: false,
            admin: false,
            message: message.to_string(),
            error_code: code.map(|s| s.to_string()),
        }
    }
}

impl fmt::Display for AuthResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.success {
            if self.admin {
                write!(f, "[+] {} (Pwn3d!)", self.message)
            } else {
                write!(f, "[+] {}", self.message)
            }
        } else {
            write!(f, "[-] {}", self.message)
        }
    }
}

/// Opaque authenticated session handle.
pub struct AuthSession {
    pub session_key: Vec<u8>,
    pub is_admin: bool,
}

// ─── Auth Provider Trait ────────────────────────────────────────

/// Trait implemented by each authentication mechanism (NTLM, Kerberos, etc.).
#[async_trait]
pub trait AuthProvider: Send + Sync {
    /// Name of this auth provider (e.g. "ntlm", "kerberos").
    fn name(&self) -> &'static str;

    /// Whether this provider supports the given auth method.
    fn supports(&self, method: AuthMethod) -> bool;

    /// Attempt authentication against a target.
    async fn authenticate(
        &self,
        target: &str,
        port: u16,
        creds: &Credentials,
    ) -> Result<AuthResult>;
}

use hmac::{Hmac, Mac};
use md4::{Digest, Md4};
use md5::Md5;
type HmacMd5 = Hmac<Md5>;

// ─── NTLM Constants & Helpers ─────────────────────────────────

const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

#[derive(Debug, Clone, Copy)]
pub enum NtlmMessageType {
    Negotiate = 1,
    Challenge = 2,
    Authenticate = 3,
}

/// Pure Rust NTLM authentication (NTLMv1/v2).
pub struct NtlmAuthenticator {
    pub domain: Option<String>,
    pub workstation: String,
}

impl NtlmAuthenticator {
    pub fn new(domain: Option<&str>) -> Self {
        let workstation = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "WORKSTATION".to_string());
        Self {
            domain: domain.map(|s| s.to_string()),
            workstation,
        }
    }

    /// Generate a Type 1 Negotiate Message.
    pub fn generate_type1(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(32);
        msg.extend_from_slice(NTLMSSP_SIGNATURE);
        msg.extend_from_slice(&(NtlmMessageType::Negotiate as u32).to_le_bytes());
        // Flags: NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_OEM | NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_ALWAYS_SIGN | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        msg.extend_from_slice(&0x00088203u32.to_le_bytes());
        // Domain and Workstation payloads (empty for type 1 often)
        msg.extend_from_slice(&[0u8; 8]); // Domain security buffer
        msg.extend_from_slice(&[0u8; 8]); // Workstation security buffer
        msg
    }

    /// Parse a Type 2 Challenge Message.
    pub fn parse_type2(&self, data: &[u8]) -> Result<([u8; 8], Vec<u8>)> {
        if data.len() < 32 || &data[0..8] != NTLMSSP_SIGNATURE {
            return Err(anyhow::anyhow!("Invalid NTLM signature"));
        }
        
        // Extract challenge nonce (8 bytes at offset 24)
        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&data[24..32]);

        // Extract Target Info (if present)
        let mut target_info = Vec::new();
        if data.len() >= 48 {
            let ti_len = u16::from_le_bytes([data[40], data[41]]) as usize;
            let ti_off = u32::from_le_bytes([data[44], data[45], data[46], data[47]]) as usize;
            if ti_off + ti_len <= data.len() {
                target_info.extend_from_slice(&data[ti_off..ti_off + ti_len]);
            }
        }

        Ok((nonce, target_info))
    }

    /// Generate a Type 3 Authenticate Message.
    pub fn generate_type3(
        &self,
        creds: &Credentials,
        challenge_nonce: &[u8; 8],
        target_info: &[u8],
    ) -> Result<Vec<u8>> {
        let username = creds.username.clone();
        let domain = creds.domain.as_deref().unwrap_or("").to_string();
        let timestamp = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;
        let client_nonce = rand::random::<[u8; 8]>();

        // 1. Calculate Hashes
        let nt_hash = if let Some(ref hash) = creds.nt_hash {
            hex::decode(hash)?.try_into().map_err(|_| anyhow::anyhow!("Invalid NT hash length"))?
        } else if let Some(ref pass) = creds.password {
            Self::calculate_nt_hash(pass)
        } else {
            return Err(anyhow::anyhow!("No password or hash provided"));
        };

        let v2_hash = Self::calculate_v2_hash(&username, &domain, &nt_hash);

        // 2. Build NTLMv2 Response
        // Structure: HMAC-MD5(v2_hash, challenge + blob) + blob
        // Blob: 0x01010000 + reserved + timestamp + client_nonce + 0 + target_info + 0
        let mut blob = Vec::new();
        blob.extend_from_slice(&[1, 1, 0, 0]); // RespType + HiRespType
        blob.extend_from_slice(&[0; 4]);       // Reserved
        blob.extend_from_slice(&timestamp.to_le_bytes());
        blob.extend_from_slice(&client_nonce);
        blob.extend_from_slice(&[0; 4]);       // Reserved2
        blob.extend_from_slice(target_info);
        blob.extend_from_slice(&[0; 4]);       // End of attributes

        let mut hmac = HmacMd5::new_from_slice(&v2_hash)?;
        hmac.update(challenge_nonce);
        hmac.update(&blob);
        let nt_proof_str = hmac.finalize().into_bytes();

        let mut nt_response = Vec::new();
        nt_response.extend_from_slice(&nt_proof_str);
        nt_response.extend_from_slice(&blob);

        // 3. Construct Type 3 Message
        // [Header][Buffers (User, Domain, WS, LmResp, NtResp, SessionKey)][Payloads]
        let mut msg = Vec::new();
        msg.extend_from_slice(NTLMSSP_SIGNATURE);
        msg.extend_from_slice(&(NtlmMessageType::Authenticate as u32).to_le_bytes());

        // Placeholders for security buffers (offset/length)
        let mut payload = Vec::new();

        let domain_utf16: Vec<u8> = domain.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let user_utf16: Vec<u8> = username.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let ws_utf16: Vec<u8> = self.workstation.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();

        // LM Response (empty for NTLMv2)
        msg.extend_from_slice(&0u16.to_le_bytes()); msg.extend_from_slice(&0u16.to_le_bytes()); msg.extend_from_slice(&0u32.to_le_bytes());
        
        // NT Response
        let nt_off = 64 + domain_utf16.len() + user_utf16.len() + ws_utf16.len();
        msg.extend_from_slice(&(nt_response.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(nt_response.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(nt_off as u32).to_le_bytes());

        // Domain
        msg.extend_from_slice(&(domain_utf16.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(domain_utf16.len() as u16).to_le_bytes());
        msg.extend_from_slice(&64u32.to_le_bytes());
        payload.extend_from_slice(&domain_utf16);

        // User
        msg.extend_from_slice(&(user_utf16.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(user_utf16.len() as u16).to_le_bytes());
        msg.extend_from_slice(&((64 + domain_utf16.len()) as u32).to_le_bytes());
        payload.extend_from_slice(&user_utf16);

        // Workstation
        msg.extend_from_slice(&(ws_utf16.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(ws_utf16.len() as u16).to_le_bytes());
        msg.extend_from_slice(&((64 + domain_utf16.len() + user_utf16.len()) as u32).to_le_bytes());
        payload.extend_from_slice(&ws_utf16);

        // Session Key (empty for now)
        msg.extend_from_slice(&0u16.to_le_bytes()); msg.extend_from_slice(&0u16.to_le_bytes()); msg.extend_from_slice(&0u32.to_le_bytes());
        
        // Flags
        msg.extend_from_slice(&0x00088201u32.to_le_bytes());

        msg.extend_from_slice(&payload);
        msg.extend_from_slice(&nt_response);

        Ok(msg)
    }

    fn calculate_nt_hash(password: &str) -> [u8; 16] {
        let mut hasher = Md4::new();
        let utf16: Vec<u16> = password.encode_utf16().collect();
        let bytes: Vec<u8> = utf16.iter().flat_map(|&u| u.to_le_bytes()).collect();
        hasher.update(&bytes);
        hasher.finalize().into()
    }

    fn calculate_v2_hash(username: &str, domain: &str, nt_hash: &[u8; 16]) -> [u8; 16] {
        let mut hmac = HmacMd5::new_from_slice(nt_hash).expect("HMAC can take key of any size");
        let identity = format!("{}{}", username.to_uppercase(), domain.to_uppercase());
        let utf16: Vec<u16> = identity.encode_utf16().collect();
        let bytes: Vec<u8> = utf16.iter().flat_map(|&u| u.to_le_bytes()).collect();
        hmac.update(&bytes);
        hmac.finalize().into_bytes().into()
    }
}

#[async_trait]
impl AuthProvider for NtlmAuthenticator {
    fn name(&self) -> &'static str {
        "ntlm"
    }

    fn supports(&self, method: AuthMethod) -> bool {
        matches!(
            method,
            AuthMethod::Password | AuthMethod::NtHash | AuthMethod::LmNtHash
        )
    }

    async fn authenticate(
        &self,
        _target: &str,
        _port: u16,
        _creds: &Credentials,
    ) -> Result<AuthResult> {
        // This is a generic auth provider wrapper. 
        // Protocols like SMB will use generate_type1/3 directly.
        Err(anyhow::anyhow!("Use protocol-specific NTLM handshake (e.g. SMB SESSION_SETUP)"))
    }
}

// ─── Kerberos Authenticator (Stub) ──────────────────────────────

/// Pure Rust Kerberos authentication (AS-REQ/TGS-REQ).
pub struct KerberosAuth {
    pub realm: String,
    pub kdc_host: Option<String>,
}

impl KerberosAuth {
    pub fn new(realm: &str, kdc_host: Option<&str>) -> Self {
        Self {
            realm: realm.to_uppercase(),
            kdc_host: kdc_host.map(|s| s.to_string()),
        }
    }
}

#[async_trait]
impl AuthProvider for KerberosAuth {
    fn name(&self) -> &'static str {
        "kerberos"
    }

    fn supports(&self, method: AuthMethod) -> bool {
        matches!(
            method,
            AuthMethod::Password
                | AuthMethod::NtHash
                | AuthMethod::KerberosTgt
                | AuthMethod::KerberosTgs
                | AuthMethod::Certificate
                | AuthMethod::AesKey
        )
    }

    async fn authenticate(
        &self,
        _target: &str,
        _port: u16,
        _creds: &Credentials,
    ) -> Result<AuthResult> {
        // TODO: Implement Kerberos AS-REQ/TGS-REQ exchange
        Err(anyhow::anyhow!(
            "Kerberos authentication not yet implemented"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntlm_v2_logic() {
        let auth = NtlmAuthenticator::new(Some("DOMAIN"));
        let creds = Credentials::password("user", "pass", Some("DOMAIN"));
        let t1 = auth.generate_type1();
        assert!(t1.starts_with(b"NTLMSSP\0"));
        
        let challenge = [0x01; 8];
        let target_info = vec![0x00; 16];
        let t3 = auth.generate_type3(&creds, &challenge, &target_info).unwrap();
        assert!(t3.starts_with(b"NTLMSSP\0"));
    }
}
