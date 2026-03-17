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

// ─── NTLM Authenticator (Stub) ─────────────────────────────────

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
        // TODO: Implement NTLM Type1/Type2/Type3 message exchange
        Err(anyhow::anyhow!("NTLM authentication not yet implemented"))
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
