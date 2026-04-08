//! # nxc-auth — NetExec-RS Authentication Engine
//!
//! Pure Rust implementation of NTLM, Kerberos, and certificate-based
//! authentication for all NetExec-RS protocol handlers.

pub mod certificate;
pub mod kerberos;
pub mod ntlm;
pub mod registry;

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

// Re-export key types for backward compatibility
pub use certificate::CertificateAuth;
pub use kerberos::{EncryptionType, KerberosClient, KerberosTicket};
pub use ntlm::{
    calculate_lm_hash, calculate_nt_hash, calculate_v2_hash, NtlmAuthResult, NtlmAuthenticator,
    NtlmChallenge, NtlmSessionSecurity, NtlmTargetInfo,
};
pub use registry::RegistrySecrets;

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
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, Default)]
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
    pub use_kerberos: bool,
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
            use_kerberos: false,
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
            use_kerberos: false,
        }
    }

    /// Create AES key credentials (overpass-the-hash).
    pub fn aes_key(username: &str, aes_256: &str, domain: Option<&str>) -> Self {
        Self {
            domain: domain.map(|s| s.to_string()),
            username: username.to_string(),
            password: None,
            nt_hash: None,
            lm_hash: None,
            aes_128_key: None,
            aes_256_key: Some(aes_256.to_string()),
            ccache_path: None,
            pfx_path: None,
            use_kerberos: false,
        }
    }

    /// Create credentials from a ccache file (ticket reuse).
    pub fn ccache(username: &str, path: &str, domain: Option<&str>) -> Self {
        Self {
            domain: domain.map(|s| s.to_string()),
            username: username.to_string(),
            password: None,
            nt_hash: None,
            lm_hash: None,
            aes_128_key: None,
            aes_256_key: None,
            ccache_path: Some(path.to_string()),
            pfx_path: None,
            use_kerberos: false,
        }
    }

    /// Create certificate-based credentials.
    pub fn certificate(username: &str, pfx_path: &str, domain: Option<&str>) -> Self {
        Self {
            domain: domain.map(|s| s.to_string()),
            username: username.to_string(),
            password: None,
            nt_hash: None,
            lm_hash: None,
            aes_128_key: None,
            aes_256_key: None,
            ccache_path: None,
            pfx_path: Some(pfx_path.to_string()),
            use_kerberos: false,
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
            use_kerberos: false,
        }
    }

    /// Determine the best auth method based on available credentials.
    pub fn auth_method(&self) -> AuthMethod {
        if self.pfx_path.is_some() {
            AuthMethod::Certificate
        } else if self.ccache_path.is_some() {
            AuthMethod::KerberosTgt
        } else if self.aes_256_key.is_some() || self.aes_128_key.is_some() {
            AuthMethod::AesKey
        } else if self.nt_hash.is_some() {
            AuthMethod::NtHash
        } else if self.password.is_some() {
            AuthMethod::Password
        } else if self.username.is_empty() {
            AuthMethod::NullSession
        } else {
            AuthMethod::Guest
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credentials_auth_method_detection() {
        let pwd = Credentials::password("user", "pass", Some("DOMAIN"));
        assert_eq!(pwd.auth_method(), AuthMethod::Password);

        let hash = Credentials::nt_hash("user", "aabbccdd", Some("DOMAIN"));
        assert_eq!(hash.auth_method(), AuthMethod::NtHash);

        let aes = Credentials::aes_key("user", "aabb...", Some("DOMAIN"));
        assert_eq!(aes.auth_method(), AuthMethod::AesKey);

        let ccache = Credentials::ccache("user", "/tmp/krb5cc_0", Some("DOMAIN"));
        assert_eq!(ccache.auth_method(), AuthMethod::KerberosTgt);

        let cert = Credentials::certificate("user", "/tmp/user.pfx", Some("DOMAIN"));
        assert_eq!(cert.auth_method(), AuthMethod::Certificate);

        let null = Credentials::null_session();
        assert_eq!(null.auth_method(), AuthMethod::NullSession);
    }

    #[test]
    fn test_auth_result_display() {
        let success = AuthResult::success(true);
        assert!(format!("{}", success).contains("Pwn3d!"));

        let fail = AuthResult::failure("Bad creds", None);
        assert!(format!("{}", fail).contains("Bad creds"));
    }
}
