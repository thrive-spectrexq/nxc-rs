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

impl fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Password => write!(f, "password"),
            Self::NtHash => write!(f, "NT hash"),
            Self::LmNtHash => write!(f, "LM/NT hash"),
            Self::KerberosTgt => write!(f, "Kerberos TGT"),
            Self::KerberosTgs => write!(f, "Kerberos TGS"),
            Self::Certificate => write!(f, "certificate"),
            Self::AesKey => write!(f, "AES key"),
            Self::NullSession => write!(f, "null session"),
            Self::Guest => write!(f, "guest"),
        }
    }
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

impl fmt::Display for Credentials {
    /// Formats a safe representation: `domain\username (auth_method)`.
    ///
    /// Passwords, hashes, and keys are **never** included in the output.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let auth = self.auth_method();
        let user = &self.username;
        if let Some(domain) = &self.domain {
            write!(f, "{domain}\\{user} ({auth})")
        } else {
            write!(f, "{user} ({auth})")
        }
    }
}

impl Credentials {
    /// Create simple password credentials.
    pub fn password(username: &str, password: &str, domain: Option<&str>) -> Self {
        let mut c = Self::default();
        c.domain = domain.map(String::from);
        c.username = username.to_string();
        c.password = Some(password.to_string());
        c
    }

    /// Create pass-the-hash credentials.
    pub fn nt_hash(username: &str, hash: &str, domain: Option<&str>) -> Self {
        let mut c = Self::default();
        c.domain = domain.map(String::from);
        c.username = username.to_string();
        c.nt_hash = Some(hash.to_string());
        c
    }

    /// Create AES key credentials (overpass-the-hash).
    pub fn aes_key(username: &str, aes_256: &str, domain: Option<&str>) -> Self {
        let mut c = Self::default();
        c.domain = domain.map(String::from);
        c.username = username.to_string();
        c.aes_256_key = Some(aes_256.to_string());
        c
    }

    /// Create credentials from a ccache file (ticket reuse).
    pub fn ccache(username: &str, path: &str, domain: Option<&str>) -> Self {
        let mut c = Self::default();
        c.domain = domain.map(String::from);
        c.username = username.to_string();
        c.ccache_path = Some(path.to_string());
        c
    }

    /// Create certificate-based credentials.
    pub fn certificate(username: &str, pfx_path: &str, domain: Option<&str>) -> Self {
        let mut c = Self::default();
        c.domain = domain.map(String::from);
        c.username = username.to_string();
        c.pfx_path = Some(pfx_path.to_string());
        c
    }

    /// Create null session (anonymous) credentials.
    pub fn null_session() -> Self {
        Self::default()
    }

    /// Returns `true` if this represents a null (anonymous) session.
    pub fn is_null_session(&self) -> bool {
        self.auth_method() == AuthMethod::NullSession
    }

    /// Returns `true` if at least one credential field is populated.
    ///
    /// Checks `password`, `nt_hash`, `aes_128_key`, `aes_256_key`,
    /// `ccache_path`, and `pfx_path`.
    pub fn has_valid_credentials(&self) -> bool {
        self.password.is_some()
            || self.nt_hash.is_some()
            || self.aes_128_key.is_some()
            || self.aes_256_key.is_some()
            || self.ccache_path.is_some()
            || self.pfx_path.is_some()
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
            message: if admin { "Pwn3d!".to_string() } else { "Authenticated".to_string() },
            error_code: None,
        }
    }

    pub fn failure(message: &str, code: Option<&str>) -> Self {
        Self {
            success: false,
            admin: false,
            message: message.to_string(),
            error_code: code.map(String::from),
        }
    }
}

impl fmt::Display for AuthResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = &self.message;
        if self.success {
            if self.admin {
                write!(f, "[+] {msg} (Pwn3d!)")
            } else {
                write!(f, "[+] {msg}")
            }
        } else {
            write!(f, "[-] {msg}")
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
    fn test_credentials_password() {
        let cred = Credentials::password("alice", "P@ssw0rd123", Some("CORP"));
        assert_eq!(cred.username, "alice");
        assert_eq!(cred.password.as_deref(), Some("P@ssw0rd123"));
        assert_eq!(cred.domain.as_deref(), Some("CORP"));
        assert_eq!(cred.auth_method(), AuthMethod::Password);
        assert!(!cred.use_kerberos);
    }

    #[test]
    fn test_credentials_nt_hash() {
        let cred = Credentials::nt_hash("bob", "8846f7eaee8fb117ad06bdd830b7586c", None);
        assert_eq!(cred.username, "bob");
        assert_eq!(cred.nt_hash.as_deref(), Some("8846f7eaee8fb117ad06bdd830b7586c"));
        assert!(cred.domain.is_none());
        assert_eq!(cred.auth_method(), AuthMethod::NtHash);
    }

    #[test]
    fn test_credentials_aes_key() {
        let cred = Credentials::aes_key("charlie", "f0a1b2c3d4...", Some("CORP.LOCAL"));
        assert_eq!(cred.username, "charlie");
        assert_eq!(cred.aes_256_key.as_deref(), Some("f0a1b2c3d4..."));
        assert_eq!(cred.auth_method(), AuthMethod::AesKey);
    }

    #[test]
    fn test_credentials_ccache() {
        let cred = Credentials::ccache("dave", "/tmp/krb5cc_1000", Some("CORP"));
        assert_eq!(cred.ccache_path.as_deref(), Some("/tmp/krb5cc_1000"));
        assert_eq!(cred.auth_method(), AuthMethod::KerberosTgt);
    }

    #[test]
    fn test_credentials_certificate() {
        let cred = Credentials::certificate("eve", "eve.pfx", Some("CORP"));
        assert_eq!(cred.pfx_path.as_deref(), Some("eve.pfx"));
        assert_eq!(cred.auth_method(), AuthMethod::Certificate);
    }

    #[test]
    fn test_credentials_null_session() {
        let cred = Credentials::null_session();
        assert!(cred.username.is_empty());
        assert!(cred.domain.is_none());
        assert_eq!(cred.auth_method(), AuthMethod::NullSession);
    }

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
    fn test_auth_result_success_admin() {
        let res = AuthResult::success(true);
        assert!(res.success);
        assert!(res.admin);
        assert_eq!(res.message, "Pwn3d!");
        assert!(res.error_code.is_none());
    }

    #[test]
    fn test_auth_result_success_user() {
        let res = AuthResult::success(false);
        assert!(res.success);
        assert!(!res.admin);
        assert_eq!(res.message, "Authenticated");
    }

    #[test]
    fn test_auth_result_failure() {
        let res = AuthResult::failure("Logon Failure", Some("STATUS_LOGON_FAILURE"));
        assert!(!res.success);
        assert!(!res.admin);
        assert_eq!(res.message, "Logon Failure");
        assert_eq!(res.error_code.as_deref(), Some("STATUS_LOGON_FAILURE"));
    }

    #[test]
    fn test_auth_result_display() {
        let success = AuthResult::success(true);
        assert!(format!("{success}").contains("Pwn3d!"));

        let success_user = AuthResult::success(false);
        assert!(format!("{success_user}").contains("Authenticated"));

        let fail = AuthResult::failure("Bad creds", None);
        assert!(format!("{fail}").contains("[-] Bad creds"));
    }
}
