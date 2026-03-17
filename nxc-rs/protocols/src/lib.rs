//! # nxc-protocols — NetExec-RS Protocol Handlers
//!
//! Each protocol (SMB, LDAP, WinRM, etc.) implements the `NxcProtocol` trait,
//! providing connect, authenticate, and execute capabilities.

use anyhow::Result;
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use serde::{Deserialize, Serialize};

pub mod smb;
pub mod ssh;
pub mod ldap;
pub mod mssql;
pub mod winrm;
pub mod rdp;
pub mod wmi;

// ─── Core Traits ────────────────────────────────────────────────

/// Trait for an active protocol session.
pub trait NxcSession: Send + Sync {
    /// Protocol name for this session.
    fn protocol(&self) -> &'static str;
    /// Target IP/hostname.
    fn target(&self) -> &str;
    /// Whether the session has admin privileges.
    fn is_admin(&self) -> bool;
}

/// Output from remote command execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
}

/// Protocol handler trait — implemented once per protocol.
#[async_trait]
pub trait NxcProtocol: Send + Sync {
    /// Protocol name (e.g. "smb", "ldap", "ssh").
    fn name(&self) -> &'static str;

    /// Default port for this protocol.
    fn default_port(&self) -> u16;

    /// Whether this protocol supports command execution.
    fn supports_exec(&self) -> bool {
        false
    }

    /// List of module names this protocol supports.
    fn supported_modules(&self) -> &[&str] {
        &[]
    }

    /// Connect to a target, returning a session handle.
    async fn connect(&self, target: &str, port: u16) -> Result<Box<dyn NxcSession>>;

    /// Authenticate an existing session.
    async fn authenticate(
        &self,
        session: &mut dyn NxcSession,
        creds: &Credentials,
    ) -> Result<AuthResult>;

    /// Execute a command on an authenticated session.
    async fn execute(&self, session: &dyn NxcSession, cmd: &str) -> Result<CommandOutput>;
}

// ─── Protocol Catalogue ─────────────────────────────────────────

/// Supported protocol identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    Smb,
    Ldap,
    WinRm,
    Wmi,
    Rdp,
    Mssql,
    Ssh,
    Ftp,
    Vnc,
    Nfs,
}

impl Protocol {
    pub fn name(&self) -> &'static str {
        match self {
            Protocol::Smb => "smb",
            Protocol::Ldap => "ldap",
            Protocol::WinRm => "winrm",
            Protocol::Wmi => "wmi",
            Protocol::Rdp => "rdp",
            Protocol::Mssql => "mssql",
            Protocol::Ssh => "ssh",
            Protocol::Ftp => "ftp",
            Protocol::Vnc => "vnc",
            Protocol::Nfs => "nfs",
        }
    }

    pub fn default_port(&self) -> u16 {
        match self {
            Protocol::Smb => 445,
            Protocol::Ldap => 389,
            Protocol::WinRm => 5985,
            Protocol::Wmi => 135,
            Protocol::Rdp => 3389,
            Protocol::Mssql => 1433,
            Protocol::Ssh => 22,
            Protocol::Ftp => 21,
            Protocol::Vnc => 5900,
            Protocol::Nfs => 2049,
        }
    }

    /// Parse a protocol name from CLI input.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "smb" => Some(Protocol::Smb),
            "ldap" | "ldaps" => Some(Protocol::Ldap),
            "winrm" => Some(Protocol::WinRm),
            "wmi" => Some(Protocol::Wmi),
            "rdp" => Some(Protocol::Rdp),
            "mssql" => Some(Protocol::Mssql),
            "ssh" => Some(Protocol::Ssh),
            "ftp" => Some(Protocol::Ftp),
            "vnc" => Some(Protocol::Vnc),
            "nfs" => Some(Protocol::Nfs),
            _ => None,
        }
    }
}
