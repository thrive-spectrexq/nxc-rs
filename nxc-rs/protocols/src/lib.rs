//! # nxc-protocols — NetExec-RS Protocol Handlers
//!
//! Each protocol (SMB, LDAP, WinRM, etc.) implements the `NxcProtocol` trait,
//! providing connect, authenticate, and execute capabilities.

use anyhow::Result;
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use serde::{Deserialize, Serialize};

pub mod adb;
pub mod ftp;
pub mod http;
pub mod ldap;
pub mod mssql;
pub mod nfs;
pub mod rdp;
pub mod rpc;
pub mod smb;
pub mod ssh;
pub mod vnc;
pub mod wifi;
pub mod winrm;
pub mod wmi;

// ─── Core Traits ────────────────────────────────────────────────

/// Trait for an active protocol session.
pub trait NxcSession: Send + Sync + 'static {
    /// Protocol name for this session.
    fn protocol(&self) -> &'static str;
    /// Target IP/hostname.
    fn target(&self) -> &str;
    /// Whether the session has admin privileges.
    fn is_admin(&self) -> bool;
    fn as_any(&self) -> &dyn std::any::Any;
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;
}

impl dyn NxcSession {
    /// Downcast a trait object to a specific type (immutable).
    pub fn downcast_ref<T: 'static>(&self) -> Option<&T> {
        self.as_any().downcast_ref::<T>()
    }

    /// Downcast a trait object to a specific type (mutable).
    pub fn downcast_mut<T: 'static>(&mut self) -> Option<&mut T> {
        self.as_any_mut().downcast_mut::<T>()
    }
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
    Adb,
    Wifi,
    Http,
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
            Protocol::Adb => "adb",
            Protocol::Wifi => "wifi",
            Protocol::Http => "http",
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
            Protocol::Adb => 5555,
            Protocol::Wifi => 0,
            Protocol::Http => 80,
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
            "adb" => Some(Protocol::Adb),
            "wifi" => Some(Protocol::Wifi),
            "http" => Some(Protocol::Http),
            _ => None,
        }
    }

    /// Return all supported protocols.
    pub fn all() -> Vec<Self> {
        vec![
            Protocol::Smb,
            Protocol::Ldap,
            Protocol::WinRm,
            Protocol::Wmi,
            Protocol::Rdp,
            Protocol::Mssql,
            Protocol::Ssh,
            Protocol::Ftp,
            Protocol::Vnc,
            Protocol::Nfs,
            Protocol::Adb,
            Protocol::Wifi,
            Protocol::Http,
        ]
    }
}
