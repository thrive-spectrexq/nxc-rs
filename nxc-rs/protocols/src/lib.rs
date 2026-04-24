//! # nxc-protocols — NetExec-RS Protocol Handlers
//!
//! Each protocol (SMB, LDAP, WinRM, etc.) implements the `NxcProtocol` trait,
//! providing connect, authenticate, and execute capabilities.

use anyhow::Result;
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use serde::{Deserialize, Serialize};

pub mod ad_setup;
pub mod adb;
pub mod connection;
pub mod dns;
pub mod docker;
pub mod errors;
pub mod ftp;
pub mod http;
pub mod ilo;
pub mod ipmi;
pub mod kube;
pub mod ldap;
pub mod mssql;
pub mod mysql;
pub mod network;
pub mod nfs;
pub mod obfuscation;
#[cfg(feature = "opcua-support")]
pub mod opcua;
pub mod postgresql;
pub mod rdp;
pub mod redis;
pub mod rpc;
pub mod smb;
pub mod snmp;
pub mod socks;
pub mod ssh;
pub mod vnc;
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
    async fn connect(
        &self,
        target: &str,
        port: u16,
        proxy: Option<&str>,
    ) -> Result<Box<dyn NxcSession>>;

    /// Authenticate an existing session.
    async fn authenticate(
        &self,
        session: &mut dyn NxcSession,
        creds: &Credentials,
    ) -> Result<AuthResult>;

    /// Execute a command on an authenticated session.
    async fn execute(&self, session: &dyn NxcSession, cmd: &str) -> Result<CommandOutput>;

    /// Read a file from the target.
    async fn read_file(
        &self,
        _session: &dyn NxcSession,
        _share: &str,
        _path: &str,
    ) -> Result<Vec<u8>> {
        Err(anyhow::anyhow!("File read not supported for this protocol"))
    }

    /// Write a file to the target.
    async fn write_file(
        &self,
        _session: &dyn NxcSession,
        _share: &str,
        _path: &str,
        _data: &[u8],
    ) -> Result<()> {
        Err(anyhow::anyhow!("File write not supported for this protocol"))
    }
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
    Network,
    Http,
    Redis,
    Postgres,
    Mysql,
    Snmp,
    Docker,
    Dns,
    Ipmi,
    Ilo,
    Kube,
    OpcUa,
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
            Protocol::Network => "network",
            Protocol::Http => "http",
            Protocol::Redis => "redis",
            Protocol::Postgres => "postgres",
            Protocol::Mysql => "mysql",
            Protocol::Snmp => "snmp",
            Protocol::Docker => "docker",
            Protocol::Dns => "dns",
            Protocol::Ipmi => "ipmi",
            Protocol::Ilo => "ilo",
            Protocol::Kube => "kube",
            Protocol::OpcUa => "opcua",
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
            Protocol::Network => 0,
            Protocol::Http => 80,
            Protocol::Redis => 6379,
            Protocol::Postgres => 5432,
            Protocol::Mysql => 3306,
            Protocol::Snmp => 161,
            Protocol::Docker => 2375,
            Protocol::Dns => 53,
            Protocol::Ipmi => 623,
            Protocol::Ilo => 443,
            Protocol::Kube => 6443,
            Protocol::OpcUa => 4840,
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
            "network" | "net" | "wifi" => Some(Protocol::Network),
            "http" => Some(Protocol::Http),
            "redis" => Some(Protocol::Redis),
            "postgres" | "postgresql" => Some(Protocol::Postgres),
            "mysql" => Some(Protocol::Mysql),
            "snmp" => Some(Protocol::Snmp),
            "docker" => Some(Protocol::Docker),
            "dns" => Some(Protocol::Dns),
            "ipmi" => Some(Protocol::Ipmi),
            "ilo" | "idrac" | "bmc" => Some(Protocol::Ilo),
            "kube" | "kubernetes" | "k8s" => Some(Protocol::Kube),
            "opcua" | "opc" => Some(Protocol::OpcUa),
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
            Protocol::Network,
            Protocol::Http,
            Protocol::Redis,
            Protocol::Postgres,
            Protocol::Mysql,
            Protocol::Snmp,
            Protocol::Docker,
            Protocol::Dns,
            Protocol::Ipmi,
            Protocol::Ilo,
            Protocol::Kube,
            Protocol::OpcUa,
        ]
    }
}
