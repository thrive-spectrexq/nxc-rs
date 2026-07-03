//! # nxc-protocols — NetExec-RS Protocol Handlers
//!
//! Each protocol (SMB, LDAP, WinRM, etc.) implements the `NxcProtocol` trait,
//! providing connect, authenticate, and execute capabilities.

use std::fmt;
use std::str::FromStr;

use anyhow::Result;
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod ad_setup;
pub mod adb;
pub mod connection;
pub mod dns;
pub mod docker;
pub mod errors;
pub mod exchange;
pub mod ftp;
pub mod http;
pub mod ilo;
pub mod ipmi;
pub mod kube;
pub mod ldap;
pub mod modbus;
pub mod mqtt;
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
pub mod telnet;
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

/// Error returned when parsing an unrecognised protocol name.
#[derive(Debug, Clone, Error)]
#[error("unknown protocol: '{0}'")]
pub struct ProtocolParseError(pub String);

/// Supported protocol identifiers.
///
/// Each variant maps to a protocol handler that implements [`NxcProtocol`].
/// Use [`Protocol::ALL`] for the full list, or parse from a string via
/// the [`FromStr`] implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    /// Server Message Block — Windows file sharing and RPC.
    Smb,
    /// Lightweight Directory Access Protocol (includes LDAPS alias).
    Ldap,
    /// Windows Remote Management (WS-Management).
    WinRm,
    /// Windows Management Instrumentation (DCOM/RPC).
    Wmi,
    /// Remote Desktop Protocol.
    Rdp,
    /// Microsoft SQL Server.
    Mssql,
    /// Secure Shell.
    Ssh,
    /// File Transfer Protocol.
    Ftp,
    /// Virtual Network Computing (remote framebuffer).
    Vnc,
    /// Network File System.
    Nfs,
    /// Android Debug Bridge.
    Adb,
    /// Network / WiFi scanning and enumeration.
    Network,
    /// HTTP(S) web services.
    Http,
    /// Redis in-memory data store.
    Redis,
    /// PostgreSQL database.
    Postgres,
    /// MySQL / MariaDB database.
    Mysql,
    /// Simple Network Management Protocol.
    Snmp,
    /// Docker engine API.
    Docker,
    /// Domain Name System.
    Dns,
    /// Intelligent Platform Management Interface.
    Ipmi,
    /// HP iLO / Dell iDRAC / generic BMC.
    Ilo,
    /// Kubernetes API server.
    Kube,
    /// OPC Unified Architecture (industrial automation).
    OpcUa,
    /// Message Queuing Telemetry Transport (IoT messaging).
    Mqtt,
    /// Modbus industrial communication protocol.
    Modbus,
    /// Microsoft Exchange Web Services.
    Exchange,
    /// Telnet remote terminal.
    Telnet,
}

impl Protocol {
    /// All supported protocol variants.
    pub const ALL: &[Protocol] = &[
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
        Protocol::Mqtt,
        Protocol::Modbus,
        Protocol::Exchange,
        Protocol::Telnet,
    ];

    /// Canonical lowercase name of this protocol.
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
            Protocol::Mqtt => "mqtt",
            Protocol::Modbus => "modbus",
            Protocol::Exchange => "exchange",
            Protocol::Telnet => "telnet",
        }
    }

    /// Default port number for this protocol.
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
            Protocol::Mqtt => 1883,
            Protocol::Modbus => 502,
            Protocol::Exchange => 443,
            Protocol::Telnet => 23,
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Protocol {
    type Err = ProtocolParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "smb" => Ok(Protocol::Smb),
            "ldap" | "ldaps" => Ok(Protocol::Ldap),
            "winrm" => Ok(Protocol::WinRm),
            "wmi" => Ok(Protocol::Wmi),
            "rdp" => Ok(Protocol::Rdp),
            "mssql" => Ok(Protocol::Mssql),
            "ssh" => Ok(Protocol::Ssh),
            "ftp" => Ok(Protocol::Ftp),
            "vnc" => Ok(Protocol::Vnc),
            "nfs" => Ok(Protocol::Nfs),
            "adb" => Ok(Protocol::Adb),
            "network" | "net" | "wifi" => Ok(Protocol::Network),
            "http" => Ok(Protocol::Http),
            "redis" => Ok(Protocol::Redis),
            "postgres" | "postgresql" => Ok(Protocol::Postgres),
            "mysql" => Ok(Protocol::Mysql),
            "snmp" => Ok(Protocol::Snmp),
            "docker" => Ok(Protocol::Docker),
            "dns" => Ok(Protocol::Dns),
            "ipmi" => Ok(Protocol::Ipmi),
            "ilo" | "idrac" | "bmc" => Ok(Protocol::Ilo),
            "kube" | "kubernetes" | "k8s" => Ok(Protocol::Kube),
            "opcua" | "opc" => Ok(Protocol::OpcUa),
            "mqtt" => Ok(Protocol::Mqtt),
            "modbus" => Ok(Protocol::Modbus),
            "exchange" | "ews" => Ok(Protocol::Exchange),
            "telnet" => Ok(Protocol::Telnet),
            _ => Err(ProtocolParseError(s.to_owned())),
        }
    }
}
