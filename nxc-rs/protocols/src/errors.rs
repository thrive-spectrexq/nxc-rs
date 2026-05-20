//! # Protocol Error Types
//!
//! Structured error types for the various protocols supported by NetExec-RS,
//! leveraging `thiserror` for better error matching and reporting.

use thiserror::Error;

/// Errors that can occur during SMB authentication and execution.
#[derive(Error, Debug)]
pub enum SmbError {
    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Share access denied: {0}")]
    AccessDenied(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Execution failed: {0}")]
    ExecutionFailed(String),

    #[error("Unsupported feature: {0}")]
    Unsupported(String),

    #[error("Unknown SMB error: {0}")]
    Unknown(String),
}

/// Errors that can occur during LDAP authentication and querying.
#[derive(Error, Debug)]
pub enum LdapError {
    #[error("Bind failed: {0}")]
    BindFailed(String),

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Search query failed: {0}")]
    SearchFailed(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Unknown LDAP error: {0}")]
    Unknown(String),
}

/// Errors that can occur during SSH authentication and execution.
#[derive(Error, Debug)]
pub enum SshError {
    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Command execution failed: {0}")]
    ExecutionFailed(String),

    #[error("Key exchange failed: {0}")]
    KeyExchangeFailed(String),

    #[error("Unknown SSH error: {0}")]
    Unknown(String),
}

/// Errors that can occur during WinRM authentication and execution.
#[derive(Error, Debug)]
pub enum WinRmError {
    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Execution failed: {0}")]
    ExecutionFailed(String),

    #[error("Unknown WinRM error: {0}")]
    Unknown(String),
}

/// Errors that can occur during MSSQL authentication and querying.
#[derive(Error, Debug)]
pub enum MssqlError {
    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Query failed: {0}")]
    QueryFailed(String),

    #[error("Unknown MSSQL error: {0}")]
    Unknown(String),
}

/// Generic protocol error for wrapping underlying errors.
#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("SMB Error: {0}")]
    Smb(#[from] SmbError),

    #[error("LDAP Error: {0}")]
    Ldap(#[from] LdapError),

    #[error("SSH Error: {0}")]
    Ssh(#[from] SshError),

    #[error("WinRM Error: {0}")]
    WinRm(#[from] WinRmError),

    #[error("MSSQL Error: {0}")]
    Mssql(#[from] MssqlError),

    #[error("Generic protocol error: {0}")]
    Generic(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl ProtocolError {
    /// Returns true if the error is an authentication failure (e.g., bad password).
    pub fn is_auth_failure(&self) -> bool {
        matches!(
            self,
            Self::Smb(SmbError::AuthFailed(_))
                | Self::Ldap(LdapError::BindFailed(_))
                | Self::Ssh(SshError::AuthFailed(_))
                | Self::WinRm(WinRmError::AuthFailed(_))
                | Self::Mssql(MssqlError::AuthFailed(_))
        )
    }

    /// Returns true if the error is a network connection failure (e.g., unreachable, timeout).
    pub fn is_connection_failure(&self) -> bool {
        matches!(
            self,
            Self::Smb(SmbError::ConnectionFailed(_))
                | Self::Ldap(LdapError::ConnectionFailed(_))
                | Self::Ssh(SshError::ConnectionFailed(_))
                | Self::WinRm(WinRmError::ConnectionFailed(_))
                | Self::Mssql(MssqlError::ConnectionFailed(_))
        )
    }
}
