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

/// Generic protocol error for wrapping underlying errors.
#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("SMB Error: {0}")]
    Smb(#[from] SmbError),

    #[error("LDAP Error: {0}")]
    Ldap(#[from] LdapError),

    #[error("SSH Error: {0}")]
    Ssh(#[from] SshError),

    #[error("Generic protocol error: {0}")]
    Generic(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
