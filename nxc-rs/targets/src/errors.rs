use thiserror::Error;

/// Typed errors for target parsing and execution in nxc-targets.
#[derive(Debug, Error)]
pub enum TargetError {
    #[error("Invalid CIDR notation '{spec}': {reason}")]
    InvalidCidr { spec: String, reason: String },

    #[error("Invalid IP range '{spec}': {reason}")]
    InvalidRange { spec: String, reason: String },

    #[error("Invalid IP address '{spec}': {source}")]
    InvalidIp {
        spec: String,
        #[source]
        source: std::net::AddrParseError,
    },

    #[error("Failed to read target file '{path}': {source}")]
    FileReadError {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Execution engine semaphore closed unexpectedly")]
    SemaphoreClosed,

    #[error("Protocol error during target execution: {0}")]
    Protocol(String),
}
