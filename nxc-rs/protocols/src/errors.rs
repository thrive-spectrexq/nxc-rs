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

/// Errors that can occur during FTP authentication and file operations.
#[derive(Error, Debug)]
pub enum FtpError {
    /// FTP login rejected (wrong user/password).
    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    /// TCP connection to the FTP server failed.
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    /// A file transfer (GET/PUT/LIST) failed.
    #[error("Transfer failed: {0}")]
    TransferFailed(String),

    /// FTP protocol-level error (unexpected reply code, etc.).
    #[error("Protocol error: {0}")]
    ProtocolError(String),

    /// Catch-all for unclassified FTP errors.
    #[error("Unknown FTP error: {0}")]
    Unknown(String),
}

/// Errors that can occur during RDP authentication and session handling.
#[derive(Error, Debug)]
pub enum RdpError {
    /// RDP/NLA authentication rejected.
    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    /// TCP connection to the RDP server failed.
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    /// TLS/CredSSP negotiation failed.
    #[error("Negotiation failed: {0}")]
    NegotiationFailed(String),

    /// RDP protocol-level error.
    #[error("Protocol error: {0}")]
    ProtocolError(String),

    /// Catch-all for unclassified RDP errors.
    #[error("Unknown RDP error: {0}")]
    Unknown(String),
}

/// Errors that can occur during VNC authentication and session handling.
#[derive(Error, Debug)]
pub enum VncError {
    /// VNC authentication rejected (bad password or security type mismatch).
    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    /// TCP connection to the VNC server failed.
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    /// RFB handshake or security negotiation failed.
    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    /// Catch-all for unclassified VNC errors.
    #[error("Unknown VNC error: {0}")]
    Unknown(String),
}

/// Errors that can occur during Redis authentication and command execution.
#[derive(Error, Debug)]
pub enum RedisError {
    /// Redis AUTH command rejected.
    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    /// TCP connection to the Redis server failed.
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    /// A Redis command returned an error.
    #[error("Command execution failed: {0}")]
    ExecutionFailed(String),

    /// Catch-all for unclassified Redis errors.
    #[error("Unknown Redis error: {0}")]
    Unknown(String),
}

/// Errors that can occur during Docker API operations.
#[derive(Error, Debug)]
pub enum DockerError {
    /// Docker API authentication/authorization failed.
    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    /// Connection to the Docker daemon failed.
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    /// Container or image operation failed.
    #[error("Execution failed: {0}")]
    ExecutionFailed(String),

    /// Docker API returned an error response.
    #[error("API error: {0}")]
    ApiError(String),

    /// Catch-all for unclassified Docker errors.
    #[error("Unknown Docker error: {0}")]
    Unknown(String),
}

/// Errors that can occur during Kubernetes API operations.
#[derive(Error, Debug)]
pub enum KubeError {
    /// Kubernetes API authentication/authorization failed.
    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    /// Connection to the Kubernetes API server failed.
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    /// Pod exec or command execution failed.
    #[error("Execution failed: {0}")]
    ExecutionFailed(String),

    /// Kubernetes API returned an error response.
    #[error("API error: {0}")]
    ApiError(String),

    /// Catch-all for unclassified Kubernetes errors.
    #[error("Unknown Kubernetes error: {0}")]
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

    /// FTP protocol errors.
    #[error("FTP Error: {0}")]
    Ftp(#[from] FtpError),

    /// RDP protocol errors.
    #[error("RDP Error: {0}")]
    Rdp(#[from] RdpError),

    /// VNC protocol errors.
    #[error("VNC Error: {0}")]
    Vnc(#[from] VncError),

    /// Redis protocol errors.
    #[error("Redis Error: {0}")]
    Redis(#[from] RedisError),

    /// Docker API errors.
    #[error("Docker Error: {0}")]
    Docker(#[from] DockerError),

    /// Kubernetes API errors.
    #[error("Kube Error: {0}")]
    Kube(#[from] KubeError),

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
                | Self::Ftp(FtpError::AuthFailed(_))
                | Self::Rdp(RdpError::AuthFailed(_))
                | Self::Vnc(VncError::AuthFailed(_))
                | Self::Redis(RedisError::AuthFailed(_))
                | Self::Docker(DockerError::AuthFailed(_))
                | Self::Kube(KubeError::AuthFailed(_))
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
                | Self::Ftp(FtpError::ConnectionFailed(_))
                | Self::Rdp(RdpError::ConnectionFailed(_))
                | Self::Vnc(VncError::ConnectionFailed(_))
                | Self::Redis(RedisError::ConnectionFailed(_))
                | Self::Docker(DockerError::ConnectionFailed(_))
                | Self::Kube(KubeError::ConnectionFailed(_))
        )
    }

    /// Returns true if the error is a command/query execution failure.
    pub fn is_execution_failure(&self) -> bool {
        matches!(
            self,
            Self::Smb(SmbError::ExecutionFailed(_))
                | Self::Ssh(SshError::ExecutionFailed(_))
                | Self::WinRm(WinRmError::ExecutionFailed(_))
                | Self::Mssql(MssqlError::QueryFailed(_))
                | Self::Redis(RedisError::ExecutionFailed(_))
                | Self::Docker(DockerError::ExecutionFailed(_))
                | Self::Kube(KubeError::ExecutionFailed(_))
        )
    }

    /// Returns the protocol name this error belongs to.
    pub fn protocol_name(&self) -> &'static str {
        match self {
            Self::Smb(_) => "smb",
            Self::Ldap(_) => "ldap",
            Self::Ssh(_) => "ssh",
            Self::WinRm(_) => "winrm",
            Self::Mssql(_) => "mssql",
            Self::Ftp(_) => "ftp",
            Self::Rdp(_) => "rdp",
            Self::Vnc(_) => "vnc",
            Self::Redis(_) => "redis",
            Self::Docker(_) => "docker",
            Self::Kube(_) => "kube",
            Self::Generic(_) | Self::Other(_) => "generic",
        }
    }
}

impl From<std::io::Error> for ProtocolError {
    fn from(err: std::io::Error) -> Self {
        Self::Generic(err.to_string())
    }
}

impl From<std::net::AddrParseError> for ProtocolError {
    fn from(err: std::net::AddrParseError) -> Self {
        Self::Generic(err.to_string())
    }
}

impl From<std::io::Error> for SmbError {
    fn from(err: std::io::Error) -> Self {
        Self::ConnectionFailed(err.to_string())
    }
}

impl From<std::io::Error> for LdapError {
    fn from(err: std::io::Error) -> Self {
        Self::ConnectionFailed(err.to_string())
    }
}

impl From<std::io::Error> for SshError {
    fn from(err: std::io::Error) -> Self {
        Self::ConnectionFailed(err.to_string())
    }
}

impl From<std::io::Error> for WinRmError {
    fn from(err: std::io::Error) -> Self {
        Self::ConnectionFailed(err.to_string())
    }
}

impl From<std::io::Error> for MssqlError {
    fn from(err: std::io::Error) -> Self {
        Self::ConnectionFailed(err.to_string())
    }
}

impl From<std::io::Error> for FtpError {
    fn from(err: std::io::Error) -> Self {
        Self::ConnectionFailed(err.to_string())
    }
}

impl From<std::io::Error> for RdpError {
    fn from(err: std::io::Error) -> Self {
        Self::ConnectionFailed(err.to_string())
    }
}

impl From<std::io::Error> for VncError {
    fn from(err: std::io::Error) -> Self {
        Self::ConnectionFailed(err.to_string())
    }
}

impl From<std::io::Error> for RedisError {
    fn from(err: std::io::Error) -> Self {
        Self::ConnectionFailed(err.to_string())
    }
}

impl From<std::io::Error> for DockerError {
    fn from(err: std::io::Error) -> Self {
        Self::ConnectionFailed(err.to_string())
    }
}

impl From<std::io::Error> for KubeError {
    fn from(err: std::io::Error) -> Self {
        Self::ConnectionFailed(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Auth failure detection ──────────────────────────────────

    #[test]
    fn smb_auth_is_auth_failure() {
        let err: ProtocolError = SmbError::AuthFailed("bad pw".into()).into();
        assert!(err.is_auth_failure());
        assert!(!err.is_connection_failure());
        assert!(!err.is_execution_failure());
    }

    #[test]
    fn ldap_bind_is_auth_failure() {
        let err: ProtocolError = LdapError::BindFailed("invalid creds".into()).into();
        assert!(err.is_auth_failure());
    }

    #[test]
    fn ftp_auth_is_auth_failure() {
        let err: ProtocolError = FtpError::AuthFailed("530 Login incorrect".into()).into();
        assert!(err.is_auth_failure());
    }

    #[test]
    fn rdp_auth_is_auth_failure() {
        let err: ProtocolError = RdpError::AuthFailed("NLA rejected".into()).into();
        assert!(err.is_auth_failure());
    }

    #[test]
    fn vnc_auth_is_auth_failure() {
        let err: ProtocolError = VncError::AuthFailed("bad password".into()).into();
        assert!(err.is_auth_failure());
    }

    #[test]
    fn redis_auth_is_auth_failure() {
        let err: ProtocolError = RedisError::AuthFailed("NOAUTH".into()).into();
        assert!(err.is_auth_failure());
    }

    #[test]
    fn docker_auth_is_auth_failure() {
        let err: ProtocolError = DockerError::AuthFailed("unauthorized".into()).into();
        assert!(err.is_auth_failure());
    }

    #[test]
    fn kube_auth_is_auth_failure() {
        let err: ProtocolError = KubeError::AuthFailed("forbidden".into()).into();
        assert!(err.is_auth_failure());
    }

    // ── Connection failure detection ────────────────────────────

    #[test]
    fn ssh_conn_is_connection_failure() {
        let err: ProtocolError = SshError::ConnectionFailed("timeout".into()).into();
        assert!(err.is_connection_failure());
        assert!(!err.is_auth_failure());
    }

    #[test]
    fn ftp_conn_is_connection_failure() {
        let err: ProtocolError = FtpError::ConnectionFailed("refused".into()).into();
        assert!(err.is_connection_failure());
    }

    #[test]
    fn rdp_conn_is_connection_failure() {
        let err: ProtocolError = RdpError::ConnectionFailed("timeout".into()).into();
        assert!(err.is_connection_failure());
    }

    #[test]
    fn docker_conn_is_connection_failure() {
        let err: ProtocolError =
            DockerError::ConnectionFailed("daemon not running".into()).into();
        assert!(err.is_connection_failure());
    }

    // ── Execution failure detection ─────────────────────────────

    #[test]
    fn smb_exec_is_execution_failure() {
        let err: ProtocolError = SmbError::ExecutionFailed("access denied".into()).into();
        assert!(err.is_execution_failure());
        assert!(!err.is_auth_failure());
    }

    #[test]
    fn ssh_exec_is_execution_failure() {
        let err: ProtocolError = SshError::ExecutionFailed("exit code 1".into()).into();
        assert!(err.is_execution_failure());
    }

    #[test]
    fn mssql_query_is_execution_failure() {
        let err: ProtocolError = MssqlError::QueryFailed("syntax error".into()).into();
        assert!(err.is_execution_failure());
    }

    #[test]
    fn redis_exec_is_execution_failure() {
        let err: ProtocolError = RedisError::ExecutionFailed("ERR unknown".into()).into();
        assert!(err.is_execution_failure());
    }

    #[test]
    fn kube_exec_is_execution_failure() {
        let err: ProtocolError = KubeError::ExecutionFailed("pod not found".into()).into();
        assert!(err.is_execution_failure());
    }

    // ── Protocol name resolution ────────────────────────────────

    #[test]
    fn protocol_name_returns_correct_names() {
        let cases: Vec<(ProtocolError, &str)> = vec![
            (SmbError::Unknown("x".into()).into(), "smb"),
            (LdapError::Unknown("x".into()).into(), "ldap"),
            (SshError::Unknown("x".into()).into(), "ssh"),
            (WinRmError::Unknown("x".into()).into(), "winrm"),
            (MssqlError::Unknown("x".into()).into(), "mssql"),
            (FtpError::Unknown("x".into()).into(), "ftp"),
            (RdpError::Unknown("x".into()).into(), "rdp"),
            (VncError::Unknown("x".into()).into(), "vnc"),
            (RedisError::Unknown("x".into()).into(), "redis"),
            (DockerError::Unknown("x".into()).into(), "docker"),
            (KubeError::Unknown("x".into()).into(), "kube"),
            (ProtocolError::Generic("x".into()), "generic"),
        ];
        for (err, expected) in cases {
            assert_eq!(err.protocol_name(), expected, "failed for {err}");
        }
    }

    // ── Non-auth errors should not be auth failures ─────────────

    #[test]
    fn protocol_error_is_not_auth_failure() {
        let err: ProtocolError = SmbError::ProtocolError("bad packet".into()).into();
        assert!(!err.is_auth_failure());
    }

    #[test]
    fn generic_is_not_any_category() {
        let err = ProtocolError::Generic("something".into());
        assert!(!err.is_auth_failure());
        assert!(!err.is_connection_failure());
        assert!(!err.is_execution_failure());
        assert_eq!(err.protocol_name(), "generic");
    }

    // ── From impls ──────────────────────────────────────────────

    #[test]
    fn from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        let err = ProtocolError::from(io_err);
        assert!(matches!(err, ProtocolError::Generic(_)));
    }

    #[test]
    fn from_addr_parse_error() {
        let parse_err: std::net::AddrParseError = "not-an-ip".parse::<std::net::IpAddr>()
            .err()
            .expect("test setup: should fail to parse");
        let err = ProtocolError::from(parse_err);
        assert!(matches!(err, ProtocolError::Generic(_)));
    }

    // ── Display formatting ──────────────────────────────────────

    #[test]
    fn display_includes_protocol_prefix() {
        let err: ProtocolError = FtpError::AuthFailed("530".into()).into();
        let msg = err.to_string();
        assert!(msg.contains("FTP Error:"), "expected 'FTP Error:' in: {msg}");
        assert!(msg.contains("Authentication failed: 530"), "expected inner error string in: {msg}");
    }

    #[test]
    fn smb_error_formatting() {
        assert_eq!(SmbError::AuthFailed("bad pw".into()).to_string(), "Authentication failed: bad pw");
        assert_eq!(SmbError::ConnectionFailed("timeout".into()).to_string(), "Connection failed: timeout");
        assert_eq!(SmbError::AccessDenied("share".into()).to_string(), "Share access denied: share");
        assert_eq!(SmbError::ProtocolError("invalid packet".into()).to_string(), "Protocol error: invalid packet");
        assert_eq!(SmbError::ExecutionFailed("crash".into()).to_string(), "Execution failed: crash");
        assert_eq!(SmbError::Unsupported("feature".into()).to_string(), "Unsupported feature: feature");
        assert_eq!(SmbError::Unknown("unknown".into()).to_string(), "Unknown SMB error: unknown");
        
        let proto: ProtocolError = SmbError::AuthFailed("bad pw".into()).into();
        assert_eq!(proto.to_string(), "SMB Error: Authentication failed: bad pw");
    }

    #[test]
    fn ldap_error_formatting() {
        assert_eq!(LdapError::BindFailed("invalid creds".into()).to_string(), "Bind failed: invalid creds");
        assert_eq!(LdapError::ConnectionFailed("timeout".into()).to_string(), "Connection failed: timeout");
        assert_eq!(LdapError::SearchFailed("bad query".into()).to_string(), "Search query failed: bad query");
        assert_eq!(LdapError::ProtocolError("invalid response".into()).to_string(), "Protocol error: invalid response");
        assert_eq!(LdapError::Unknown("unknown".into()).to_string(), "Unknown LDAP error: unknown");
        
        let proto: ProtocolError = LdapError::BindFailed("invalid creds".into()).into();
        assert_eq!(proto.to_string(), "LDAP Error: Bind failed: invalid creds");
    }

    #[test]
    fn ssh_error_formatting() {
        assert_eq!(SshError::AuthFailed("bad key".into()).to_string(), "Authentication failed: bad key");
        assert_eq!(SshError::ConnectionFailed("timeout".into()).to_string(), "Connection failed: timeout");
        assert_eq!(SshError::ExecutionFailed("crash".into()).to_string(), "Command execution failed: crash");
        assert_eq!(SshError::KeyExchangeFailed("bad algo".into()).to_string(), "Key exchange failed: bad algo");
        assert_eq!(SshError::Unknown("unknown".into()).to_string(), "Unknown SSH error: unknown");
        
        let proto: ProtocolError = SshError::AuthFailed("bad key".into()).into();
        assert_eq!(proto.to_string(), "SSH Error: Authentication failed: bad key");
    }

    #[test]
    fn winrm_error_formatting() {
        assert_eq!(WinRmError::AuthFailed("bad token".into()).to_string(), "Authentication failed: bad token");
        assert_eq!(WinRmError::ConnectionFailed("timeout".into()).to_string(), "Connection failed: timeout");
        assert_eq!(WinRmError::ExecutionFailed("crash".into()).to_string(), "Execution failed: crash");
        assert_eq!(WinRmError::Unknown("unknown".into()).to_string(), "Unknown WinRM error: unknown");
        
        let proto: ProtocolError = WinRmError::AuthFailed("bad token".into()).into();
        assert_eq!(proto.to_string(), "WinRM Error: Authentication failed: bad token");
    }

    #[test]
    fn mssql_error_formatting() {
        assert_eq!(MssqlError::AuthFailed("bad user".into()).to_string(), "Authentication failed: bad user");
        assert_eq!(MssqlError::ConnectionFailed("timeout".into()).to_string(), "Connection failed: timeout");
        assert_eq!(MssqlError::QueryFailed("syntax".into()).to_string(), "Query failed: syntax");
        assert_eq!(MssqlError::Unknown("unknown".into()).to_string(), "Unknown MSSQL error: unknown");
        
        let proto: ProtocolError = MssqlError::AuthFailed("bad user".into()).into();
        assert_eq!(proto.to_string(), "MSSQL Error: Authentication failed: bad user");
    }

    #[test]
    fn ftp_error_formatting() {
        assert_eq!(FtpError::AuthFailed("530".into()).to_string(), "Authentication failed: 530");
        assert_eq!(FtpError::ConnectionFailed("refused".into()).to_string(), "Connection failed: refused");
        assert_eq!(FtpError::TransferFailed("aborted".into()).to_string(), "Transfer failed: aborted");
        assert_eq!(FtpError::ProtocolError("bad code".into()).to_string(), "Protocol error: bad code");
        assert_eq!(FtpError::Unknown("unknown".into()).to_string(), "Unknown FTP error: unknown");
    }

    #[test]
    fn rdp_error_formatting() {
        assert_eq!(RdpError::AuthFailed("nla".into()).to_string(), "Authentication failed: nla");
        assert_eq!(RdpError::ConnectionFailed("refused".into()).to_string(), "Connection failed: refused");
        assert_eq!(RdpError::NegotiationFailed("tls".into()).to_string(), "Negotiation failed: tls");
        assert_eq!(RdpError::ProtocolError("bad packet".into()).to_string(), "Protocol error: bad packet");
        assert_eq!(RdpError::Unknown("unknown".into()).to_string(), "Unknown RDP error: unknown");
    }

    #[test]
    fn vnc_error_formatting() {
        assert_eq!(VncError::AuthFailed("bad pw".into()).to_string(), "Authentication failed: bad pw");
        assert_eq!(VncError::ConnectionFailed("refused".into()).to_string(), "Connection failed: refused");
        assert_eq!(VncError::HandshakeFailed("version".into()).to_string(), "Handshake failed: version");
        assert_eq!(VncError::Unknown("unknown".into()).to_string(), "Unknown VNC error: unknown");
    }

    #[test]
    fn redis_error_formatting() {
        assert_eq!(RedisError::AuthFailed("noauth".into()).to_string(), "Authentication failed: noauth");
        assert_eq!(RedisError::ConnectionFailed("refused".into()).to_string(), "Connection failed: refused");
        assert_eq!(RedisError::ExecutionFailed("err".into()).to_string(), "Command execution failed: err");
        assert_eq!(RedisError::Unknown("unknown".into()).to_string(), "Unknown Redis error: unknown");
    }

    #[test]
    fn docker_error_formatting() {
        assert_eq!(DockerError::AuthFailed("unauth".into()).to_string(), "Authentication failed: unauth");
        assert_eq!(DockerError::ConnectionFailed("refused".into()).to_string(), "Connection failed: refused");
        assert_eq!(DockerError::ExecutionFailed("crash".into()).to_string(), "Execution failed: crash");
        assert_eq!(DockerError::ApiError("404".into()).to_string(), "API error: 404");
        assert_eq!(DockerError::Unknown("unknown".into()).to_string(), "Unknown Docker error: unknown");
    }

    #[test]
    fn kube_error_formatting() {
        assert_eq!(KubeError::AuthFailed("forbidden".into()).to_string(), "Authentication failed: forbidden");
        assert_eq!(KubeError::ConnectionFailed("refused".into()).to_string(), "Connection failed: refused");
        assert_eq!(KubeError::ExecutionFailed("crash".into()).to_string(), "Execution failed: crash");
        assert_eq!(KubeError::ApiError("404".into()).to_string(), "API error: 404");
        assert_eq!(KubeError::Unknown("unknown".into()).to_string(), "Unknown Kubernetes error: unknown");
    }

    #[test]
    fn from_io_error_for_protocol_enums() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        let smb_err: SmbError = io_err.into();
        assert!(matches!(smb_err, SmbError::ConnectionFailed(msg) if msg == "refused"));

        let io_err2 = std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout");
        let ssh_err: SshError = io_err2.into();
        assert!(matches!(ssh_err, SshError::ConnectionFailed(msg) if msg == "timeout"));
    }
}
