/// NxcError — errors specific to NetExec-RS operations.
#[derive(Debug, thiserror::Error)]
pub enum NxcError {
    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Connection refused to {host}:{port}")]
    ConnectionRefused { host: String, port: u16 },

    #[error("Connection timeout to {host}:{port}")]
    ConnectionTimeout { host: String, port: u16 },

    #[error("Module error in {module}: {message}")]
    ModuleError { module: String, message: String },

    #[error("Target parse error: {0}")]
    TargetParseError(String),

    #[error("Credential error: {0}")]
    CredentialError(String),

    #[error("Account locked out: {0}")]
    AccountLockedOut(String),

    #[error("Database error: {0}")]
    DatabaseError(String),
}

/// NxcEvent — events emitted by NetExec-RS operations.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum NxcEvent {
    /// An authentication attempt was made.
    AuthAttempt {
        protocol: String,
        target: String,
        username: String,
    },
    /// Authentication result received.
    AuthResult {
        protocol: String,
        target: String,
        username: String,
        success: bool,
        admin: bool,
        message: String,
    },
    /// Module execution completed.
    ModuleResult {
        protocol: String,
        target: String,
        module: String,
        success: bool,
        output: String,
    },
    /// Spray progress update.
    SprayProgress {
        completed: usize,
        total: usize,
        successes: usize,
        failures: usize,
    },
    /// New host discovered.
    HostDiscovered {
        ip: String,
        hostname: Option<String>,
        os: Option<String>,
    },
    /// Credential found.
    CredentialFound {
        domain: Option<String>,
        username: String,
        source: String,
    },
}
