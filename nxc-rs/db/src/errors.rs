use thiserror::Error;

/// Structured database errors for `nxc-db`.
#[derive(Debug, Error)]
pub enum DbError {
    #[error("SQLite database error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("Connection pool error: {0}")]
    Pool(#[from] r2d2::Error),

    #[error("Schema initialization failed: {0}")]
    SchemaInitFailed(String),

    #[error("Host not found: {0}")]
    HostNotFound(String),

    #[error("Credential not found for ID: {0}")]
    CredentialNotFound(i64),

    #[error("Workspace error: {0}")]
    WorkspaceError(String),

    #[error("Serialization / Deserialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
