#[derive(Debug, thiserror::Error)]
pub enum NetSageError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("LLM provider error: {0}")]
    Llm(String),
    #[error("tool execution failed: {tool} — {reason}")]
    Tool { tool: String, reason: String },
    #[error("packet capture error: {0}")]
    Capture(String),
    #[error("session storage error: {0}")]
    Session(#[from] rusqlite::Error),
    #[error("network I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("approval denied by user")]
    ApprovalDenied,
    #[error("operation cancelled")]
    Cancelled,
}

pub type Result<T> = std::result::Result<T, NetSageError>;
