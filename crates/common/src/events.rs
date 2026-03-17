use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AppEvent {
    // Agent events
    AgentThinking(bool),
    AgentToken(String),
    AgentToolCall {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    AgentToolResult {
        id: String,
        result: serde_json::Value,
    },
    AgentDone(String),
    AgentError(String),
    // TUI commands
    UserInput(String),
    ApprovalResponse(bool),
    ToggleTopology,
    ExportSession,
    ClearHistory,
    Quit,
    // Capture events
    PacketCaptured(PacketSummary),
    CaptureStarted {
        iface: String,
    },
    CaptureStopped,
    // Session events
    SessionCreated(Uuid),
    AuditEntry(AuditRecord),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketSummary {
    pub timestamp: DateTime<Utc>,
    pub length: u32,
    pub protocol: String,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub tool_name: String,
    pub approved: bool,
    pub duration_ms: u64,
}
