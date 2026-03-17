use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetSageConfig {
    pub core: CoreConfig,
    pub agent: AgentConfig,
    pub capture: CaptureConfig,
    pub session: SessionConfig,
    pub tui: TuiConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CoreConfig {
    pub provider: Provider,
    pub model: String,
    pub approval_mode: ApprovalMode,
    pub network_md: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    Anthropic,
    OpenAi,
    Gemini,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    ReadOnly,
    Supervised,
    Autonomous,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentConfig {
    pub max_tokens: u32,
    pub max_tool_iterations: u8,
    pub stream_timeout_secs: u64,
    pub system_prompt_extra: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CaptureConfig {
    pub default_interface: Option<String>,
    pub promiscuous: bool,
    pub snaplen: u32,
    pub max_packets_store: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SessionConfig {
    pub db_path: std::path::PathBuf,
    pub retain_days: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TuiConfig {
    pub theme: String,
    pub show_timestamps: bool,
    pub packet_viewer: bool,
    pub topology_view: bool,
    pub refresh_rate_ms: u64,
}
