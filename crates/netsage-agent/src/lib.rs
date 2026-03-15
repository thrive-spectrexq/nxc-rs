pub mod agent;
pub use agent::Agent;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq)]
pub enum Provider {
    Anthropic,
    OpenAI,
    Gemini,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq)]
pub enum ApprovalMode {
    ReadOnly,
    Supervised,
    Autonomous,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ToolUse {
    pub id: String,
    pub name: String,
    pub input: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ContentBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "tool_use")]
    ToolUse(ToolUse),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClaudeRequest {
    pub model: String,
    pub messages: Vec<Message>,
    pub max_tokens: u32,
    pub stream: bool,
    pub tools: Option<Vec<serde_json::Value>>,
}

// Phase 4: MCP (Model Context Protocol) Support
pub struct McpServer {
    pub name: String,
    pub version: String,
}

impl McpServer {
    pub fn new() -> Self {
        Self {
            name: "netsage-mcp".to_string(),
            version: "0.1.0".to_string(),
        }
    }
}
