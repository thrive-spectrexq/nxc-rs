use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub mod anthropic;
pub mod gemini;
pub mod mock;
pub mod ollama;
pub mod openai;

pub use anthropic::AnthropicProvider;
pub use gemini::GeminiProvider;
pub use mock::MockAiProvider;
pub use ollama::OllamaProvider;
pub use openai::OpenAiProvider;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiResponse {
    pub text: Option<String>,
    pub tool_calls: Vec<ToolCall>,
}

#[async_trait]
pub trait AiProvider: Send + Sync {
    /// Name of the provider.
    fn name(&self) -> &'static str;

    /// Send a prompt to the LLM with optional tool definitions.
    async fn complete(
        &self,
        system_prompt: &str,
        user_prompt: &str,
        history: &[Message],
        tools: &[ToolDefinition],
    ) -> Result<AiResponse>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    pub content: String,
    pub tool_calls: Option<Vec<ToolCall>>,
    pub tool_results: Option<Vec<ToolResult>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub call_id: String,
    pub content: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_debug_redacts_keys() {
        let secret_key = "sk-proj-super-secret-api-key-that-must-never-leak";

        let oai = OpenAiProvider::new(secret_key.to_string(), Some("gpt-4o".to_string()));
        let debug_str = format!("{oai:?}");
        assert!(!debug_str.contains(secret_key));
        assert!(debug_str.contains("[REDACTED]"));

        let gemini =
            GeminiProvider::new(secret_key.to_string(), Some("gemini-2.0-flash".to_string()));
        let debug_str = format!("{gemini:?}");
        assert!(!debug_str.contains(secret_key));
        assert!(debug_str.contains("[REDACTED]"));

        let anthropic =
            AnthropicProvider::new(secret_key.to_string(), Some("claude-3-7".to_string()));
        let debug_str = format!("{anthropic:?}");
        assert!(!debug_str.contains(secret_key));
        assert!(debug_str.contains("[REDACTED]"));
    }
}
