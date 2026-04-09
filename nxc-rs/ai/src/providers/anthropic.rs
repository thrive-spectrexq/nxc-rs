use super::{AiProvider, AiResponse, Message, ToolDefinition};
use anyhow::{Result, bail};
use async_trait::async_trait;

pub struct AnthropicProvider {
    pub api_key: String,
    pub model: String,
}

impl AnthropicProvider {
    pub fn new(api_key: String, model: Option<String>) -> Self {
        Self {
            api_key,
            model: model.unwrap_or_else(|| "claude-3-5-sonnet-20241022".to_string()),
        }
    }
}

#[async_trait]
impl AiProvider for AnthropicProvider {
    fn name(&self) -> &'static str {
        "anthropic"
    }

    async fn complete(
        &self,
        _system_prompt: &str,
        _user_prompt: &str,
        _history: &[Message],
        _tools: &[ToolDefinition],
    ) -> Result<AiResponse> {
        bail!("Anthropic provider is not yet fully implemented.")
    }
}
