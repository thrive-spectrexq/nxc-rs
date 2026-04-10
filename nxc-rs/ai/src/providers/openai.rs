use super::{AiProvider, AiResponse, Message, ToolDefinition};
use anyhow::{bail, Result};
use async_trait::async_trait;

pub struct OpenAiProvider {
    pub api_key: String,
    pub model: String,
}

impl OpenAiProvider {
    pub fn new(api_key: String, model: Option<String>) -> Self {
        Self { api_key, model: model.unwrap_or_else(|| "gpt-4o".to_string()) }
    }
}

#[async_trait]
impl AiProvider for OpenAiProvider {
    fn name(&self) -> &'static str {
        "openai"
    }

    async fn complete(
        &self,
        _system_prompt: &str,
        _user_prompt: &str,
        _history: &[Message],
        _tools: &[ToolDefinition],
    ) -> Result<AiResponse> {
        bail!("OpenAI provider is not yet fully implemented.")
    }
}
