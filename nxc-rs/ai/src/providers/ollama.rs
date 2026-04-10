use super::{AiProvider, AiResponse, Message, ToolDefinition};
use anyhow::{bail, Result};
use async_trait::async_trait;

pub struct OllamaProvider {
    pub api_base: String,
    pub model: String,
}

impl OllamaProvider {
    pub fn new(api_base: String, model: Option<String>) -> Self {
        Self { api_base, model: model.unwrap_or_else(|| "llama3.2".to_string()) }
    }
}

#[async_trait]
impl AiProvider for OllamaProvider {
    fn name(&self) -> &'static str {
        "ollama"
    }

    async fn complete(
        &self,
        _system_prompt: &str,
        _user_prompt: &str,
        _history: &[Message],
        _tools: &[ToolDefinition],
    ) -> Result<AiResponse> {
        bail!("Ollama provider is not yet fully implemented.")
    }
}
