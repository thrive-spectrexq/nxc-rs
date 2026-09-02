//! Mock AI Provider for offline testing and verification.

use super::{AiProvider, AiResponse, Message, ToolDefinition};
use anyhow::Result;
use async_trait::async_trait;
use std::sync::{Arc, Mutex};

/// A mock AI provider that returns predefined responses or echoes tool calls.
#[derive(Debug, Clone)]
pub struct MockAiProvider {
    canned_responses: Arc<Mutex<Vec<AiResponse>>>,
    recorded_prompts: Arc<Mutex<Vec<String>>>,
}

impl Default for MockAiProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl MockAiProvider {
    pub fn new() -> Self {
        Self {
            canned_responses: Arc::new(Mutex::new(Vec::new())),
            recorded_prompts: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn with_responses(responses: Vec<AiResponse>) -> Self {
        Self {
            canned_responses: Arc::new(Mutex::new(responses)),
            recorded_prompts: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn add_response(&self, response: AiResponse) {
        if let Ok(mut lock) = self.canned_responses.lock() {
            lock.push(response);
        }
    }

    pub fn recorded_prompts(&self) -> Vec<String> {
        self.recorded_prompts.lock().map(|l| l.clone()).unwrap_or_default()
    }
}

#[async_trait]
impl AiProvider for MockAiProvider {
    fn name(&self) -> &'static str {
        "mock"
    }

    async fn complete(
        &self,
        _system_prompt: &str,
        user_prompt: &str,
        _history: &[Message],
        _tools: &[ToolDefinition],
    ) -> Result<AiResponse> {
        if let Ok(mut prompts) = self.recorded_prompts.lock() {
            prompts.push(user_prompt.to_string());
        }

        if let Ok(mut lock) = self.canned_responses.lock() {
            if !lock.is_empty() {
                return Ok(lock.remove(0));
            }
        }

        // Default offline response
        Ok(AiResponse {
            text: Some(format!("Mock response for: {user_prompt}")),
            tool_calls: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_provider_offline() {
        let provider = MockAiProvider::new();
        provider.add_response(AiResponse {
            text: Some("Simulated attack plan".to_string()),
            tool_calls: Vec::new(),
        });

        let resp = provider.complete("system", "audit domain", &[], &[]).await.unwrap();
        assert_eq!(resp.text.as_deref(), Some("Simulated attack plan"));
        assert_eq!(provider.recorded_prompts(), vec!["audit domain"]);
    }
}
