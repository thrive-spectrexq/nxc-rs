use crate::{CompletionResponse, Message, StopReason};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use futures::StreamExt;
use netsage_common::AppEvent;
use serde_json::json;
use tokio::sync::broadcast;

#[async_trait]
pub trait LlmClient: Send + Sync {
    async fn stream_completion(
        &self,
        messages: &[Message],
        tools: &[serde_json::Value],
        event_tx: &broadcast::Sender<AppEvent>,
    ) -> Result<CompletionResponse>;
}

pub struct AnthropicClient {
    pub api_key: String,
    pub model: String,
    pub client: reqwest::Client,
}

#[async_trait]
impl LlmClient for AnthropicClient {
    async fn stream_completion(
        &self,
        messages: &[Message],
        tools: &[serde_json::Value],
        event_tx: &broadcast::Sender<AppEvent>,
    ) -> Result<CompletionResponse> {
        let mut body = json!({
            "model": self.model,
            "max_tokens": 4096,
            "messages": messages,
            "stream": true,
        });

        if !tools.is_empty() {
            body["tools"] = json!(tools);
        }

        let response = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let err_text = response.text().await?;
            return Err(anyhow!("Anthropic API error: {}", err_text));
        }

        let mut stream = response.bytes_stream();
        let mut full_content = String::new();
        let tool_calls = Vec::new();
        let mut stop_reason = StopReason::EndTurn;

        let _ = event_tx.send(AppEvent::AgentThinking(true));

        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            let text = String::from_utf8_lossy(&chunk);

            for line in text.lines() {
                if let Some(data) = line.strip_prefix("data: ") {
                    if data == "[DONE]" {
                        break;
                    }

                    if let Ok(value) = serde_json::from_str::<serde_json::Value>(data) {
                        match value["type"].as_str() {
                            Some("content_block_delta") => {
                                if let Some(delta) = value["delta"]["text"].as_str() {
                                    full_content.push_str(delta);
                                    let _ = event_tx.send(AppEvent::AgentToken(delta.to_string()));
                                }
                            }
                            Some("message_delta") => {
                                if let Some(reason) = value["delta"]["stop_reason"].as_str() {
                                    if reason == "tool_use" {
                                        stop_reason = StopReason::ToolUse;
                                    }
                                }
                            }
                            // Handle tool use start/delta if needed
                            _ => {}
                        }
                    }
                }
            }
        }

        let _ = event_tx.send(AppEvent::AgentThinking(false));

        Ok(CompletionResponse {
            content: full_content,
            tool_calls, // Simplified tool call parsing for this iteration
            stop_reason,
        })
    }
}

pub struct OpenAiClient {
    pub api_key: String,
    pub model: String,
    pub client: reqwest::Client,
}

#[async_trait]
impl LlmClient for OpenAiClient {
    async fn stream_completion(
        &self,
        _messages: &[Message],
        _tools: &[serde_json::Value],
        _tx: &broadcast::Sender<AppEvent>,
    ) -> Result<CompletionResponse> {
        // Implementation for OpenAI SSE
        todo!()
    }
}

pub struct GeminiClient {
    pub api_key: String,
    pub model: String,
    pub client: reqwest::Client,
}

#[async_trait]
impl LlmClient for GeminiClient {
    async fn stream_completion(
        &self,
        _messages: &[Message],
        _tools: &[serde_json::Value],
        _tx: &broadcast::Sender<AppEvent>,
    ) -> Result<CompletionResponse> {
        // Implementation for Gemini Streaming
        todo!()
    }
}
