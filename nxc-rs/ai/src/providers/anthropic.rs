use super::{AiProvider, AiResponse, Message, Role, ToolCall, ToolDefinition};
use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;

pub struct AnthropicProvider {
    client: Client,
    pub api_key: String,
    pub model: String,
}

impl AnthropicProvider {
    pub fn new(api_key: String, model: Option<String>) -> Self {
        let model = model.unwrap_or_else(|| {
            std::env::var("ANTHROPIC_MODEL")
                .unwrap_or_else(|_| "claude-sonnet-4-20250514".to_string())
        });
        Self { client: Client::new(), api_key, model }
    }
}

#[async_trait]
impl AiProvider for AnthropicProvider {
    fn name(&self) -> &'static str {
        "anthropic"
    }

    async fn complete(
        &self,
        system_prompt: &str,
        _user_prompt: &str,
        history: &[Message],
        tools: &[ToolDefinition],
    ) -> Result<AiResponse> {
        let url = "https://api.anthropic.com/v1/messages";

        // Build messages array (Anthropic format: user/assistant alternating)
        let mut messages = Vec::new();

        for msg in history {
            match msg.role {
                Role::System => {
                    // System messages are handled via the top-level `system` field
                    // If there are inline system messages, treat as user context
                    if !msg.content.is_empty() {
                        messages.push(json!({ "role": "user", "content": msg.content }));
                    }
                }
                Role::User => {
                    messages.push(json!({ "role": "user", "content": msg.content }));
                }
                Role::Assistant => {
                    let mut content_blocks: Vec<serde_json::Value> = Vec::new();
                    if !msg.content.is_empty() {
                        content_blocks.push(json!({ "type": "text", "text": msg.content }));
                    }
                    if let Some(tool_calls) = &msg.tool_calls {
                        for tc in tool_calls {
                            content_blocks.push(json!({
                                "type": "tool_use",
                                "id": tc.id,
                                "name": tc.name,
                                "input": serde_json::from_str::<serde_json::Value>(&tc.arguments)
                                    .unwrap_or(json!({}))
                            }));
                        }
                    }
                    messages.push(json!({ "role": "assistant", "content": content_blocks }));
                }
                Role::Tool => {
                    if let Some(results) = &msg.tool_results {
                        let content_blocks: Vec<serde_json::Value> = results
                            .iter()
                            .map(|tr| {
                                json!({
                                    "type": "tool_result",
                                    "tool_use_id": tr.call_id,
                                    "content": tr.content
                                })
                            })
                            .collect();
                        messages.push(json!({ "role": "user", "content": content_blocks }));
                    }
                }
            }
        }

        let mut body = json!({
            "model": self.model,
            "max_tokens": 8192,
            "system": system_prompt,
            "messages": messages,
        });

        // Add tools if provided
        if !tools.is_empty() {
            let anthropic_tools: Vec<serde_json::Value> = tools
                .iter()
                .map(|t| {
                    json!({
                        "name": t.name,
                        "description": t.description,
                        "input_schema": t.parameters
                    })
                })
                .collect();
            body["tools"] = json!(anthropic_tools);
        }

        let resp = self
            .client
            .post(url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let err_text = resp.text().await?;
            anyhow::bail!("Anthropic API error ({status}): {err_text}");
        }

        let anth_resp: AnthropicResponse = resp.json().await?;

        let mut text: Option<String> = None;
        let mut tool_calls = Vec::new();

        for block in &anth_resp.content {
            match block.content_type.as_str() {
                "text" => {
                    text = block.text.clone();
                }
                "tool_use" => {
                    if let (Some(id), Some(name), Some(input)) =
                        (&block.id, &block.name, &block.input)
                    {
                        tool_calls.push(ToolCall {
                            id: id.clone(),
                            name: name.clone(),
                            arguments: input.to_string(),
                        });
                    }
                }
                _ => {}
            }
        }

        Ok(AiResponse { text, tool_calls })
    }
}

// ─── Anthropic Response Types ───────────────────────────────────

#[derive(Deserialize, Debug)]
struct AnthropicResponse {
    content: Vec<ContentBlock>,
}

#[derive(Deserialize, Debug)]
struct ContentBlock {
    #[serde(rename = "type")]
    content_type: String,
    text: Option<String>,
    id: Option<String>,
    name: Option<String>,
    input: Option<serde_json::Value>,
}
