use super::{AiProvider, AiResponse, Message, Role, ToolCall, ToolDefinition};
use anyhow::{Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;

pub struct OpenAiProvider {
    client: Client,
    pub api_key: String,
    pub model: String,
}

impl OpenAiProvider {
    pub fn new(api_key: String, model: Option<String>) -> Self {
        let model = model.unwrap_or_else(|| {
            std::env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4o".to_string())
        });
        Self { client: Client::new(), api_key, model }
    }
}

#[async_trait]
impl AiProvider for OpenAiProvider {
    fn name(&self) -> &'static str {
        "openai"
    }

    async fn complete(
        &self,
        system_prompt: &str,
        _user_prompt: &str,
        history: &[Message],
        tools: &[ToolDefinition],
    ) -> Result<AiResponse> {
        let url = "https://api.openai.com/v1/chat/completions";

        // Build messages array
        let mut messages = vec![json!({
            "role": "system",
            "content": system_prompt
        })];

        for msg in history {
            match msg.role {
                Role::System => {
                    messages.push(json!({ "role": "system", "content": msg.content }));
                }
                Role::User => {
                    messages.push(json!({ "role": "user", "content": msg.content }));
                }
                Role::Assistant => {
                    let mut m = json!({ "role": "assistant" });
                    if !msg.content.is_empty() {
                        m["content"] = json!(msg.content);
                    }
                    if let Some(tool_calls) = &msg.tool_calls {
                        let tcs: Vec<serde_json::Value> = tool_calls
                            .iter()
                            .map(|tc| {
                                json!({
                                    "id": tc.id,
                                    "type": "function",
                                    "function": {
                                        "name": tc.name,
                                        "arguments": tc.arguments
                                    }
                                })
                            })
                            .collect();
                        m["tool_calls"] = json!(tcs);
                    }
                    messages.push(m);
                }
                Role::Tool => {
                    if let Some(results) = &msg.tool_results {
                        for tr in results {
                            messages.push(json!({
                                "role": "tool",
                                "tool_call_id": tr.call_id,
                                "content": tr.content
                            }));
                        }
                    }
                }
            }
        }

        // Build request body
        let mut body = json!({
            "model": self.model,
            "messages": messages,
            "temperature": 0.7,
            "max_tokens": 8192,
        });

        // Add tools if provided
        if !tools.is_empty() {
            let openai_tools: Vec<serde_json::Value> = tools
                .iter()
                .map(|t| {
                    json!({
                        "type": "function",
                        "function": {
                            "name": t.name,
                            "description": t.description,
                            "parameters": t.parameters
                        }
                    })
                })
                .collect();
            body["tools"] = json!(openai_tools);
            body["tool_choice"] = json!("auto");
        }

        let resp = self
            .client
            .post(url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let err_text = resp.text().await?;
            anyhow::bail!("OpenAI API error ({status}): {err_text}");
        }

        let oai_resp: OpenAiResponse = resp.json().await?;

        let choice = oai_resp.choices.first().context("No choices in OpenAI response")?;
        let text = choice.message.content.clone();
        let mut tool_calls = Vec::new();

        if let Some(tcs) = &choice.message.tool_calls {
            for tc in tcs {
                tool_calls.push(ToolCall {
                    id: tc.id.clone(),
                    name: tc.function.name.clone(),
                    arguments: tc.function.arguments.clone(),
                });
            }
        }

        Ok(AiResponse { text, tool_calls })
    }
}

// ─── OpenAI Response Types ──────────────────────────────────────

#[derive(Deserialize, Debug)]
struct OpenAiResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize, Debug)]
struct Choice {
    message: ResponseMessage,
}

#[derive(Deserialize, Debug)]
struct ResponseMessage {
    content: Option<String>,
    tool_calls: Option<Vec<ResponseToolCall>>,
}

#[derive(Deserialize, Debug)]
struct ResponseToolCall {
    id: String,
    function: FunctionCall,
}

#[derive(Deserialize, Debug)]
struct FunctionCall {
    name: String,
    arguments: String,
}
