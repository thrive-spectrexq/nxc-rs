use super::{AiProvider, AiResponse, Message, Role, ToolCall, ToolDefinition};
use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;

pub struct OllamaProvider {
    client: Client,
    pub api_base: String,
    pub model: String,
}

impl std::fmt::Debug for OllamaProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OllamaProvider")
            .field("api_base", &self.api_base)
            .field("model", &self.model)
            .finish()
    }
}

impl OllamaProvider {
    pub fn new(api_base: String, model: Option<String>) -> Self {
        let model = model.unwrap_or_else(|| {
            std::env::var("OLLAMA_MODEL").unwrap_or_else(|_| "llama3.2".to_string())
        });
        Self { client: Client::new(), api_base, model }
    }
}

#[async_trait]
impl AiProvider for OllamaProvider {
    fn name(&self) -> &'static str {
        "ollama"
    }

    async fn complete(
        &self,
        system_prompt: &str,
        _user_prompt: &str,
        history: &[Message],
        tools: &[ToolDefinition],
    ) -> Result<AiResponse> {
        let url = format!("{}/api/chat", self.api_base.trim_end_matches('/'));

        // Build messages array (OpenAI-compatible format)
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
                                    "function": {
                                        "name": tc.name,
                                        "arguments": serde_json::from_str::<serde_json::Value>(&tc.arguments)
                                            .unwrap_or(json!({}))
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
                                "content": tr.content
                            }));
                        }
                    }
                }
            }
        }

        let mut body = json!({
            "model": self.model,
            "messages": messages,
            "stream": false,
            "options": {
                "temperature": 0.7,
                "num_predict": 8192
            }
        });

        // Add tools if provided (Ollama 0.5+ supports tool calling)
        if !tools.is_empty() {
            let ollama_tools: Vec<serde_json::Value> = tools
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
            body["tools"] = json!(ollama_tools);
        }

        let mut attempts = 0;
        let max_attempts = 3;
        let mut backoff = std::time::Duration::from_millis(500);

        let resp = loop {
            attempts += 1;
            match self
                .client
                .post(&url)
                .header("Content-Type", "application/json")
                .json(&body)
                .send()
                .await
            {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        break resp;
                    }
                    if attempts < max_attempts
                        && (status.as_u16() == 429 || status.is_server_error())
                    {
                        tracing::warn!("Ollama API status {status}; retrying in {:?}", backoff);
                        tokio::time::sleep(backoff).await;
                        backoff *= 2;
                        continue;
                    }
                    let err_text =
                        resp.text().await.unwrap_or_else(|_| "Unknown error".to_string());
                    anyhow::bail!("Ollama API error ({status}): {err_text}");
                }
                Err(e) => {
                    if attempts < max_attempts {
                        tracing::warn!("Ollama connection error: {e}; retrying in {:?}", backoff);
                        tokio::time::sleep(backoff).await;
                        backoff *= 2;
                        continue;
                    }
                    anyhow::bail!("Ollama connection failed after {attempts} attempts: {e}");
                }
            }
        };

        let ollama_resp: OllamaResponse = resp.json().await?;

        let text = if ollama_resp.message.content.is_empty() {
            None
        } else {
            Some(ollama_resp.message.content)
        };

        let mut tool_calls = Vec::new();
        if let Some(tcs) = &ollama_resp.message.tool_calls {
            for tc in tcs {
                tool_calls.push(ToolCall {
                    id: uuid::Uuid::new_v4().to_string(),
                    name: tc.function.name.clone(),
                    arguments: tc.function.arguments.to_string(),
                });
            }
        }

        Ok(AiResponse { text, tool_calls })
    }
}

// ─── Ollama Response Types ──────────────────────────────────────

#[derive(Deserialize, Debug)]
struct OllamaResponse {
    message: OllamaMessage,
}

#[derive(Deserialize, Debug)]
struct OllamaMessage {
    #[serde(default)]
    content: String,
    tool_calls: Option<Vec<OllamaToolCall>>,
}

#[derive(Deserialize, Debug)]
struct OllamaToolCall {
    function: OllamaFunction,
}

#[derive(Deserialize, Debug)]
struct OllamaFunction {
    name: String,
    arguments: serde_json::Value,
}
