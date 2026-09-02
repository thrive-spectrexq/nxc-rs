use super::{AiProvider, AiResponse, Message, Role, ToolCall, ToolDefinition};
use anyhow::{Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;

pub struct GeminiProvider {
    client: Client,
    api_key: String,
    model: String,
}

impl std::fmt::Debug for GeminiProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeminiProvider")
            .field("model", &self.model)
            .field("api_key", &"[REDACTED]")
            .finish()
    }
}

impl GeminiProvider {
    pub fn new(api_key: String, model: Option<String>) -> Self {
        let model = model.unwrap_or_else(|| {
            std::env::var("GEMINI_MODEL").unwrap_or_else(|_| "gemini-2.0-flash".to_string())
        });
        Self { client: Client::new(), api_key, model }
    }
}

#[async_trait]
impl AiProvider for GeminiProvider {
    fn name(&self) -> &'static str {
        "gemini"
    }

    async fn complete(
        &self,
        system_prompt: &str,
        _user_prompt: &str,
        history: &[Message],
        tools: &[ToolDefinition],
    ) -> Result<AiResponse> {
        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent",
            self.model
        );

        let mut contents = Vec::new();

        // System instruction is handled separately in Gemini v1beta
        // But for simplicity/compatibility we can prepended to history if needed,
        // however Gemini has a system_instruction field.

        for msg in history {
            let role = match msg.role {
                Role::User => "user",
                Role::Assistant => "model",
                Role::System => "user", // Treated as user if not in system_instruction
                Role::Tool => "function",
            };

            let mut parts = Vec::new();
            if !msg.content.is_empty() {
                parts.push(json!({ "text": msg.content }));
            }

            if let Some(tool_calls) = &msg.tool_calls {
                for tc in tool_calls {
                    parts.push(json!({
                        "function_call": {
                            "name": tc.name,
                            "args": serde_json::from_str::<serde_json::Value>(&tc.arguments).unwrap_or(json!({}))
                        }
                    }));
                }
            }

            if let Some(tool_results) = &msg.tool_results {
                for tr in tool_results {
                    parts.push(json!({
                        "function_response": {
                            "name": tr.call_id, // In this agent, tr.call_id is actually the tool name used in mod.rs:99
                            "response": { "result": tr.content }
                        }
                    }));
                }
            }

            if !parts.is_empty() {
                contents.push(json!({
                    "role": role,
                    "parts": parts
                }));
            }
        }

        // The current user prompt is now assumed to be part of the history (the final message)
        // or passed via history if we modified AiAgent to push it first.

        let mut body = json!({
            "contents": contents,
            "system_instruction": {
                "parts": [{"text": system_prompt}]
            },
            "generationConfig": {
                "temperature": 0.7,
                "topK": 40,
                "topP": 0.95,
                "maxOutputTokens": 8192,
            }
        });

        if !tools.is_empty() {
            let mut gemini_tools = Vec::new();
            for t in tools {
                gemini_tools.push(json!({
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters
                }));
            }
            body["tools"] = json!([{ "function_declarations": gemini_tools }]);
        }

        let mut attempts = 0;
        let max_attempts = 3;
        let mut backoff = std::time::Duration::from_millis(500);

        let resp = loop {
            attempts += 1;
            match self
                .client
                .post(&url)
                .header("x-goog-api-key", &self.api_key)
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
                        tracing::warn!("Gemini API status {status}; retrying in {:?}", backoff);
                        tokio::time::sleep(backoff).await;
                        backoff *= 2;
                        continue;
                    }
                    let err_text =
                        resp.text().await.unwrap_or_else(|_| "Unknown error".to_string());
                    let safe_err = err_text.replace(&self.api_key, "[REDACTED]");
                    anyhow::bail!("Gemini API error ({status}): {safe_err}");
                }
                Err(e) => {
                    if attempts < max_attempts {
                        tracing::warn!("Gemini request error: {e}; retrying in {:?}", backoff);
                        tokio::time::sleep(backoff).await;
                        backoff *= 2;
                        continue;
                    }
                    anyhow::bail!("Gemini connection error after {attempts} attempts: {e}");
                }
            }
        };

        let gemini_resp: GeminiResponse = resp.json().await?;

        let candidate =
            gemini_resp.candidates.first().context("No candidates in Gemini response")?;
        let mut text: Option<String> = None;
        let mut tool_calls = Vec::new();

        for part in &candidate.content.parts {
            if let Some(t) = &part.text {
                text = Some(t.clone());
            }
            if let Some(fc) = &part.function_call {
                tool_calls.push(ToolCall {
                    id: uuid::Uuid::new_v4().to_string(),
                    name: fc.name.clone(),
                    arguments: fc.args.to_string(),
                });
            }
        }

        Ok(AiResponse { text, tool_calls })
    }
}

#[derive(Deserialize, Debug)]
struct GeminiResponse {
    candidates: Vec<Candidate>,
}

#[derive(Deserialize, Debug)]
struct Candidate {
    content: Content,
}

#[derive(Deserialize, Debug)]
struct Content {
    parts: Vec<Part>,
}

#[derive(Deserialize, Debug)]
struct Part {
    text: Option<String>,
    #[serde(rename = "functionCall")]
    function_call: Option<FunctionCall>,
}

#[derive(Deserialize, Debug)]
struct FunctionCall {
    name: String,
    args: serde_json::Value,
}
