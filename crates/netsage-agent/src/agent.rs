use crate::{ApprovalMode, ClaudeRequest, Message, Provider};
use anyhow::Result;
use netsage_pybridge::PythonBridge;
use netsage_session::SessionStore;
use reqwest::Client;
use serde_json::{json, Value};
use tracing::{info, warn};
use uuid::Uuid;

pub struct Agent {
    client: Client,
    api_key: String,
    model: String,
    provider: Provider,
    mode: ApprovalMode,
    session_store: SessionStore,
}

impl Agent {
    pub fn new(
        api_key: String,
        model: String,
        provider: Provider,
        mode: ApprovalMode,
        session_store: SessionStore,
    ) -> Self {
        Self {
            client: Client::new(),
            api_key,
            model,
            provider,
            mode,
            session_store,
        }
    }

    pub async fn handle_tool_call(
        &self,
        bridge: &mut PythonBridge,
        name: &str,
        args: Value,
    ) -> Result<Value> {
        let call_id = Uuid::new_v4().to_string();

        info!("Handling tool call: {} (id: {})", name, call_id);

        match self.mode {
            ApprovalMode::ReadOnly => {
                warn!("Blocked tool call in ReadOnly mode: {}", name);
                anyhow::bail!("Tool execution not allowed in Read-Only mode");
            }
            ApprovalMode::Supervised => {
                info!("Requesting approval for tool: {}", name);
            }
            ApprovalMode::Autonomous => {
                info!("Auto-approving tool: {}", name);
            }
        }

        self.session_store
            .log_tool_call(&call_id, name, &args, "pending")?;

        let result = bridge.call_tool(name, args).await?;

        self.session_store.update_tool_result(&call_id, &result)?;

        Ok(result)
    }

    pub async fn chat(&self, messages: Vec<Message>) -> Result<String> {
        match self.provider {
            Provider::Anthropic => self.call_anthropic(messages).await,
            Provider::OpenAI => self.call_openai(messages).await,
            Provider::Gemini => self.call_gemini(messages).await,
        }
    }

    async fn call_anthropic(&self, messages: Vec<Message>) -> Result<String> {
        let request = json!({
            "model": self.model,
            "messages": messages,
            "max_tokens": 1024,
        });

        let response = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .json(&request)
            .send()
            .await?;

        let res_json: Value = response.json().await?;
        Ok(res_json["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_string())
    }

    async fn call_openai(&self, messages: Vec<Message>) -> Result<String> {
        let request = json!({
            "model": self.model,
            "messages": messages,
        });

        let response = self
            .client
            .post("https://api.openai.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&request)
            .send()
            .await?;

        let res_json: Value = response.json().await?;
        Ok(res_json["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("")
            .to_string())
    }

    async fn call_gemini(&self, messages: Vec<Message>) -> Result<String> {
        let contents: Vec<Value> = messages
            .iter()
            .map(|m| {
                json!({
                    "role": if m.role == "user" { "user" } else { "model" },
                    "parts": [{"text": m.content}]
                })
            })
            .collect();

        let request = json!({ "contents": contents });
        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
            self.model, self.api_key
        );

        let response = self.client.post(url).json(&request).send().await?;

        let res_json: Value = response.json().await?;
        Ok(res_json["candidates"][0]["content"]["parts"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_string())
    }
}
