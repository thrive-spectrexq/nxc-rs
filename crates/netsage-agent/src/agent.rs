use crate::{
    stream::{parse_sse_line, ClaudeEvent},
    ApprovalMode, Message, Persona, Provider,
};
use anyhow::{anyhow, Result};
use futures::StreamExt;
use netsage_session::SessionStore;
use netsage_tools::ToolRegistry;
use reqwest::Client;
use serde_json::{json, to_value, Value};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::info;

#[derive(Debug, Clone)]
pub enum AgentEvent {
    TextDelta(String),
    ToolCall {
        id: String,
        name: String,
        args: Value,
    },
    ToolResult {
        id: String,
        result: Value,
    },
    Error(String),
    Finished,
    Thinking(bool),
}

pub struct Agent {
    client: Client,
    api_key: String,
    model: String,
    provider: Provider,
    mode: ApprovalMode,
    persona: Arc<Mutex<Persona>>,
    session_store: SessionStore,
    tool_registry: ToolRegistry,
}

impl Agent {
    pub fn new(
        api_key: String,
        model: String,
        provider: Provider,
        mode: ApprovalMode,
        persona: Persona,
        session_store: SessionStore,
    ) -> Self {
        Self {
            client: Client::new(),
            api_key,
            model,
            provider,
            mode,
            persona: Arc::new(Mutex::new(persona)),
            session_store,
            tool_registry: ToolRegistry::new(),
        }
    }

    pub async fn run_loop(
        &self,
        messages: &mut Vec<Message>,
        event_tx: mpsc::Sender<AgentEvent>,
    ) -> Result<()> {
        let _ = event_tx.send(AgentEvent::Thinking(true)).await;

        loop {
            let system_prompt = self.get_system_prompt().await;
            let mut tool_calls_this_turn = Vec::new();

            // 1. Call LLM based on provider
            let mut assistant_text = String::new();

            match self.provider {
                Provider::Anthropic => {
                    let mut response_stream =
                        self.stream_anthropic(messages, &system_prompt).await?;
                    while let Some(item) = response_stream.next().await {
                        let line = item?;
                        if let Some(event) = parse_sse_line(&line)? {
                            match event {
                                ClaudeEvent::ContentBlockDelta { delta, .. } => {
                                    if let Some(text) = delta["text"].as_str() {
                                        assistant_text.push_str(text);
                                        let _ = event_tx
                                            .send(AgentEvent::TextDelta(text.to_string()))
                                            .await;
                                    }
                                }
                                ClaudeEvent::ContentBlockStart { content_block, .. } => {
                                    if content_block["type"] == "tool_use" {
                                        tool_calls_this_turn.push(content_block);
                                    }
                                }
                                ClaudeEvent::MessageStop => break,
                                ClaudeEvent::Error { error } => {
                                    let msg =
                                        error["message"].as_str().unwrap_or("Unknown Claude error");
                                    let _ = event_tx.send(AgentEvent::Error(msg.to_string())).await;
                                    let _ = event_tx.send(AgentEvent::Thinking(false)).await;
                                    return Err(anyhow!("Claude API Error: {}", msg));
                                }
                                _ => {}
                            }
                        }
                    }
                }
                Provider::Gemini => {
                    self.stream_gemini(
                        messages,
                        &system_prompt,
                        &mut assistant_text,
                        &mut tool_calls_this_turn,
                        &event_tx,
                    )
                    .await?;
                }
                Provider::OpenAI => {
                    self.stream_openai(
                        messages,
                        &system_prompt,
                        &mut assistant_text,
                        &mut tool_calls_this_turn,
                        &event_tx,
                    )
                    .await?;
                }
            }

            // Append assistant response to messages
            if !assistant_text.is_empty() {
                messages.push(Message {
                    role: "assistant".to_string(),
                    content: assistant_text,
                });
            }

            if tool_calls_this_turn.is_empty() {
                break; // No more tool calls, exit loop
            }

            // 2. Handle Tool Calls
            for tool_use in tool_calls_this_turn {
                let id = tool_use["id"].as_str().unwrap_or_default().to_string();
                let name = tool_use["name"].as_str().unwrap_or_default().to_string();
                let args = tool_use["input"].clone();

                info!("Handling tool call: {} (id: {})", name, id);

                // Approval check
                let (approved, _reason) = match self.mode {
                    ApprovalMode::ReadOnly => (false, "ReadOnly mode blocks all tool calls"),
                    ApprovalMode::Supervised => {
                        let _ = event_tx
                            .send(AgentEvent::ToolCall {
                                id: id.clone(),
                                name: name.clone(),
                                args: args.clone(),
                            })
                            .await;
                        // In a real TUI, we would wait for a response here.
                        // For now, we'll continue with the execution but note that it's supervised.
                        (
                            true,
                            "Supervised mode (Awaiting TUI response in future version)",
                        )
                    }
                    ApprovalMode::Autonomous => (true, "Autonomous mode"),
                };

                if !approved {
                    messages.push(Message {
                        role: "user".to_string(),
                        content: format!("Tool call {} blocked: {}", name, _reason),
                    });
                    continue;
                }

                self.session_store
                    .log_tool_call(&id, &name, &args, "pending")?;

                let result = self.tool_registry.call_tool(&name, args.clone()).await?;
                self.session_store.update_tool_result(&id, &result)?;

                let _ = event_tx
                    .send(AgentEvent::ToolResult {
                        id: id.clone(),
                        result: result.clone(),
                    })
                    .await;

                messages.push(Message {
                    role: "user".to_string(),
                    content: format!("Tool {} result: {}", name, result),
                });
            }
        }

        let _ = event_tx.send(AgentEvent::Thinking(false)).await;
        let _ = event_tx.send(AgentEvent::Finished).await;
        Ok(())
    }

    async fn stream_anthropic(
        &self,
        messages: &[Message],
        system_prompt: &str,
    ) -> Result<impl futures::Stream<Item = Result<String>>> {
        let messages_val = to_value(messages)?;
        let tools_val = to_value(self.tool_registry.get_schemas())?;

        let request = json!({
            "model": self.model,
            "system": system_prompt,
            "messages": messages_val,
            "max_tokens": 4096,
            "stream": true,
            "tools": tools_val,
        });

        let response = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let err_text = response.text().await?;
            return Err(anyhow!("Anthropic API failed: {}", err_text));
        }

        Ok(response.bytes_stream().map(|b| {
            let bytes = b.map_err(|e| anyhow!("Stream error: {}", e))?;
            String::from_utf8(bytes.to_vec()).map_err(|e| anyhow!("UTF-8 error: {}", e))
        }))
    }

    async fn stream_openai(
        &self,
        messages: &[Message],
        _system_prompt: &str,
        assistant_text: &mut String,
        tool_calls: &mut Vec<Value>,
        event_tx: &mpsc::Sender<AgentEvent>,
    ) -> Result<()> {
        let mut openai_messages = Vec::new();
        // OpenAI system prompt is usually first message
        openai_messages.push(json!({ "role": "system", "content": _system_prompt }));
        for m in messages {
            openai_messages.push(json!({ "role": &m.role, "content": &m.content }));
        }

        let request = json!({
            "model": self.model,
            "messages": openai_messages,
            "stream": true,
            "tools": self.tool_registry.get_openai_schemas(),
        });

        let response = self
            .client
            .post("https://api.openai.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let err = response.text().await?;
            return Err(anyhow!("OpenAI API error: {}", err));
        }

        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            let text = String::from_utf8_lossy(&chunk);
            for line in text.lines() {
                if let Some(data) = line.strip_prefix("data: ") {
                    if data == "[DONE]" {
                        break;
                    }
                    let val: Value = serde_json::from_str(data)?;
                    if let Some(delta) = val["choices"][0]["delta"].as_object() {
                        if let Some(content) = delta.get("content").and_then(|v| v.as_str()) {
                            assistant_text.push_str(content);
                            let _ = event_tx
                                .send(AgentEvent::TextDelta(content.to_string()))
                                .await;
                        }
                        if let Some(t_calls) = delta.get("tool_calls").and_then(|v| v.as_array()) {
                            for tc in t_calls {
                                tool_calls.push(tc.clone());
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn stream_gemini(
        &self,
        messages: &[Message],
        _system_prompt: &str,
        assistant_text: &mut String,
        tool_calls: &mut Vec<Value>,
        event_tx: &mpsc::Sender<AgentEvent>,
    ) -> Result<()> {
        let mut contents = Vec::new();
        for m in messages {
            let role = if m.role == "assistant" {
                "model"
            } else {
                "user"
            };
            contents.push(json!({
                "role": role,
                "parts": [{ "text": &m.content }]
            }));
        }

        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{}:streamGenerateContent?alt=sse&key={}",
            self.model, self.api_key
        );

        let request = json!({
            "contents": contents,
            "system_instruction": { "parts": [{ "text": _system_prompt }] },
            "tools": [{ "function_declarations": self.tool_registry.get_gemini_schemas() }],
        });

        let response = self.client.post(&url).json(&request).send().await?;

        if !response.status().is_success() {
            let err = response.text().await?;
            return Err(anyhow!("Gemini API error: {}", err));
        }

        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            let text = String::from_utf8_lossy(&chunk);
            for line in text.lines() {
                if let Some(data) = line.strip_prefix("data: ") {
                    let val: Value = serde_json::from_str(data)?;
                    if let Some(candidates) = val["candidates"].as_array() {
                        for cand in candidates {
                            if let Some(parts) = cand["content"]["parts"].as_array() {
                                for part in parts {
                                    if let Some(t) = part["text"].as_str() {
                                        assistant_text.push_str(t);
                                        let _ = event_tx
                                            .send(AgentEvent::TextDelta(t.to_string()))
                                            .await;
                                    }
                                    if let Some(fc) = part.get("functionCall") {
                                        // Gemini tool calls need to be mapped to Anthropic format for consistency
                                        tool_calls.push(json!({
                                            "type": "tool_use",
                                            "id": uuid::Uuid::new_v4().to_string(),
                                            "name": fc["name"],
                                            "input": fc["args"]
                                        }));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn set_persona(&self, persona: Persona) {
        let mut p = self.persona.lock().await;
        *p = persona;
    }

    async fn get_system_prompt(&self) -> String {
        let p = self.persona.lock().await;
        match *p {
            Persona::General => "You are NetSage, an AI network intelligence assistant. You help users diagnose and monitor networks using available tools.".to_string(),
            Persona::NetOps => "You are a Senior Network Operations Engineer. Focus on routing, switching, ISP issues, and throughput optimization. Be precise with CIDR and protocol details.".to_string(),
            Persona::SecOps => "You are a Cybersecurity Analyst. Focus on port scanning, service detection, potential intrusions, and unauthorized traffic. Look for anomalies.".to_string(),
            Persona::SRE => "You are a Site Reliability Engineer. Focus on latency, availability, connectivity issues, and infrastructure health.".to_string(),
        }
    }
}
