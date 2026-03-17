use crate::{
    client::{AnthropicClient, GeminiClient, LlmClient, OpenAiClient},
    Message, StopReason,
};
use anyhow::Result;
use netsage_common::{AppEvent, ApprovalMode, NetSageConfig, Provider};
use netsage_session::SessionManager;
use netsage_tools::ToolRegistry;
use tokio::sync::{broadcast, mpsc};

pub use netsage_common::AppEvent as AgentEvent;

pub struct Agent {
    llm_client: Box<dyn LlmClient>,
    config: NetSageConfig,
    session_manager: SessionManager,
    session_id: uuid::Uuid,
    tool_registry: ToolRegistry,
    event_tx: broadcast::Sender<AppEvent>,
    rx: mpsc::Receiver<String>,
}

impl Agent {
    pub fn new(
        config: NetSageConfig,
        session_manager: SessionManager,
        session_id: uuid::Uuid,
        event_tx: broadcast::Sender<AppEvent>,
        rx: mpsc::Receiver<String>,
    ) -> Self {
        let client = reqwest::Client::new();
        let api_key = match config.core.provider {
            Provider::Anthropic => std::env::var("ANTHROPIC_API_KEY").unwrap_or_default(),
            Provider::OpenAi => std::env::var("OPENAI_API_KEY").unwrap_or_default(),
            Provider::Gemini => std::env::var("GEMINI_API_KEY").unwrap_or_default(),
        };

        let llm_client: Box<dyn LlmClient> = match config.core.provider {
            Provider::Anthropic => Box::new(AnthropicClient {
                api_key,
                model: config.core.model.clone(),
                client,
            }),
            Provider::OpenAi => Box::new(OpenAiClient {
                api_key,
                model: config.core.model.clone(),
                client,
            }),
            Provider::Gemini => Box::new(GeminiClient {
                api_key,
                model: config.core.model.clone(),
                client,
            }),
        };

        Self {
            llm_client,
            config,
            session_manager,
            session_id,
            tool_registry: ToolRegistry::new(),
            event_tx,
            rx,
        }
    }

    pub async fn run(mut self, mut history: Vec<Message>) -> Result<()> {
        loop {
            let user_msg = match self.rx.recv().await {
                Some(msg) => msg,
                None => break,
            };
            history.push(Message::user(user_msg.clone()));
            let _ = self
                .session_manager
                .log_turn(self.session_id, "user", &user_msg)
                .await;

            'agent: loop {
                let response = self
                    .llm_client
                    .stream_completion(&history, &self.tool_registry.get_schemas(), &self.event_tx)
                    .await?;

                match response.stop_reason {
                    StopReason::EndTurn => {
                        history.push(Message::assistant(response.content.clone()));
                        let _ = self
                            .session_manager
                            .log_turn(self.session_id, "assistant", &response.content)
                            .await;
                        let _ = self.event_tx.send(AppEvent::AgentDone("".to_string()));
                        break 'agent;
                    }
                    StopReason::ToolUse => {
                        for tool_call in response.tool_calls {
                            let approved = self
                                .gate_approval(&tool_call.name, &tool_call.input)
                                .await?;
                            if !approved {
                                history.push(Message::user(format!(
                                    "Tool call {} denied by user.",
                                    tool_call.name
                                )));
                                continue;
                            }

                            let result = self
                                .tool_registry
                                .call_tool(&tool_call.name, tool_call.input.clone())
                                .await?;

                            let _ = self.event_tx.send(AppEvent::AgentToolResult {
                                id: tool_call.id.clone(),
                                result: result.clone(),
                            });

                            history.push(Message::user(format!(
                                "Tool {} result: {}",
                                tool_call.name, result
                            )));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn gate_approval(&self, name: &str, input: &serde_json::Value) -> Result<bool> {
        match self.config.core.approval_mode {
            ApprovalMode::ReadOnly => Ok(false),
            ApprovalMode::Supervised => {
                let _ = self.event_tx.send(AppEvent::AgentToolCall {
                    id: uuid::Uuid::new_v4().to_string(), // Placeholder ID
                    name: name.to_string(),
                    input: input.clone(),
                });
                // In actual implementation, we would wait for AppEvent::ApprovalResponse
                // For now, returning true to allow progress in testing, but this needs proper wiring
                Ok(true)
            }
            ApprovalMode::Autonomous => Ok(true),
        }
    }
}
