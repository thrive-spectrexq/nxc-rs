use crate::providers::{AiProvider, Message, Role, ToolResult};
use crate::tools::ToolRegistry;
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::Value;

#[async_trait]
pub trait AgentFeedback: Send + Sync {
    async fn on_thought(&self, text: &str) -> Result<()>;
    async fn on_tool_call(&self, name: &str, args: &str) -> Result<()>;
    async fn on_tool_result(&self, name: &str, result: &str) -> Result<()>;
}

pub struct CliFeedback;

#[async_trait]
impl AgentFeedback for CliFeedback {
    async fn on_thought(&self, text: &str) -> Result<()> {
        println!("AI: {}", text);
        Ok(())
    }
    async fn on_tool_call(&self, name: &str, args: &str) -> Result<()> {
        println!("AI is calling tool: {} with args: {}", name, args);
        Ok(())
    }
    async fn on_tool_result(&self, _name: &str, _result: &str) -> Result<()> {
        Ok(())
    }
}

pub struct AiAgent {
    provider: Box<dyn AiProvider>,
    tools: ToolRegistry,
    history: Vec<Message>,
    feedback: Box<dyn AgentFeedback>,
}

impl AiAgent {
    pub fn new(provider: Box<dyn AiProvider>, tools: ToolRegistry, feedback: Box<dyn AgentFeedback>) -> Self {
        Self {
            provider,
            tools,
            history: Vec::new(),
            feedback,
        }
    }

    pub async fn run(&mut self, user_prompt: &str) -> Result<()> {
        let system_prompt = "You are a professional network security orchestrator powered by NetExec-RS.
Your goal is to assist in network discovery, credential auditing, and automated exploitation tasks.

Guidelines:
1. **Persistence Awareness**: Use the `query_db` tool to see what *hosts* have already been discovered in the current workspace. This helps you avoid redundant scans.
2. **Targeting**: When scanning, use previously discovered IP addresses or hostnames as a baseline.
3. **Offensive Modules**: Use `search_modules` to find specialized payloads for specific goals (e.g., 'bloodhound' for AD mapping, 'secretsdump' for password extraction).
4. **Efficiency**: Break down complex goals into a series of logical steps (Discovery -> Enumeration -> Exploitation -> Reporting).
5. **Conciseness**: Be technical and concise. Avoid fluff.
6. **Safety**: Confirm before taking any potentially destructive actions (e.g., changing passwords, persisting in WMI).";

        let mut current_user_prompt = user_prompt.to_string();

        loop {
            // Push the user message to history before completing
            // Gemini expects a clean User -> Assistant -> User sequence
            self.history.push(Message {
                role: Role::User,
                content: current_user_prompt.clone(),
                tool_calls: None,
                tool_results: None,
            });

            // Get tool definitions for the provider
            let tool_defs: Vec<_> = self.tools.all().iter().map(|t| crate::providers::ToolDefinition {
                name: t.name().to_string(),
                description: t.description().to_string(),
                parameters: t.parameters(),
            }).collect();

            let resp = self.provider.complete(system_prompt, &current_user_prompt, &self.history, &tool_defs).await?;

            // Unify thought and tool calls into a single Assistant message for Gemini compatibility
            let mut assistant_msg = Message {
                role: Role::Assistant,
                content: String::new(),
                tool_calls: None,
                tool_results: None,
            };

            if let Some(text) = &resp.text {
                self.feedback.on_thought(text).await?;
                assistant_msg.content = text.clone();
            }

            if !resp.tool_calls.is_empty() {
                assistant_msg.tool_calls = Some(resp.tool_calls.clone());
            }

            self.history.push(assistant_msg);

            if resp.tool_calls.is_empty() {
                break;
            }

            let mut tool_results = Vec::new();
            for tc in &resp.tool_calls {
                self.feedback.on_tool_call(&tc.name, &tc.arguments).await?;
                
                let tool = self.tools.get(&tc.name).context(format!("Tool not found: {}", tc.name))?;
                let args: Value = serde_json::from_str(&tc.arguments)?;
                
                let result = tool.call(args).await?;
                let result_str = serde_json::to_string(&result)?;
                
                self.feedback.on_tool_result(&tc.name, &result_str).await?;
                
                tool_results.push(ToolResult {
                    call_id: tc.name.clone(),
                    content: result_str,
                });
            }

            self.history.push(Message {
                role: Role::Tool,
                content: String::new(),
                tool_calls: None,
                tool_results: Some(tool_results),
            });

            // Continue the loop with a prompt to process tool results
            current_user_prompt = "Process the tool results and provide a summary or the next step.".to_string();
        }

        Ok(())
    }
}
