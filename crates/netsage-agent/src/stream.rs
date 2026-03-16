use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum ClaudeEvent {
    #[serde(rename = "message_start")]
    MessageStart { message: Value },
    #[serde(rename = "content_block_start")]
    ContentBlockStart { index: usize, content_block: Value },
    #[serde(rename = "content_block_delta")]
    ContentBlockDelta { index: usize, delta: Value },
    #[serde(rename = "content_block_stop")]
    ContentBlockStop { index: usize },
    #[serde(rename = "message_delta")]
    MessageDelta { delta: Value, usage: Value },
    #[serde(rename = "message_stop")]
    MessageStop,
    #[serde(rename = "ping")]
    Ping,
    #[serde(rename = "error")]
    Error { error: Value },
}

pub fn parse_sse_line(line: &str) -> Result<Option<ClaudeEvent>> {
    if let Some(data) = line.strip_prefix("data: ") {
        let event: ClaudeEvent = serde_json::from_str(data)?;
        Ok(Some(event))
    } else {
        Ok(None)
    }
}
