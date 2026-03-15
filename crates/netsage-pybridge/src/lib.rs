pub mod protocol;

use anyhow::Result;
use protocol::{JsonRpcRequest, JsonRpcResponse, ToolCallParams};
use serde_json::json;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tracing::info;

pub struct PythonBridge {
    child: Child,
}

impl PythonBridge {
    pub async fn spawn(python_path: &str, script_path: &str) -> Result<Self> {
        let child = Command::new(python_path)
            .arg(script_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        info!("Spawned Python bridge process");
        Ok(Self { child })
    }

    pub async fn call_tool(
        &mut self,
        tool: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let stdin = self
            .child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("No stdin"))?;
        let stdout = self
            .child
            .stdout
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("No stdout"))?;
        let mut reader = BufReader::new(stdout);

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: json!("1"), // Simple ID for now
            method: "execute_tool".to_string(),
            params: json!(ToolCallParams {
                tool: tool.to_string(),
                args,
            }),
        };

        let request_str = serde_json::to_string(&request)? + "\n";
        stdin.write_all(request_str.as_bytes()).await?;
        stdin.flush().await?;

        let mut response_line = String::new();
        reader.read_line(&mut response_line).await?;

        let response: JsonRpcResponse = serde_json::from_str(&response_line)?;
        if let Some(err) = response.error {
            anyhow::bail!("Python error {}: {}", err.code, err.message);
        }

        response
            .result
            .ok_or_else(|| anyhow::anyhow!("No result in response"))
    }
}
