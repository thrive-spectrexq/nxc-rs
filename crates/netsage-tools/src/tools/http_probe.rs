use crate::{NetworkTool, ToolResult};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::time::Instant;

pub struct HttpProbeTool;

#[async_trait]
impl NetworkTool for HttpProbeTool {
    fn name(&self) -> &'static str {
        "http_probe"
    }
    fn description(&self) -> &'static str {
        "Send an HTTP/HTTPS request and return performance metrics"
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "url": { "type": "string", "description": "Target URL" },
                "method": { "type": "string", "default": "GET" }
            },
            "required": ["url"]
        })
    }

    async fn execute(&self, input: Value) -> Result<ToolResult> {
        let url = input["url"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing url"))?;
        let method_str = input["method"].as_str().unwrap_or("GET");

        let start_time = Instant::now();
        let client = reqwest::Client::new();

        let method = match method_str.to_uppercase().as_str() {
            "POST" => reqwest::Method::POST,
            "PUT" => reqwest::Method::PUT,
            _ => reqwest::Method::GET,
        };

        let response = client.request(method, url).send().await?;
        let status = response.status();
        let headers = response.headers().len();

        let duration = start_time.elapsed().as_millis() as u64;

        Ok(ToolResult {
            success: status.is_success(),
            output: format!("http_probe {}: status {} in {}ms", url, status, duration),
            data: json!({
                "url": url,
                "status": status.as_u16(),
                "headers_count": headers,
                "duration_ms": duration
            }),
            duration_ms: duration,
        })
    }
}
