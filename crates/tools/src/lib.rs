use anyhow::Result;
use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

pub mod tools;

#[async_trait]
pub trait NetworkTool: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn input_schema(&self) -> Value;
    fn is_read_only(&self) -> bool {
        true
    }
    async fn execute(&self, input: Value) -> Result<ToolResult>;
}

pub struct ToolResult {
    pub success: bool,
    pub output: String,
    pub data: Value,
    pub duration_ms: u64,
}

impl ToolResult {
    pub fn to_json(&self) -> Value {
        json!({
            "success": self.success,
            "output": self.output,
            "data": self.data,
            "duration_ms": self.duration_ms,
        })
    }
}

pub struct ToolRegistry {
    tools: HashMap<String, Arc<dyn NetworkTool>>,
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolRegistry {
    pub fn new() -> Self {
        let mut tools: HashMap<String, Arc<dyn NetworkTool>> = HashMap::new();

        tools.insert(
            "ping".to_string(),
            Arc::new(tools::ping::PingTool) as Arc<dyn NetworkTool>,
        );
        tools.insert(
            "dns_lookup".to_string(),
            Arc::new(tools::dns::DnsTool) as Arc<dyn NetworkTool>,
        );
        tools.insert(
            "port_scan".to_string(),
            Arc::new(tools::port_scan::PortScanTool) as Arc<dyn NetworkTool>,
        );
        tools.insert(
            "geoip_lookup".to_string(),
            Arc::new(tools::geoip::GeoIpTool) as Arc<dyn NetworkTool>,
        );
        tools.insert(
            "whois_lookup".to_string(),
            Arc::new(tools::whois::WhoisTool) as Arc<dyn NetworkTool>,
        );
        tools.insert(
            "ssh_command".to_string(),
            Arc::new(tools::ssh::SshTool) as Arc<dyn NetworkTool>,
        );
        tools.insert(
            "traceroute".to_string(),
            Arc::new(tools::traceroute::TracerouteTool) as Arc<dyn NetworkTool>,
        );
        tools.insert(
            "http_probe".to_string(),
            Arc::new(tools::http_probe::HttpProbeTool) as Arc<dyn NetworkTool>,
        );

        Self { tools }
    }

    pub fn register(&mut self, tool: Arc<dyn NetworkTool>) {
        self.tools.insert(tool.name().to_string(), tool);
    }

    pub async fn call_tool(&self, name: &str, args: Value) -> Result<Value> {
        let tool = self
            .tools
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("Tool not implemented: {}", name))?;

        let result = tool.execute(args).await?;
        Ok(result.to_json())
    }

    pub fn get_schemas(&self) -> Vec<Value> {
        self.tools
            .values()
            .map(|t| {
                json!({
                    "name": t.name(),
                    "description": t.description(),
                    "input_schema": t.input_schema(),
                })
            })
            .collect()
    }

    pub fn get_openai_schemas(&self) -> Vec<Value> {
        self.tools
            .values()
            .map(|t| {
                json!({
                    "type": "function",
                    "function": {
                        "name": t.name(),
                        "description": t.description(),
                        "parameters": t.input_schema()
                    }
                })
            })
            .collect()
    }

    pub fn get_gemini_schemas(&self) -> Vec<Value> {
        self.tools
            .values()
            .map(|t| {
                json!({
                    "name": t.name(),
                    "description": t.description(),
                    "parameters": t.input_schema()
                })
            })
            .collect()
    }
}
