use crate::{NetworkTool, ToolResult};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Instant;

pub struct WhoisTool;

#[async_trait]
impl NetworkTool for WhoisTool {
    fn name(&self) -> &'static str {
        "whois_lookup"
    }
    fn description(&self) -> &'static str {
        "Retrieve WHOIS registry information for a domain or IP"
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "domain": { "type": "string", "description": "Domain name or IP address" }
            },
            "required": ["domain"]
        })
    }

    async fn execute(&self, input: Value) -> Result<ToolResult> {
        let domain = input["domain"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing domain"))?;
        let start_time = Instant::now();

        let mut stream = TcpStream::connect("whois.iana.org:43")?;
        stream.write_all(format!("{}\r\n", domain).as_bytes())?;

        let mut response = String::new();
        stream.read_to_string(&mut response)?;

        let duration = start_time.elapsed().as_millis() as u64;

        Ok(ToolResult {
            success: true,
            output: format!("whois_lookup {}: received {} bytes", domain, response.len()),
            data: json!({
                "domain": domain,
                "raw": response
            }),
            duration_ms: duration,
        })
    }
}
