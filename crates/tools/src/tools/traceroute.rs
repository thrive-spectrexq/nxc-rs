use crate::{NetworkTool, ToolResult};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::time::Instant;
use tokio::net::lookup_host;

pub struct TracerouteTool;

#[async_trait]
impl NetworkTool for TracerouteTool {
    fn name(&self) -> &'static str {
        "traceroute"
    }
    fn description(&self) -> &'static str {
        "Trace the path to a host using TTL probes (stub)"
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "host": { "type": "string", "description": "Target hostname or IP" },
                "max_hops": { "type": "integer", "default": 30 },
                "timeout_ms": { "type": "integer", "default": 2000 }
            },
            "required": ["host"]
        })
    }

    async fn execute(&self, input: Value) -> Result<ToolResult> {
        let host = input["host"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing host"))?;
        let _max_hops = input["max_hops"].as_u64().unwrap_or(30) as u8;
        let _timeout_ms = input["timeout_ms"].as_u64().unwrap_or(2000);

        let start_time = Instant::now();
        let addr = lookup_host(format!("{}:0", host))
            .await?
            .next()
            .ok_or_else(|| anyhow!("DNS resolution failed"))?
            .ip();

        let mut hops = Vec::new();
        let payload = [0u8; 56];

        // Mocking the result for now to ensure compile
        for ttl in 1..=5 {
            let _ = surge_ping::ping(addr, &payload).await;
            hops.push(json!({
                "hop": ttl,
                "ip": format!("192.168.{}.1", ttl),
                "rtt_ms": [1.2, 1.5, 1.3]
            }));
        }

        let duration = start_time.elapsed().as_millis() as u64;

        Ok(ToolResult {
            success: true,
            output: format!(
                "traceroute to {}: {} hops completed (mocked)",
                host,
                hops.len()
            ),
            data: json!({ "host": host, "hops": hops }),
            duration_ms: duration,
        })
    }
}
