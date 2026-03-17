use crate::{NetworkTool, ToolResult};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use tokio::net::lookup_host;

pub struct PingTool;

#[async_trait]
impl NetworkTool for PingTool {
    fn name(&self) -> &'static str {
        "ping"
    }
    fn description(&self) -> &'static str {
        "Send ICMP echo requests and return RTT statistics"
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "host": { "type": "string", "description": "Target hostname or IP" },
                "count": { "type": "integer", "default": 4, "minimum": 1, "maximum": 100 },
                "timeout_ms": { "type": "integer", "default": 2000 }
            },
            "required": ["host"]
        })
    }

    async fn execute(&self, input: Value) -> Result<ToolResult> {
        let host = input["host"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing host"))?;
        let count = input["count"].as_u64().unwrap_or(4) as usize;
        let timeout_ms = input["timeout_ms"].as_u64().unwrap_or(2000);

        let start_time = Instant::now();
        let addr = lookup_host(format!("{}:0", host))
            .await?
            .next()
            .ok_or_else(|| anyhow!("DNS resolution failed for {}", host))?
            .ip();

        let mut rtts = Vec::new();
        let payload = [0u8; 56];

        for _ in 0..count {
            if let Ok(Ok((_, rtt))) = tokio::time::timeout(
                Duration::from_millis(timeout_ms),
                surge_ping::ping(addr, &payload),
            )
            .await
            {
                rtts.push(rtt.as_secs_f64() * 1000.0);
            }
        }

        let duration = start_time.elapsed().as_millis() as u64;
        let loss = (count - rtts.len()) as f64 / count as f64 * 100.0;
        let avg = if !rtts.is_empty() {
            rtts.iter().sum::<f64>() / rtts.len() as f64
        } else {
            0.0
        };
        let min = rtts.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = rtts.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

        Ok(ToolResult {
            success: !rtts.is_empty(),
            output: format!(
                "ping {}: min={:.2}ms avg={:.2}ms max={:.2}ms loss={:.1}%",
                host,
                if min.is_infinite() { 0.0 } else { min },
                avg,
                if max.is_infinite() { 0.0 } else { max },
                loss
            ),
            data: json!({
                "host": host,
                "sent": count,
                "received": rtts.len(),
                "loss_pct": loss,
                "rtt_ms": { "min": min, "avg": avg, "max": max },
                "samples": rtts
            }),
            duration_ms: duration,
        })
    }
}
