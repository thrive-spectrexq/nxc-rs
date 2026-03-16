use crate::{NetworkTool, ToolResult};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::time::Instant;

pub struct GeoIpTool;

#[async_trait]
impl NetworkTool for GeoIpTool {
    fn name(&self) -> &'static str {
        "geoip_lookup"
    }
    fn description(&self) -> &'static str {
        "Get geographical and ISP information for a public IP address"
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "ip": { "type": "string", "description": "The public IP address to lookup" }
            },
            "required": ["ip"]
        })
    }

    async fn execute(&self, input: Value) -> Result<ToolResult> {
        let ip_str = input["ip"].as_str().ok_or_else(|| anyhow!("Missing ip"))?;
        let start_time = Instant::now();

        // For now, retaining mock logic as per original until DB path is integrated
        let is_private = ip_str.starts_with("10.")
            || ip_str.starts_with("192.168.")
            || ip_str.starts_with("172.");

        let data = if is_private {
            json!({
                "status": "success",
                "ip": ip_str,
                "location": "Internal Network",
                "isp": "Local Authority",
                "note": "Private IP address detected"
            })
        } else {
            json!({
                "status": "success",
                "ip": ip_str,
                "city": "San Francisco",
                "region": "California",
                "country": "United States",
                "isp": "Cloudflare / Google Mock",
                "note": "GeoIP database path not configured, returning mock data"
            })
        };

        let duration = start_time.elapsed().as_millis() as u64;

        Ok(ToolResult {
            success: true,
            output: format!(
                "geoip_lookup {}: {}",
                ip_str,
                data["location"]
                    .as_str()
                    .or(data["country"].as_str())
                    .unwrap_or("Unknown")
            ),
            data,
            duration_ms: duration,
        })
    }
}
