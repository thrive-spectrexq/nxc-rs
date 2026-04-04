use super::NxcTool;
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::net::lookup_host;
use std::time::Duration;

pub struct UtilityTool;

#[async_trait]
impl NxcTool for UtilityTool {
    fn name(&self) -> &'static str {
        "utils"
    }

    fn description(&self) -> &'static str {
        "Base network utilities for DNS resolution, reachability checks (ping), and geolocation lookup."
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["resolve_dns", "ping", "geo_lookup"],
                    "description": "The utility action to perform"
                },
                "target": {
                    "type": "string",
                    "description": "The hostname or IP address to process"
                }
            },
            "required": ["action", "target"]
        })
    }

    async fn call(&self, args: Value) -> Result<Value> {
        let action = args["action"].as_str().context("Missing action")?;
        let target = args["target"].as_str().context("Missing target")?;

        match action {
            "resolve_dns" => {
                let addrs = lookup_host(format!("{}:80", target)).await?;
                let ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
                Ok(json!({ "resolved_ips": ips }))
            }
            "ping" => {
                // Implementation using TCP connect to 80/443 as a primitive ping
                let ports = [80, 443, 22];
                let mut success = false;
                let mut latency = None;

                for port in ports {
                    let start = std::time::Instant::now();
                    if let Ok(_) = tokio::time::timeout(
                        Duration::from_secs(2),
                        tokio::net::TcpStream::connect(format!("{}:{}", target, port))
                    ).await {
                        success = true;
                        latency = Some(start.elapsed().as_millis());
                        break;
                    }
                }

                Ok(json!({ 
                    "reachable": success, 
                    "latency_ms": latency,
                    "method": "TCP connect (ports 80/443/22)"
                }))
            }
            "geo_lookup" => {
                let url = format!("http://ip-api.com/json/{}?fields=status,message,country,city,isp,query", target);
                let client = reqwest::Client::new();
                let resp = client.get(url).send().await?;
                let json: Value = resp.json().await?;
                Ok(json)
            }
            _ => Ok(json!({ "error": "Invalid action" }))
        }
    }
}
