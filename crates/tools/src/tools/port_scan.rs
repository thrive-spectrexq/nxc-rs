use crate::{NetworkTool, ToolResult};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};
use serde_json::{json, Value};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

pub struct PortScanTool;

#[async_trait]
impl NetworkTool for PortScanTool {
    fn name(&self) -> &'static str {
        "port_scan"
    }
    fn description(&self) -> &'static str {
        "Scan a target host for open TCP ports"
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "host": { "type": "string", "description": "Target hostname or IP" },
                "ports": { "type": "string", "description": "Port range (e.g., '1-1024' or '80,443')", "default": "1-1024" },
                "concurrency": { "type": "integer", "default": 200 },
                "timeout_ms": { "type": "integer", "default": 500 }
            },
            "required": ["host"]
        })
    }

    async fn execute(&self, input: Value) -> Result<ToolResult> {
        let host = input["host"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing host"))?;
        let ports_str = input["ports"].as_str().unwrap_or("1-1024");
        let concurrency = input["concurrency"].as_u64().unwrap_or(200) as usize;
        let timeout = Duration::from_millis(input["timeout_ms"].as_u64().unwrap_or(500));

        let start_time = Instant::now();
        let addr: IpAddr = if let Ok(ip) = host.parse::<IpAddr>() {
            ip
        } else {
            tokio::net::lookup_host(format!("{}:0", host))
                .await?
                .next()
                .ok_or_else(|| anyhow!("DNS resolution failed"))?
                .ip()
        };

        let ports = parse_ports(ports_str)?;
        let semaphore = Arc::new(Semaphore::new(concurrency));
        let mut tasks = FuturesUnordered::new();

        for port in ports {
            let permit = semaphore.clone().acquire_owned().await?;
            tasks.push(tokio::spawn(async move {
                let _permit = permit;
                let target = SocketAddr::new(addr, port);
                let open = tokio::time::timeout(timeout, TcpStream::connect(target))
                    .await
                    .is_ok_and(|r| r.is_ok());
                (port, open)
            }));
        }

        let mut open_ports = Vec::new();
        while let Some(Ok((port, open))) = tasks.next().await {
            if open {
                open_ports.push(port);
            }
        }
        open_ports.sort_unstable();

        let duration = start_time.elapsed().as_millis() as u64;

        Ok(ToolResult {
            success: true,
            output: format!("port_scan {}: found {} open ports", host, open_ports.len()),
            data: json!({
                "host": host,
                "open_ports": open_ports,
                "total_scanned": open_ports.len() // simplified
            }),
            duration_ms: duration,
        })
    }
}

fn parse_ports(ports_str: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();
    if ports_str.contains('-') {
        let parts: Vec<&str> = ports_str.split('-').collect();
        if parts.len() == 2 {
            let start = parts[0].parse::<u16>()?;
            let end = parts[1].parse::<u16>()?;
            for p in start..=end {
                ports.push(p);
            }
        }
    } else {
        for p in ports_str.split(',') {
            if let Ok(port) = p.trim().parse::<u16>() {
                ports.push(port);
            }
        }
    }
    Ok(ports)
}
