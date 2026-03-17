use crate::{NetworkTool, ToolResult};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::net::IpAddr;
use std::time::Instant;
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;

pub struct DnsTool;

#[async_trait]
impl NetworkTool for DnsTool {
    fn name(&self) -> &'static str {
        "dns_lookup"
    }
    fn description(&self) -> &'static str {
        "Resolve a hostname to IP addresses or vice versa"
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "query": { "type": "string", "description": "The hostname or IP to resolve" }
            },
            "required": ["query"]
        })
    }

    async fn execute(&self, input: Value) -> Result<ToolResult> {
        let query = input["query"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing query"))?;
        let start_time = Instant::now();
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        let (query_type, results) = if let Ok(ip) = query.parse::<IpAddr>() {
            let response = resolver.reverse_lookup(ip).await?;
            (
                "PTR",
                response
                    .into_iter()
                    .map(|n| n.to_utf8())
                    .collect::<Vec<_>>(),
            )
        } else {
            let response = resolver.lookup_ip(query).await?;
            (
                "A/AAAA",
                response
                    .into_iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>(),
            )
        };

        let duration = start_time.elapsed().as_millis() as u64;

        Ok(ToolResult {
            success: !results.is_empty(),
            output: format!(
                "dns_lookup {}: {} found {} results",
                query,
                query_type,
                results.len()
            ),
            data: json!({
                "query": query,
                "type": query_type,
                "results": results
            }),
            duration_ms: duration,
        })
    }
}
