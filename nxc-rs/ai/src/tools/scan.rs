use super::NxcTool;
use anyhow::{Context, Result};
use async_trait::async_trait;
use nxc_targets::parse_targets;
use serde_json::{json, Value};

pub struct ScanTool;

#[async_trait]
impl NxcTool for ScanTool {
    fn name(&self) -> &'static str {
        "parse_targets"
    }

    fn description(&self) -> &'static str {
        "Parse and expand target specifications (IPs, CIDRs, ranges) into a list of individual targets."
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "targets": {
                    "type": "string",
                    "description": "The target specification (e.g., '192.168.1.0/24', '10.0.0.1-50', 'hosts.txt')"
                }
            },
            "required": ["targets"]
        })
    }

    async fn call(&self, args: Value) -> Result<Value> {
        let targets_spec = args["targets"]
            .as_str()
            .context("Missing targets argument")?;
        let targets = parse_targets(targets_spec)?;

        let mut results = Vec::new();
        for t in targets {
            results.push(json!({
                "ip": t.ip_string(),
                "hostname": t.hostname,
            }));
        }

        Ok(json!({ "targets": results }))
    }
}
