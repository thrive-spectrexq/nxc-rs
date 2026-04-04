use super::NxcTool;
use anyhow::{Context, Result};
use async_trait::async_trait;
use nxc_modules::ModuleRegistry;
use serde_json::{json, Value};
use std::sync::Arc;

pub struct SearchModulesTool {
    registry: Arc<ModuleRegistry>,
}

impl SearchModulesTool {
    pub fn new(registry: Arc<ModuleRegistry>) -> Self {
        Self { registry }
    }
}

#[async_trait]
impl NxcTool for SearchModulesTool {
    fn name(&self) -> &'static str {
        "search_modules"
    }

    fn description(&self) -> &'static str {
        "Search for NetExec modules (e.g. bloodhound, secretsdump, laps) by name or description for offensive actions."
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "keyword": {
                    "type": "string",
                    "description": "Keyword to search for in module name or description"
                },
                "protocol": {
                    "type": "string",
                    "description": "Optional protocol to filter modules (e.g. smb, ldap)"
                }
            }
        })
    }

    async fn call(&self, args: Value) -> Result<Value> {
        let keyword = args["keyword"].as_str().unwrap_or("").to_lowercase();
        let protocol = args["protocol"].as_str();

        let modules = self.registry.list(protocol);
        let mut results = Vec::new();

        for m in modules {
            let name = m.name();
            let desc = m.description();
            if name.contains(&keyword) || desc.to_lowercase().contains(&keyword) {
                results.push(json!({
                    "name": name,
                    "description": desc,
                    "supported_protocols": m.supported_protocols()
                }));
            }
        }

        Ok(json!({ "modules": results }))
    }
}
