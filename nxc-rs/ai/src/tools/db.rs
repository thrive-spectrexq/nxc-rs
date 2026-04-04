use super::NxcTool;
use anyhow::{Context, Result};
use async_trait::async_trait;
use nxc_db::NxcDb;
use serde_json::{json, Value};
use std::sync::Arc;

pub struct QueryDbTool {
    db: Arc<NxcDb>,
}

impl QueryDbTool {
    pub fn new(db: Arc<NxcDb>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl NxcTool for QueryDbTool {
    fn name(&self) -> &'static str {
        "query_db"
    }

    fn description(&self) -> &'static str {
        "Query the local NetExec database for discovered hosts, credentials, and scan results in the current workspace."
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "query_type": {
                    "type": "string",
                    "enum": ["hosts", "stats"],
                    "description": "The type of information to retrieve"
                },
                "workspace": {
                    "type": "string",
                    "description": "Optional workspace name (defaults to 'default')"
                }
            },
            "required": ["query_type"]
        })
    }

    async fn call(&self, args: Value) -> Result<Value> {
        let query_type = args["query_type"].as_str().context("Missing query type")?;
        let workspace = args["workspace"].as_str().unwrap_or("default");

        match query_type {
            "hosts" => {
                let hosts = self.db.list_hosts_in(workspace)?;
                Ok(json!({ "hosts": hosts }))
            }
            "stats" => {
                let stats = self.db.get_stats_in(workspace)?;
                Ok(json!({ "stats": stats }))
            }
            _ => Ok(json!({ "error": "Invalid query type" }))
        }
    }
}
