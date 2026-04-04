use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;

pub mod scan;
pub mod protocol;
pub mod db;
pub mod modules;
pub mod utils;

#[async_trait]
pub trait NxcTool: Send + Sync {
    /// Tool name.
    fn name(&self) -> &'static str;

    /// Tool description.
    fn description(&self) -> &'static str;

    /// Tool parameters (JSON schema).
    fn parameters(&self) -> Value;

    /// Execute the tool with arguments.
    async fn call(&self, args: Value) -> Result<Value>;
}

pub struct ToolRegistry {
    tools: HashMap<String, Box<dyn NxcTool>>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
        }
    }

    pub fn register(&mut self, tool: Box<dyn NxcTool>) {
        self.tools.insert(tool.name().to_string(), tool);
    }

    pub fn get(&self, name: &str) -> Option<&dyn NxcTool> {
        self.tools.get(name).map(|t| t.as_ref())
    }

    pub fn all(&self) -> Vec<&dyn NxcTool> {
        self.tools.values().map(|t| t.as_ref()).collect()
    }
}
