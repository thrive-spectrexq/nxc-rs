use anyhow::Result;
use netsage_tools::ToolRegistry;
use serde_json::{json, Value};
use std::io::{self, BufRead};

pub struct McpServer {
    registry: ToolRegistry,
}

impl Default for McpServer {
    fn default() -> Self {
        Self::new()
    }
}

impl McpServer {
    pub fn new() -> Self {
        Self {
            registry: ToolRegistry::new(),
        }
    }

    pub async fn run(&self) -> Result<()> {
        let stdin = io::stdin();
        let mut reader = stdin.lock().lines();

        while let Some(Ok(line)) = reader.next() {
            let request: Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(_) => continue,
            };

            let id = request["id"].clone();
            let method = request["method"].as_str().unwrap_or_default();

            match method {
                "listTools" => {
                    let tools = self.registry.get_schemas();
                    let response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": { "tools": tools }
                    });
                    println!("{}", response);
                }
                "callTool" => {
                    let name = request["params"]["name"].as_str().unwrap_or_default();
                    let args = request["params"]["arguments"].clone();

                    let registry = &self.registry;
                    // We need a way to run async in a sync loop or make run async
                    // Actually run is already async!
                    match registry.call_tool(name, args).await {
                        Ok(res) => {
                            let response = json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": { "content": [{ "type": "text", "text": res.to_string() }] }
                            });
                            println!("{}", response);
                        }
                        Err(e) => {
                            let response = json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "error": { "code": -32603, "message": e.to_string() }
                            });
                            println!("{}", response);
                        }
                    }
                }
                _ => {
                    let response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32601, "message": "Method not found" }
                    });
                    println!("{}", response);
                }
            }
        }

        Ok(())
    }
}
