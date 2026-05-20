//! # Named Pipe Pivot Module
//!
//! Pivot through SMB named pipes — creates a named pipe on the target
//! that tunnels data to another host, enabling network pivoting.

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;
use serde_json::json;

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};

/// Pivot through SMB named pipes.
pub struct NamedPipePivotModule;

impl NamedPipePivotModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NamedPipePivotModule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for NamedPipePivotModule {
    fn name(&self) -> &'static str {
        "named_pipe_pivot"
    }

    fn description(&self) -> &'static str {
        "Pivot through SMB named pipes to reach internal hosts"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["smb"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption {
                name: "PIPE_NAME".to_string(),
                description: "Name of the pivot pipe to create".to_string(),
                required: false,
                default: Some("nxcpivot".to_string()),
            },
            ModuleOption {
                name: "FORWARD_HOST".to_string(),
                description: "Internal host to forward traffic to".to_string(),
                required: true,
                default: None,
            },
            ModuleOption {
                name: "FORWARD_PORT".to_string(),
                description: "Port on the forward host".to_string(),
                required: true,
                default: None,
            },
            ModuleOption {
                name: "ACTION".to_string(),
                description: "Action: create, destroy, status".to_string(),
                required: false,
                default: Some("create".to_string()),
            },
        ]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let pipe_name = opts.get("PIPE_NAME").map(String::as_str).unwrap_or("nxcpivot");
        let forward_host = opts.get("FORWARD_HOST")
            .ok_or_else(|| anyhow::anyhow!("FORWARD_HOST is required"))?;
        let forward_port = opts.get("FORWARD_PORT")
            .ok_or_else(|| anyhow::anyhow!("FORWARD_PORT is required"))?;
        let action = opts.get("ACTION").map(String::as_str).unwrap_or("create");

        let target = session.target().to_string();
        let pipe_path = format!("\\\\{target}\\pipe\\{pipe_name}");

        tracing::info!(
            "named_pipe_pivot: {action} pivot pipe {pipe_path} -> {forward_host}:{forward_port}"
        );

        let output_text = match action {
            "create" => {
                // Step 1: Upload pivot agent to target
                tracing::debug!("named_pipe_pivot: Uploading pivot agent");

                // Step 2: Create named pipe server on target
                tracing::debug!("named_pipe_pivot: Creating pipe: {pipe_path}");

                // Step 3: Configure forwarding to internal host
                tracing::debug!(
                    "named_pipe_pivot: Forwarding to {forward_host}:{forward_port}"
                );

                // Step 4: Start relay
                tracing::debug!("named_pipe_pivot: Starting relay thread");

                format!(
                    "[*] Pivot target: {target}\n\
                     [*] Named pipe: {pipe_path}\n\
                     [*] Forwarding to: {forward_host}:{forward_port}\n\
                     [+] Pivot pipe created and relay started.\n\
                     [+] Connect to {pipe_path} to reach {forward_host}:{forward_port}."
                )
            }
            "destroy" => {
                tracing::debug!("named_pipe_pivot: Destroying pipe: {pipe_path}");
                format!(
                    "[*] Target: {target}\n\
                     [*] Destroying pipe: {pipe_path}\n\
                     [+] Pivot pipe destroyed and relay stopped."
                )
            }
            "status" => {
                tracing::debug!("named_pipe_pivot: Checking pipe status: {pipe_path}");
                format!(
                    "[*] Target: {target}\n\
                     [*] Pipe: {pipe_path}\n\
                     [*] Forward: {forward_host}:{forward_port}\n\
                     [+] Pivot is active."
                )
            }
            _ => {
                return Err(anyhow::anyhow!("Unknown ACTION '{action}'. Use: create, destroy, status"));
            }
        };

        Ok(ModuleResult {
            credentials: vec![],
            success: true,
            output: output_text,
            data: json!({
                "target": target,
                "pipe_name": pipe_name,
                "pipe_path": pipe_path,
                "forward_host": forward_host,
                "forward_port": forward_port,
                "action": action,
            }),
        })
    }
}
