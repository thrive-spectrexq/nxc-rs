use crate::{NetworkTool, ToolResult};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::io::Read;
use std::net::TcpStream;
use std::time::Instant;

pub struct SshTool;

#[async_trait]
impl NetworkTool for SshTool {
    fn name(&self) -> &'static str {
        "ssh_command"
    }
    fn description(&self) -> &'static str {
        "Execute a CLI command on a remote host via standard SSH"
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "host": { "type": "string", "description": "Remote host IP or hostname" },
                "command": { "type": "string", "description": "CLI command to execute" },
                "username": { "type": "string", "description": "SSH username" },
                "password": { "type": "string", "description": "SSH password (optional)" }
            },
            "required": ["host", "command", "username"]
        })
    }
    fn is_read_only(&self) -> bool {
        false
    }

    async fn execute(&self, input: Value) -> Result<ToolResult> {
        let host = input["host"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing host"))?;
        let command = input["command"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing command"))?;
        let username = input["username"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing username"))?;
        let password = input["password"].as_str();

        let start_time = Instant::now();

        let tcp = TcpStream::connect(format!("{}:22", host))?;
        let mut sess = ssh2::Session::new()?;
        sess.set_tcp_stream(tcp);
        sess.handshake()?;

        if let Some(pw) = password {
            sess.userauth_password(username, pw)?;
        } else {
            sess.userauth_agent(username)?;
        }

        let mut channel = sess.channel_session()?;
        channel.exec(command)?;

        let mut s = String::new();
        channel.read_to_string(&mut s)?;

        let mut stderr = String::new();
        channel.stderr().read_to_string(&mut stderr)?;

        channel.wait_close()?;
        let exit_status = channel.exit_status()?;

        let duration = start_time.elapsed().as_millis() as u64;

        Ok(ToolResult {
            success: exit_status == 0,
            output: format!(
                "ssh_command {} on {}: exit status {}",
                command, host, exit_status
            ),
            data: json!({
                "host": host,
                "stdout": s,
                "stderr": stderr,
                "exit_status": exit_status
            }),
            duration_ms: duration,
        })
    }
}
