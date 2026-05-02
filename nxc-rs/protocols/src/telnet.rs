//! # Telnet Protocol Handler
//!
//! Telnet protocol implementation for NetExec-RS.
//! Provides authentication and basic command execution.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};
use tracing::{debug, info};

// ─── Telnet Session ───────────────────────────────────────────────

pub struct TelnetSession {
    pub target: String,
    pub port: u16,
    pub admin: bool,
    pub stream: Arc<Mutex<TcpStream>>,
}

impl NxcSession for TelnetSession {
    fn protocol(&self) -> &'static str {
        "telnet"
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn is_admin(&self) -> bool {
        self.admin
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

// ─── Telnet Protocol Handler ──────────────────────────────────────

pub struct TelnetProtocol;

impl TelnetProtocol {
    pub fn new() -> Self {
        Self
    }

    // Read from stream until one of the prompts is found or timeout occurs
    async fn read_until(stream: &mut TcpStream, prompts: &[&str], timeout_sec: u64) -> Result<String> {
        let mut buffer = [0; 4096];
        let mut output = String::new();

        let read_future = async {
            loop {
                match stream.read(&mut buffer).await {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        // Very basic filter to drop non-printable chars / telnet negotiations
                        // In a real robust implementation, we'd process IAC (0xFF) sequences
                        let chunk = String::from_utf8_lossy(&buffer[..n]);
                        let filtered: String = chunk.chars().filter(|c| c.is_ascii() && !c.is_control() || *c == '\n' || *c == '\r' || *c == '\t').collect();

                        output.push_str(&filtered);

                        let lower_out = output.to_lowercase();
                        for prompt in prompts {
                            if lower_out.contains(&prompt.to_lowercase()) {
                                return Ok::<String, anyhow::Error>(output.clone());
                            }
                        }
                    }
                    Err(e) => return Err(anyhow::anyhow!("Read error: {e}")),
                }
            }
            Ok(output.clone())
        };

        match timeout(Duration::from_secs(timeout_sec), read_future).await {
            Ok(res) => res,
            Err(_) => {
                debug!("Timeout reading from telnet");
                Ok(output) // Return what we got so far on timeout
            }
        }
    }
}

impl Default for TelnetProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcProtocol for TelnetProtocol {
    fn name(&self) -> &'static str {
        "telnet"
    }

    fn default_port(&self) -> u16 {
        23
    }

    fn supports_exec(&self) -> bool {
        true
    }

    async fn connect(
        &self,
        target: &str,
        port: u16,
        _proxy: Option<&str>,
    ) -> Result<Box<dyn NxcSession>> {
        debug!("Telnet: Connecting to {}:{}", target, port);

        // Simple TCP connect
        let stream = match timeout(Duration::from_secs(5), TcpStream::connect((target, port))).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(anyhow!("Failed to connect to {target}:{port}: {e}")),
            Err(_) => return Err(anyhow!("Connection timeout to {target}:{port}")),
        };

        Ok(Box::new(TelnetSession {
            target: target.to_string(),
            port,
            admin: false,
            stream: Arc::new(Mutex::new(stream)),
        }))
    }

    async fn authenticate(
        &self,
        session: &mut dyn NxcSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        let telnet_sess = session
            .as_any_mut()
            .downcast_mut::<TelnetSession>()
            .ok_or_else(|| anyhow!("Invalid session type"))?;

        let mut stream = telnet_sess.stream.lock().await;

        // Wait for login prompt
        let login_prompts = ["login:", "username:", "user:"];
        let out = Self::read_until(&mut stream, &login_prompts, 5).await?;

        let mut found_prompt = false;
        for p in &login_prompts {
            if out.to_lowercase().contains(p) {
                found_prompt = true;
                break;
            }
        }

        if !found_prompt && !out.is_empty() {
            debug!("Did not find expected login prompt. Got: {}", out);
        }

        // Send username
        let user_line = format!("{}\r\n", creds.username);
        if let Err(e) = stream.write_all(user_line.as_bytes()).await {
            return Ok(AuthResult::failure(&format!("Write username failed: {e}"), None));
        }

        // Wait for password prompt
        if let Some(ref pass) = creds.password {
            let pass_prompts = ["password:", "pass:"];
            let _out_pass = Self::read_until(&mut stream, &pass_prompts, 5).await?;

            let pass_line = format!("{pass}\r\n");
            if let Err(e) = stream.write_all(pass_line.as_bytes()).await {
                return Ok(AuthResult::failure(&format!("Write password failed: {e}"), None));
            }
        }

        // Wait for shell prompt
        let shell_prompts = ["$", "#", ">", "%", "C:\\"];
        let final_out = Self::read_until(&mut stream, &shell_prompts, 5).await?;

        let mut success = false;
        let mut is_admin = false;
        for p in &shell_prompts {
            if final_out.contains(p) {
                success = true;
                if *p == "#" {
                    is_admin = true;
                }
                break;
            }
        }

        // Sometimes "Login incorrect" is clear
        if final_out.to_lowercase().contains("incorrect") || final_out.to_lowercase().contains("invalid") {
            success = false;
        }

        if success {
            info!("Telnet: Authenticated successfully on {}:{}", telnet_sess.target, telnet_sess.port);
            telnet_sess.admin = is_admin;
            Ok(AuthResult::success(is_admin))
        } else {
            debug!("Telnet: Authentication failed for {}:{}, Output: {}", telnet_sess.target, telnet_sess.port, final_out);
            Ok(AuthResult::failure("Authentication failed or prompt not found", None))
        }
    }

    async fn execute(&self, session: &dyn NxcSession, cmd: &str) -> Result<CommandOutput> {
        let telnet_sess = session
            .as_any()
            .downcast_ref::<TelnetSession>()
            .ok_or_else(|| anyhow!("Invalid session type"))?;

        let mut stream = telnet_sess.stream.lock().await;

        // Send command
        let cmd_line = format!("{cmd}\r\n");
        stream.write_all(cmd_line.as_bytes()).await?;

        // Wait for shell prompt to return
        let shell_prompts = ["$", "#", ">", "%", "C:\\"];
        let output = Self::read_until(&mut stream, &shell_prompts, 10).await?;

        Ok(CommandOutput {
            stdout: output.trim().to_string(),
            stderr: String::new(),
            exit_code: Some(0), // We don't have a reliable way to get exit code in raw telnet easily
        })
    }
}
