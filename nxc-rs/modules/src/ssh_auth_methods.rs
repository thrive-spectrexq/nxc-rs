use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{ssh::SshSession, NxcSession};
use serde_json::json;
use tracing::info;
use std::net::TcpStream;

pub struct SshAuthMethods {}

impl SshAuthMethods {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for SshAuthMethods {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for SshAuthMethods {
    fn name(&self) -> &'static str {
        "ssh_auth_methods"
    }

    fn description(&self) -> &'static str {
        "Queries the SSH daemon to retrieve the authentication methods natively supported for a given user."
    }

    fn supported_protocols(&self) -> &[&str] {
        &["ssh"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption {
                name: "USERNAME".to_string(),
                description: "Target user context to request properties for (default: root)".to_string(),
                required: false,
                default: Some("root".to_string()),
            },
        ]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let ssh_sess = session
            .as_any()
            .downcast_ref::<SshSession>()
            .ok_or_else(|| anyhow!("Module requires an SSH session"))?;

        let username = opts.get("USERNAME").map(|s| s.as_str()).unwrap_or("root").to_string();
        let target = ssh_sess.target.clone();
        let port = ssh_sess.port;

        info!("Enumerating supported SSH auth methods for '{}' on {}:{}", username, target, port);

        // SSH connections from ssh2 crate are blocking, so we use spawn_blocking (which is completely acceptable and common here)
        let result = tokio::task::spawn_blocking(move || -> Result<(String, bool, Vec<String>)> {
            let addr = format!("{}:{}", target, port);
            let mut output = String::from("SSH Authentication Methods Results:\n");
            
            let tcp = TcpStream::connect_timeout(
                &addr.parse().map_err(|e| anyhow!("Invalid address: {}", e))?,
                std::time::Duration::from_secs(5),
            )?;
            tcp.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;

            let mut sess = ssh2::Session::new()?;
            sess.set_timeout(5000);
            sess.set_tcp_stream(tcp);
            sess.handshake()?;

            // auth_methods acts by making a dummy authentication request.
            // It will usually return a comma-separated list of strings: "publickey,password,keyboard-interactive"
            let methods_raw = sess.auth_methods(&username)?;
            let methods: Vec<String> = methods_raw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();

            output.push_str(&format!("  [*] Target Username: {}\n", username));
            
            if methods.is_empty() {
                output.push_str("  [-] No authentication methods gracefully returned by the server.\n");
            } else {
                 output.push_str(&format!("  [+] Supported Methods (count: {}):\n", methods.len()));
                 for method in &methods {
                      output.push_str(&format!("      -> {}\n", method));
                 }
                 
                 // Add security analysis context
                 if methods.contains(&"password".to_string()) || methods.contains(&"keyboard-interactive".to_string()) {
                      output.push_str("\n      [!] WARNING: Target supports password/interactive authentication. Prone to brute-force attacks.\n");
                 } else if methods.contains(&"publickey".to_string()) {
                      output.push_str("\n      [+] SECURE: Target strictly enforces Public Key authentication. Resistant to traditional credential brute forcing.\n");
                 }
            }
            
            Ok((output, sess.authenticated(), methods))
        }).await??;

        Ok(ModuleResult {
            success: true,
            output: result.0,
            data: json!({ "supported_methods": result.2 }),
            credentials: vec![],
        })
    }
}
