use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::Result;
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};

pub struct SmbSession {
    pub target: String,
    pub admin: bool,
}

impl NxcSession for SmbSession {
    fn protocol(&self) -> &'static str {
        "smb"
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn is_admin(&self) -> bool {
        self.admin
    }
}

pub struct SmbProtocol {}

impl SmbProtocol {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for SmbProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcProtocol for SmbProtocol {
    fn name(&self) -> &'static str {
        "smb"
    }

    fn default_port(&self) -> u16 {
        445
    }

    fn supports_exec(&self) -> bool {
        true
    }

    fn supported_modules(&self) -> &[&str] {
        &["secretsdump", "sam"]
    }

    async fn connect(&self, target: &str, _port: u16) -> Result<Box<dyn NxcSession>> {
        // Simulate network latency
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        
        // Mock connection failure for a specific IP for testing
        if target.contains("192.168.1.99") {
            return Err(anyhow::anyhow!("Connection refused"));
        }

        Ok(Box::new(SmbSession {
            target: target.to_string(),
            admin: false,
        }))
    }

    async fn authenticate(
        &self,
        _session: &mut dyn NxcSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        // Simulate auth latency
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Mock auth logic
        if creds.username == "admin" && creds.password.as_deref() == Some("Password123!") {
            // Downcast might fail in a real scenario, but this is a mock
            // To mutate the session properly, we should ideally have a way.
            // For now, we'll just return a success AuthResult that indicates admin.
            Ok(AuthResult::success(true))
        } else if creds.username == "user" && creds.password.as_deref() == Some("pass") {
            Ok(AuthResult::success(false))
        } else {
            Ok(AuthResult::failure("STATUS_LOGON_FAILURE", Some("0xC000006D")))
        }
    }

    async fn execute(&self, _session: &dyn NxcSession, cmd: &str) -> Result<CommandOutput> {
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        Ok(CommandOutput {
            stdout: format!("Executed mock command: {}", cmd),
            stderr: String::new(),
            exit_code: Some(0),
        })
    }
}
