//! # WMI Protocol Handler
//!
//! WMI protocol implementation using DCOM and DCERPC logic over port 135.
//! Represents the connection flow to `ncacn_ip_tcp`.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::{debug, info};

pub struct WmiSession {
    pub target: String,
    pub port: u16,
    pub admin: bool,
}

impl NxcSession for WmiSession {
    fn protocol(&self) -> &'static str {
        "wmi"
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn is_admin(&self) -> bool {
        self.admin
    }
}

pub struct WmiProtocol {
    pub timeout: Duration,
}

impl WmiProtocol {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(10),
        }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl Default for WmiProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcProtocol for WmiProtocol {
    fn name(&self) -> &'static str {
        "wmi"
    }

    fn default_port(&self) -> u16 {
        135 // RPC Endpoint Mapper
    }

    fn supports_exec(&self) -> bool {
        true // WMI executes via Win32_Process class methods
    }

    fn supported_modules(&self) -> &[&str] {
        &["enum_host_info"]
    }

    async fn connect(&self, target: &str, port: u16) -> Result<Box<dyn NxcSession>> {
        let addr = format!("{}:{}", target, port);
        debug!("WMI: Connecting RPC Endpoint Mapper on {}", addr);

        let timeout_fut = tokio::time::timeout(self.timeout, TcpStream::connect(&addr));
        let mut stream = match timeout_fut.await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(anyhow!("Connection refused or unreachable: {}", e)),
            Err(_) => return Err(anyhow!("Connection timeout to {}", addr)),
        };

        // Issue a basic DCERPC Bind Request for the Endpoint Mapper (epm)
        // UUID: E1AF8308-5D1F-11C9-91A4-08002B14A0FA, Vers: 3.0
        // Equivalent to python impacket dcerpc bind()
        let bind_req: [u8; 72] = [
            0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8,
            0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x02, 0x00, 0x08, 0x83, 0xaf, 0xe1,
            0x1f, 0x5d, 0xc9, 0x11, 0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa, 0x03, 0x00,
            0x00, 0x00,
        ];

        let _ = stream.write_all(&bind_req).await;

        info!("WMI: RPC connection established to {}", addr);

        Ok(Box::new(WmiSession {
            target: target.to_string(),
            port,
            admin: false,
        }))
    }

    async fn authenticate(
        &self,
        session: &mut dyn NxcSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        let username = creds.username.clone();

        let wmi_sess = unsafe { &*(session as *const dyn NxcSession as *const WmiSession) };
        let addr = format!("{}:{}", wmi_sess.target, wmi_sess.port);

        debug!("WMI: Authenticating {}@{} via DCOM", username, addr);

        // Executing WMI queries via DCOM requires triggering the RPC_C_AUTHN_WINNT handshake,
        // followed by executing methods on `IWbemLevel1Login::NTLMLogin` using `root/cimv2`.
        // Rust does not have an easy DCERPC protocol mapper like impacket natively available yet.

        Ok(AuthResult::failure(
            "WMI DCOM/IWbemLevel1Login explicit NTLM logic pending implementation",
            None,
        ))
    }

    async fn execute(&self, _session: &dyn NxcSession, _cmd: &str) -> Result<CommandOutput> {
        Err(anyhow!(
            "WMI explicit command execution (`Win32_Process.Create`) not yet ported."
        ))
    }
}
