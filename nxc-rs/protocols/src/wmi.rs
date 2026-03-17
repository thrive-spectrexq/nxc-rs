//! # WMI Protocol Handler
//!
//! WMI protocol implementation using DCOM and DCERPC logic over port 135.
//! Represents the connection flow to `ncacn_ip_tcp`.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
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
        let wmi_sess = match session.downcast_mut::<WmiSession>() {
            Some(s) => s,
            None => return Err(anyhow!("Invalid session type for WMI")),
        };

        let addr = format!("{}:{}", wmi_sess.target, wmi_sess.port);
        debug!("WMI: Triggering EPM lookup on {}", addr);

        // 1. Connect to EPM (port 135)
        let mut stream = TcpStream::connect(&addr).await?;
        
        // 2. DCERPC Bind to EPM
        // UUID: E1AF8308-5D1F-11C9-91A4-08002B14A0FA (EPM)
        use crate::rpc::{DcerpcHeader, DcerpcBind, PacketType};
        let uuid_epm: [u8; 16] = [
            0x08, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11, 0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa
        ];
        
        let bind = DcerpcBind::new(uuid_epm, 3, 0);
        let bind_bytes = bind.to_bytes();
        let header = DcerpcHeader::new(PacketType::Bind, 1, (24 + bind_bytes.len()) as u16);
        
        let mut pkt = header.to_bytes();
        pkt.extend_from_slice(&bind_bytes);
        stream.write_all(&pkt).await?;
        
        // 3. Read BindAck
        let mut ack_hdr = [0u8; 24];
        stream.read_exact(&mut ack_hdr).await?;
        
        // In a full implementation, we'd now call EptMap to get the WMI port.
        // For the offensive MVP, successful Bind to EPM proves RPC connectivity.
        
        info!("WMI: RPC Bind to EPM successful on {}. Proceeding with DCOM/NTLM logic...", addr);

        Ok(AuthResult::failure(
            "WMI NTLM authentication over DCOM pending full NTLMSSP integration",
            None,
        ))
    }

    async fn execute(&self, _session: &dyn NxcSession, _cmd: &str) -> Result<CommandOutput> {
        Err(anyhow!(
            "WMI explicit command execution (`Win32_Process.Create`) not yet ported."
        ))
    }
}
