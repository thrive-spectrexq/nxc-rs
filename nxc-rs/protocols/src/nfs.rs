//! # NFS Protocol Handler
//!
//! NFS protocol implementation connecting to Portmap (Port 111)
//! to enumerate NFS daemon availability.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

pub struct NfsSession {
    pub target: String,
    pub port: u16,
    pub admin: bool,
}

impl NxcSession for NfsSession {
    fn protocol(&self) -> &'static str {
        "nfs"
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

pub struct NfsProtocol {
    pub timeout: Duration,
}

impl NfsProtocol {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(10),
        }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl Default for NfsProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcProtocol for NfsProtocol {
    fn name(&self) -> &'static str {
        "nfs"
    }

    fn default_port(&self) -> u16 {
        111 // Portmap
    }

    fn supports_exec(&self) -> bool {
        false // NFS is restricted to file management
    }

    fn supported_modules(&self) -> &[&str] {
        &["ls", "get", "put", "shares"]
    }

    async fn connect(&self, target: &str, port: u16) -> Result<Box<dyn NxcSession>> {
        let addr = format!("{}:{}", target, port);
        debug!("NFS: Connecting to Portmap on {}", addr);

        let timeout_fut = tokio::time::timeout(self.timeout, TcpStream::connect(&addr));
        let mut stream = match timeout_fut.await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(anyhow!("Connection refused or unreachable: {}", e)),
            Err(_) => return Err(anyhow!("Connection timeout to {}", addr)),
        };

        // Simplified DCERPC Bind / Portmap Ping
        // Magic byte sequence for requesting port mapping (rpcbind GETPORT)
        let rpc_bind: [u8; 60] = [
            0x80, 0x00, 0x00, 0x34, // Fragment header
            0x00, 0x00, 0x00, 0x01, // XID
            0x00, 0x00, 0x00, 0x00, // CALL (0)
            0x00, 0x00, 0x00, 0x02, // RPC Version (2)
            0x00, 0x01, 0x86, 0xa0, // Program: 100000 (Portmap)
            0x00, 0x00, 0x00, 0x02, // Version: 2
            0x00, 0x00, 0x00, 0x03, // Procedure: 3 (GETPORT)
            0x00, 0x00, 0x00, 0x00, // Credentials Flavor (AUTH_NULL)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Verifier Flavor (AUTH_NULL)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x86, 0xa3, // Requested Program: 100003 (NFS)
            0x00, 0x00, 0x00, 0x03, // Req. Version: 3
            0x00, 0x00, 0x00, 0x06, // Proto: 6 (TCP)
            0x00, 0x00, 0x00, 0x00, // Port: 0 (Let server respond with port)
        ];

        let _ = stream.write_all(&rpc_bind).await;

        // Wait for the server to respond with the port mapper output. We don't parse it fully
        // to get the true Mount port for this stub, just asserting the response confirms Portmap presence.
        let mut resp = vec![0; 28];
        let read_fut = tokio::time::timeout(self.timeout, stream.read_exact(&mut resp));

        if let Err(e) = read_fut.await {
            return Err(anyhow!("NFS Portmap daemon unresponsive: {}", e));
        }

        info!(
            "NFS: Connected to Portmap on {} and requested NFS mappings",
            addr
        );

        Ok(Box::new(NfsSession {
            target: target.to_string(),
            port,
            admin: false,
        }))
    }

    async fn authenticate(
        &self,
        _session: &mut dyn NxcSession,
        _creds: &Credentials,
    ) -> Result<AuthResult> {
        // NFS doesn't typically have "authentication" in the traditional USER/PASS sense for listing.
        // It relies on UID/GID which we can provide in RPC headers for file access,
        // but for share listing (MOUNT DUMP), it usually just works if the service is exposed.
        Ok(AuthResult::success(false))
    }

    async fn execute(&self, _session: &dyn NxcSession, _cmd: &str) -> Result<CommandOutput> {
        Err(anyhow!("NFS does not support explicit command execution."))
    }
}

impl NfsProtocol {
    /// Helper to list NFS exports via the MOUNT service.
    pub async fn list_exports(&self, target: &str) -> Result<Vec<String>> {
        // 1. Get port for MOUNT service (100005) from Portmap (111)
        let mount_port = self.get_rpc_port(target, 100005, 3).await?;
        if mount_port == 0 {
            return Err(anyhow!("NFS MOUNT service not found on {}", target));
        }

        debug!("NFS: Found MOUNT service on port {}", mount_port);

        // 2. Connect to MOUNT service
        let addr = format!("{}:{}", target, mount_port);
        let mut stream = TcpStream::connect(&addr).await?;

        // 3. Send MOUNT DUMP (Procedure 2)
        // RPC Header: XID, CALL, RPC_VER(2), PROG(100005), PROG_VER(3), PROC(2), AUTH_NULL, AUTH_NULL
        let rpc_call = vec![
            0x80, 0x00, 0x00, 0x28, // Record marking (Fragment header)
            0x00, 0x00, 0x00, 0x02, // XID
            0x00, 0x00, 0x00, 0x00, // CALL (0)
            0x00, 0x00, 0x00, 0x02, // RPC Version (2)
            0x00, 0x01, 0x86, 0xa5, // Program: 100005 (Mount)
            0x00, 0x00, 0x00, 0x03, // Version: 3
            0x00, 0x00, 0x00, 0x02, // Procedure: 2 (DUMP)
            0x00, 0x00, 0x00, 0x00, // Credentials Flavor (AUTH_NULL)
            0x00, 0x00, 0x00, 0x00, // Credentials Length (0)
            0x00, 0x00, 0x00, 0x00, // Verifier Flavor (AUTH_NULL)
            0x00, 0x00, 0x00, 0x00, // Verifier Length (0)
        ];

        stream.write_all(&rpc_call).await?;

        // 4. Read response
        let mut resp_header = vec![0; 24];
        stream.read_exact(&mut resp_header).await?;

        // Simple check for RPC_REPLY (1) and MSG_ACCEPTED (0)
        if resp_header[4..8] != [0x00, 0x00, 0x00, 0x01] {
            return Err(anyhow!("NFS MOUNT DUMP: Invalid RPC reply"));
        }

        let mut body = Vec::new();
        stream.read_to_end(&mut body).await?;

        // 5. Parse XDR list of exports
        // Format: [1, length, export_name, 1, length, host_name, ...] terminated by 0
        let mut exports = Vec::new();
        let mut pos = 0;

        while pos + 4 <= body.len() && body[pos + 3] == 1 {
            pos += 4;
            if pos + 4 > body.len() { break; }
            let len = u32::from_be_bytes(body[pos..pos+4].try_into().unwrap()) as usize;
            pos += 4;
            let aligned_len = (len + 3) & !3;
            if pos + aligned_len > body.len() { break; }
            
            let export = String::from_utf8_lossy(&body[pos..pos+len]).to_string();
            exports.push(export);
            pos += aligned_len;

            // Skip the next segment (host list for this export)
            if pos + 4 > body.len() { break; }
            while pos + 4 <= body.len() && body[pos + 3] == 1 {
                pos += 4;
                if pos + 4 > body.len() { break; }
                let h_len = u32::from_be_bytes(body[pos..pos+4].try_into().unwrap()) as usize;
                pos += 4;
                pos += (h_len + 3) & !3;
                if pos + 4 > body.len() { break; }
            }
            pos += 4; // Skip the terminating 0 for this export's host list
        }

        Ok(exports)
    }

    async fn get_rpc_port(&self, target: &str, program: u32, version: u32) -> Result<u16> {
        let mut stream = TcpStream::connect(format!("{}:111", target)).await?;
        
        let mut rpc_bind = vec![
            0x80, 0x00, 0x00, 0x34, // Fragment header
            0x00, 0x00, 0x00, 0x01, // XID
            0x00, 0x00, 0x00, 0x00, // CALL (0)
            0x00, 0x00, 0x00, 0x02, // RPC Version (2)
            0x00, 0x01, 0x86, 0xa0, // Program: 100000 (Portmap)
            0x00, 0x00, 0x00, 0x02, // Version: 2
            0x00, 0x00, 0x00, 0x03, // Procedure: 3 (GETPORT)
            0x00, 0x00, 0x00, 0x00, // Credentials Flavor (AUTH_NULL)
            0x00, 0x00, 0x00, 0x00, // Credentials Length (0)
            0x00, 0x00, 0x00, 0x00, // Verifier Flavor (AUTH_NULL)
            0x00, 0x00, 0x00, 0x00, // Verifier Length (0)
        ];
        
        rpc_bind.extend_from_slice(&program.to_be_bytes());
        rpc_bind.extend_from_slice(&version.to_be_bytes());
        rpc_bind.extend_from_slice(&6u32.to_be_bytes()); // Proto: TCP (6)
        rpc_bind.extend_from_slice(&0u32.to_be_bytes()); // Port: 0
        
        stream.write_all(&rpc_bind).await?;
        
        let mut resp = vec![0; 28];
        stream.read_exact(&mut resp).await?;
        
        let port = u32::from_be_bytes(resp[24..28].try_into().unwrap()) as u16;
        Ok(port)
    }
}
