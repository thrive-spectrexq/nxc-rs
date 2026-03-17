//! # NFS Protocol Handler
//!
//! NFS protocol implementation connecting to Portmap (Port 111) 
//! to enumerate NFS daemon availability.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
            0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, // Verifier Flavor (AUTH_NULL)
            0x00, 0x00, 0x00, 0x00, 
            0x00, 0x01, 0x86, 0xa3, // Requested Program: 100003 (NFS)
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

        info!("NFS: Connected to Portmap on {} and requested NFS mappings", addr);

        Ok(Box::new(NfsSession {
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
        
        let nfs_sess = unsafe { &*(session as *const dyn NxcSession as *const NfsSession) };
        let addr = format!("{}:{}", nfs_sess.target, nfs_sess.port);
        
        debug!("NFS: Tracking auth flow {}@{}", username, addr);

        Ok(AuthResult::failure("NFS shares validation using UID 0 (root) and GID impersonation logic pending implementation", None))
    }

    async fn execute(&self, _session: &dyn NxcSession, _cmd: &str) -> Result<CommandOutput> {
        Err(anyhow!("NFS does not support explicit command execution."))
    }
}
