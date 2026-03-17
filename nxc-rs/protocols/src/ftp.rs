//! # FTP Protocol Handler
//!
//! FTP protocol implementation handling banner grabbing and 
//! credential authentication over port 21.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::io::AsyncReadExt;
use tracing::{debug, info};

pub struct FtpSession {
    pub target: String,
    pub port: u16,
    pub banner: String,
    pub admin: bool,
}

impl NxcSession for FtpSession {
    fn protocol(&self) -> &'static str {
        "ftp"
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn is_admin(&self) -> bool {
        self.admin
    }
}

pub struct FtpProtocol {
    pub timeout: Duration,
}

impl FtpProtocol {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(10),
        }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl Default for FtpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcProtocol for FtpProtocol {
    fn name(&self) -> &'static str {
        "ftp"
    }

    fn default_port(&self) -> u16 {
        21
    }

    fn supports_exec(&self) -> bool {
        false // FTP is an enumeration and data transfer protocol
    }

    fn supported_modules(&self) -> &[&str] {
        &["ls", "get", "put"] 
    }

    async fn connect(&self, target: &str, port: u16) -> Result<Box<dyn NxcSession>> {
        let addr = format!("{}:{}", target, port);
        debug!("FTP: Connecting to {}", addr);

        let timeout_fut = tokio::time::timeout(self.timeout, TcpStream::connect(&addr));
        let mut stream = match timeout_fut.await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(anyhow!("Connection refused or unreachable: {}", e)),
            Err(_) => return Err(anyhow!("Connection timeout to {}", addr)),
        };

        // Grab the FTP welcome banner (should start with "220")
        let mut buf = vec![0; 1024];
        let mut banner = String::new();
        
        let read_fut = tokio::time::timeout(self.timeout, stream.read(&mut buf));
        if let Ok(Ok(n)) = read_fut.await {
            if n > 0 {
                banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
            }
        }

        if banner.is_empty() || !banner.starts_with("220") {
            return Err(anyhow!("Invalid or empty FTP welcome banner: {}", banner));
        }

        info!("FTP: Connected to {} (Banner: {})", addr, banner);

        Ok(Box::new(FtpSession {
            target: target.to_string(),
            port,
            banner,
            admin: false, // FTP doesn't really have "admin", just file perms
        }))
    }

    async fn authenticate(
        &self,
        session: &mut dyn NxcSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        let username = creds.username.clone();
        
        let ftp_sess = unsafe { &*(session as *const dyn NxcSession as *const FtpSession) };
        let addr = format!("{}:{}", ftp_sess.target, ftp_sess.port);
        
        debug!("FTP: Authenticating {}@{}", username, addr);

        // A full FTP implementation would establish the connection again here or pass the stream,
        // then dispatch the `USER <username>` and `PASS <password>` sequence, expecting `230 Logged in`.
        Ok(AuthResult::failure("FTP user/pass authentication sequence pending implementation", None))
    }

    async fn execute(&self, _session: &dyn NxcSession, _cmd: &str) -> Result<CommandOutput> {
        Err(anyhow!("FTP does not support explicit command execution."))
    }
}
