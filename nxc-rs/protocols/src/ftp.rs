//! # FTP Protocol Handler
//!
//! FTP protocol implementation handling banner grabbing and
//! credential authentication over port 21.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use std::time::Duration;
use suppaftp::tokio::AsyncFtpStream;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tracing::{debug, info};

pub struct FtpSession {
    pub target: String,
    pub port: u16,
    pub banner: String,
    pub admin: bool,
    pub credentials: Credentials,
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
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
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
        &["ls", "get", "put", "ftp_anon"]
    }

    async fn connect(
        &self,
        target: &str,
        port: u16,
        _proxy: Option<&str>,
    ) -> Result<Box<dyn NxcSession>> {
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
            credentials: Credentials::null_session(),
        }))
    }

    async fn authenticate(
        &self,
        session: &mut dyn NxcSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        let username = creds.username.clone();
        let password = creds.password.clone().unwrap_or_default();

        let ftp_sess = session
            .as_any()
            .downcast_ref::<FtpSession>()
            .ok_or_else(|| anyhow::anyhow!("Invalid session type"))?;
        let addr = format!("{}:{}", ftp_sess.target, ftp_sess.port);

        debug!("FTP: Authenticating {}@{}", username, addr);

        let mut ftp_stream = AsyncFtpStream::connect(&addr).await?;

        match ftp_stream.login(&username, &password).await {
            Ok(_) => {
                info!("FTP: Auth success for {}@{}", username, addr);
                // Update session with successful credentials
                let ftp_sess_mut = session
                    .as_any_mut()
                    .downcast_mut::<FtpSession>()
                    .ok_or_else(|| anyhow::anyhow!("Invalid session type"))?;
                ftp_sess_mut.credentials = creds.clone();
                Ok(AuthResult::success(false)) // FTP doesn't really have "admin"
            }
            Err(e) => {
                debug!("FTP: Auth failed for {}@{}: {}", username, addr, e);
                Ok(AuthResult::failure(
                    &format!("FTP Auth failed: {}", e),
                    None,
                ))
            }
        }
    }

    async fn execute(&self, _session: &dyn NxcSession, _cmd: &str) -> Result<CommandOutput> {
        Err(anyhow!("FTP does not support explicit command execution."))
    }

    async fn read_file(
        &self,
        session: &dyn NxcSession,
        _share: &str,
        path: &str,
    ) -> Result<Vec<u8>> {
        let ftp_sess = session
            .downcast_ref::<FtpSession>()
            .ok_or_else(|| anyhow!("Invalid session"))?;
        let addr = format!("{}:{}", ftp_sess.target, ftp_sess.port);
        let mut ftp_stream = AsyncFtpStream::connect(&addr).await?;

        let empty = String::new();
        let pass = ftp_sess.credentials.password.as_ref().unwrap_or(&empty);
        ftp_stream
            .login(&ftp_sess.credentials.username, pass)
            .await?;

        let mut reader = ftp_stream.retr_as_stream(path).await?;
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).await?;
        ftp_stream.finalize_retr_stream(reader).await?;
        Ok(buffer)
    }

    async fn write_file(
        &self,
        session: &dyn NxcSession,
        _share: &str,
        path: &str,
        data: &[u8],
    ) -> Result<()> {
        let ftp_sess = session
            .downcast_ref::<FtpSession>()
            .ok_or_else(|| anyhow!("Invalid session"))?;
        let addr = format!("{}:{}", ftp_sess.target, ftp_sess.port);
        let mut ftp_stream = AsyncFtpStream::connect(&addr).await?;

        let empty = String::new();
        let pass = ftp_sess.credentials.password.as_ref().unwrap_or(&empty);
        ftp_stream
            .login(&ftp_sess.credentials.username, pass)
            .await?;

        let mut cursor = std::io::Cursor::new(data);
        ftp_stream.put_file(path, &mut cursor).await?;
        Ok(())
    }
}

impl FtpProtocol {
    /// Helper to list files in the current directory.
    pub async fn list_files(
        &self,
        target: &str,
        port: u16,
        creds: &Credentials,
    ) -> Result<Vec<String>> {
        let addr = format!("{}:{}", target, port);
        let mut ftp_stream = AsyncFtpStream::connect(&addr).await?;

        let username = creds.username.clone();
        let password = creds.password.clone().unwrap_or_default();

        ftp_stream.login(&username, &password).await?;

        let list = ftp_stream.list(None).await?;
        Ok(list)
    }
}
