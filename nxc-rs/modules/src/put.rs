//! # put — Upload File Module
//!
//! Uploads a file to the remote target (SMB/FTP).

use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;
use tracing::info;

pub struct PutModule;

impl PutModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PutModule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for PutModule {
    fn name(&self) -> &'static str {
        "put"
    }

    fn description(&self) -> &'static str {
        "Upload a local file to the remote target"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["smb", "ftp"]
    }

    fn options(&self) -> Vec<crate::ModuleOption> {
        vec![
            crate::ModuleOption {
                name: "LOCAL".to_string(),
                description: "Local file path to upload".to_string(),
                required: true,
                default: None,
            },
            crate::ModuleOption {
                name: "REMOTE".to_string(),
                description: "Remote path (e.g. C$\\Windows\\Temp\\file.exe)".to_string(),
                required: true,
                default: None,
            },
        ]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let local = opts.get("LOCAL").ok_or_else(|| anyhow::anyhow!("LOCAL option is required"))?;
        let remote =
            opts.get("REMOTE").ok_or_else(|| anyhow::anyhow!("REMOTE option is required"))?;

        match session.protocol() {
            "smb" => self.run_smb(session, local, remote).await,
            "ftp" => self.run_ftp(session, local, remote).await,
            _ => Err(anyhow::anyhow!("Module only supports SMB and FTP")),
        }
    }
}

impl PutModule {
    async fn run_smb(
        &self,
        session: &mut dyn NxcSession,
        local: &str,
        remote_full: &str,
    ) -> Result<ModuleResult> {
        let smb_sess = session
            .as_any()
            .downcast_ref::<nxc_protocols::smb::SmbSession>()
            .ok_or_else(|| anyhow::anyhow!("Invalid session"))?;
        let protocol = nxc_protocols::smb::SmbProtocol::new();

        let (share, path) = remote_full
            .split_once('\\')
            .ok_or_else(|| anyhow::anyhow!("REMOTE must be in format SHARE\\path"))?;

        let data = std::fs::read(local)?;
        info!("Put: Uploading {} to {}\\{} on {}", local, share, path, session.target());

        match protocol.upload_file(smb_sess, share, path, &data).await {
            Ok(_) => Ok(ModuleResult {
                credentials: vec![],
                success: true,
                output: format!("[+] Successfully uploaded {local} to {remote_full}"),
                data: serde_json::json!({ "remote_path": remote_full, "size": data.len() }),
            }),
            Err(e) => Ok(ModuleResult {
                credentials: vec![],
                success: false,
                output: format!("[-] Failed to upload: {e}"),
                data: serde_json::Value::Null,
            }),
        }
    }

    async fn run_ftp(
        &self,
        session: &mut dyn NxcSession,
        local: &str,
        remote: &str,
    ) -> Result<ModuleResult> {
        let ftp_sess = session
            .as_any()
            .downcast_ref::<nxc_protocols::ftp::FtpSession>()
            .ok_or_else(|| anyhow::anyhow!("Invalid session"))?;
        let addr = format!("{}:{}", ftp_sess.target, ftp_sess.port);

        info!("Put: FTP upload '{}' → '{}' on {}", local, remote, addr);
        let data = std::fs::read(local)?;

        let mut ftp_stream = suppaftp::tokio::AsyncFtpStream::connect(&addr).await?;

        let empty = String::new();
        let pass = ftp_sess.credentials.password.as_ref().unwrap_or(&empty);
        ftp_stream.login(&ftp_sess.credentials.username, pass).await?;

        let mut cursor = std::io::Cursor::new(&data);
        ftp_stream.put_file(remote, &mut cursor).await?;

        Ok(ModuleResult {
            credentials: vec![],
            success: true,
            output: format!("[+] Uploaded {} ({} bytes) → {}", local, data.len(), remote),
            data: serde_json::json!({ "remote_path": remote, "size": data.len() }),
        })
    }
}
