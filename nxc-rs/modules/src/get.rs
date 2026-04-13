//! # get — Download File Module
//!
//! Downloads a file from the remote target (SMB/FTP).

use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;
use tracing::info;

pub struct GetModule;

impl GetModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GetModule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for GetModule {
    fn name(&self) -> &'static str {
        "get"
    }

    fn description(&self) -> &'static str {
        "Download a file from the remote target"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["smb", "ftp"]
    }

    fn options(&self) -> Vec<crate::ModuleOption> {
        vec![crate::ModuleOption {
            name: "PATH".to_string(),
            description: "Remote path to download (e.g. C$\\Windows\\win.ini)".to_string(),
            required: true,
            default: None,
        }]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let path = opts.get("PATH").ok_or_else(|| anyhow::anyhow!("PATH option is required"))?;

        match session.protocol() {
            "smb" => self.run_smb(session, path).await,
            "ftp" => self.run_ftp(session, path).await,
            _ => Err(anyhow::anyhow!("Module only supports SMB and FTP")),
        }
    }
}

impl GetModule {
    async fn run_smb(&self, session: &mut dyn NxcSession, path_full: &str) -> Result<ModuleResult> {
        let smb_sess = session
            .as_any()
            .downcast_ref::<nxc_protocols::smb::SmbSession>()
            .ok_or_else(|| anyhow::anyhow!("Invalid session"))?;
        let protocol = nxc_protocols::smb::SmbProtocol::new();

        let (share, path) = path_full
            .split_once('\\')
            .ok_or_else(|| anyhow::anyhow!("PATH must be in format SHARE\\path"))?;

        info!("Get: Downloading {}\\{} from {}", share, path, session.target());
        match protocol.download_file(smb_sess, share, path).await {
            Ok(data) => {
                let local_path = format!("loot/{}_{}", session.target(), path.replace('\\', "_"));
                std::fs::create_dir_all("loot")?;
                std::fs::write(&local_path, &data)?;

                Ok(ModuleResult {
                    credentials: vec![],
                    success: true,
                    output: format!("[+] Successfully downloaded {path_full} to {local_path}"),
                    data: serde_json::json!({ "local_path": local_path, "size": data.len() }),
                })
            }
            Err(e) => Ok(ModuleResult {
                credentials: vec![],
                success: false,
                output: format!("[-] Failed to download: {e}"),
                data: serde_json::Value::Null,
            }),
        }
    }

    async fn run_ftp(&self, session: &mut dyn NxcSession, path: &str) -> Result<ModuleResult> {
        let ftp_sess = session
            .as_any()
            .downcast_ref::<nxc_protocols::ftp::FtpSession>()
            .ok_or_else(|| anyhow::anyhow!("Invalid session"))?;
        let addr = format!("{}:{}", ftp_sess.target, ftp_sess.port);

        info!("Get: FTP download '{}' from {}", path, addr);
        let mut ftp_stream = suppaftp::tokio::AsyncFtpStream::connect(&addr).await?;

        let empty = String::new();
        let pass = ftp_sess.credentials.password.as_ref().unwrap_or(&empty);
        ftp_stream.login(&ftp_sess.credentials.username, pass).await?;

        // Transfer file
        let mut reader = ftp_stream.retr_as_stream(path).await?;
        let mut buffer = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut buffer).await?;
        ftp_stream.finalize_retr_stream(reader).await?;

        // Save to loot directory
        let filename = path.rsplit('/').next().unwrap_or(path);
        let local_path = format!("loot/{}_{}", ftp_sess.target, filename);
        std::fs::create_dir_all("loot")?;
        std::fs::write(&local_path, &buffer)?;

        Ok(ModuleResult {
            credentials: vec![],
            success: true,
            output: format!("[+] Downloaded {} ({} bytes) → {}", path, buffer.len(), local_path),
            data: serde_json::json!({ "local_path": local_path, "size": buffer.len() }),
        })
    }
}
