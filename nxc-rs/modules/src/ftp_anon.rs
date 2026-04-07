use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{ftp::FtpSession, NxcSession};
use serde_json::json;
use tracing::info;
use suppaftp::tokio::AsyncFtpStream;

pub struct FtpAnon {}

impl FtpAnon {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for FtpAnon {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for FtpAnon {
    fn name(&self) -> &'static str {
        "ftp_anon"
    }

    fn description(&self) -> &'static str {
        "Checks for FTP Anonymous login privileges and attempts to list the root directory."
    }

    fn supported_protocols(&self) -> &[&str] {
        &["ftp"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        _opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let ftp_sess = session
            .as_any()
            .downcast_ref::<FtpSession>()
            .ok_or_else(|| anyhow!("Module requires an FTP session"))?;

        let addr = format!("{}:{}", ftp_sess.target, ftp_sess.port);
        info!("Starting FTP Anonymous Login Check on {}", addr);

        let mut output = String::from("FTP Anonymous Login Results:\n");
        let mut anon_successful = false;
        let mut files = Vec::new();

        if let Ok(mut ftp_stream) = AsyncFtpStream::connect(&addr).await {
            // Attempt anonymous login
            if let Ok(_) = ftp_stream.login("anonymous", "anonymous@domain.com").await {
                anon_successful = true;
                output.push_str("  [+] VULNERABLE: Anonymous login successful!\n");

                // If successful, attempt to list the root directory
                if let Ok(list) = ftp_stream.list(None).await {
                    if list.is_empty() {
                        output.push_str("      -> Root directory is empty.\n");
                    } else {
                        output.push_str("      -> Root directory contents:\n");
                        for item in list.iter().take(20) {
                            output.push_str(&format!("         {}\n", item.trim()));
                            files.push(item.trim().to_string());
                        }
                        if list.len() > 20 {
                            output.push_str(&format!("         ... and {} more items.\n", list.len() - 20));
                        }
                    }
                } else {
                    output.push_str("      [-] Anonymous login succeeded, but failed to list directory contents (Data channel blocked or permissions denied).\n");
                }
                
                // Cleanup
                let _ = ftp_stream.quit().await;
            } else {
                output.push_str("  [-] Target rejected anonymous login.\n");
            }
        } else {
            output.push_str("  [-] Failed to establish FTP connection for anonymous check.\n");
        }

        Ok(ModuleResult {
            success: anon_successful,
            output,
            data: json!({ "anonymous_login": anon_successful, "files": files }),
            credentials: vec![],
        })
    }
}
