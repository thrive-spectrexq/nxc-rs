//! # ftp_ls — FTP File Listing Module
//!
//! Lists files on the remote FTP server.

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;

use crate::{ModuleOptions, ModuleResult, NxcModule};

/// FTP file listing module.
pub struct FtpLs;

impl FtpLs {
    pub fn new() -> Self {
        Self
    }
}

impl Default for FtpLs {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for FtpLs {
    fn name(&self) -> &'static str {
        "ls"
    }

    fn description(&self) -> &'static str {
        "List files in the current directory of the FTP server"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["ftp"]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        _opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let ftp_sess = match session.protocol() {
            "ftp" => unsafe {
                &*(session as *const dyn NxcSession as *const nxc_protocols::ftp::FtpSession)
            },
            _ => return Err(anyhow::anyhow!("Module only supports FTP")),
        };

        let protocol = nxc_protocols::ftp::FtpProtocol::new();

        let mut output_lines = Vec::new();
        output_lines.push(format!(
            "Listing files on {}:{}",
            ftp_sess.target, ftp_sess.port
        ));

        match protocol
            .list_files(&ftp_sess.target, ftp_sess.port, &ftp_sess.credentials)
            .await
        {
            Ok(files) => {
                for file in files {
                    output_lines.push(format!("  {}", file));
                }
                Ok(ModuleResult {
                    success: true,
                    output: output_lines.join("\n"),
                    data: serde_json::json!({ "files": output_lines[1..] }),
                })
            }
            Err(e) => Ok(ModuleResult {
                success: false,
                output: format!("Failed to list files: {}", e),
                data: serde_json::Value::Null,
            }),
        }
    }
}
