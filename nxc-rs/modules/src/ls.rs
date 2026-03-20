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
        &["ftp", "smb"]
    }

    fn options(&self) -> Vec<crate::ModuleOption> {
        vec![crate::ModuleOption {
            name: "PATH".to_string(),
            description: "Remote share and path to list (e.g. C$\\Windows). If not specified, lists shares.".to_string(),
            required: false,
            default: None,
        }]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        match session.protocol() {
            "ftp" => self.run_ftp(session).await,
            "smb" => self.run_smb(session, opts).await,
            _ => return Err(anyhow::anyhow!("Module only supports FTP and SMB")),
        }
    }
}

impl FtpLs {
    async fn run_ftp(&self, session: &mut dyn NxcSession) -> Result<ModuleResult> {
        let ftp_sess = unsafe {
            &*(session as *const dyn NxcSession as *const nxc_protocols::ftp::FtpSession)
        };
        let protocol = nxc_protocols::ftp::FtpProtocol::new();
        let mut output_lines = Vec::new();
        
        match protocol.list_files(&ftp_sess.target, ftp_sess.port, &ftp_sess.credentials).await {
            Ok(files) => {
                for file in files {
                    output_lines.push(format!("  {}", file));
                }
                Ok(ModuleResult {
                    success: true,
                    output: output_lines.join("\n"),
                    data: serde_json::json!({ "files": output_lines }),
                })
            }
            Err(e) => Ok(ModuleResult {
                success: false,
                output: format!("Failed to list files: {}", e),
                data: serde_json::Value::Null,
            }),
        }
    }

    async fn run_smb(&self, session: &mut dyn NxcSession, opts: &ModuleOptions) -> Result<ModuleResult> {
        let smb_sess = unsafe {
            &*(session as *const dyn NxcSession as *const nxc_protocols::smb::SmbSession)
        };
        let protocol = nxc_protocols::smb::SmbProtocol::new();
        
        if let Some(path_full) = opts.get("PATH") {
            // Split path into share and subpath (e.g. C$\Windows -> share=C$, path=Windows)
            let (share, path) = match path_full.split_once('\\') {
                Some((s, p)) => (s, p),
                None => (path_full.as_str(), ""),
            };
            
            match protocol.list_directory(smb_sess, share, path).await {
                Ok(entries) => {
                    let mut output = format!("Listing entries in {}\\{}:\n", share, path);
                    for entry in &entries {
                        output.push_str(&format!("  {}\n", entry));
                    }
                    Ok(ModuleResult {
                        success: true,
                        output,
                        data: serde_json::json!({ "entries": entries }),
                    })
                }
                Err(e) => Ok(ModuleResult {
                    success: false,
                    output: format!("Failed to list directory: {}", e),
                    data: serde_json::Value::Null,
                }),
            }
        } else {
            // No path specified, list shares
            match protocol.list_shares(smb_sess).await {
                Ok(shares) => {
                    let mut output = String::from("Available Shares:\n");
                    for share in &shares {
                        output.push_str(&format!("  {}\n", share));
                    }
                    Ok(ModuleResult {
                        success: true,
                        output,
                        data: serde_json::json!({ "shares": shares }),
                    })
                }
                Err(e) => Ok(ModuleResult {
                    success: false,
                    output: format!("Failed to list shares: {}", e),
                    data: serde_json::Value::Null,
                }),
            }
        }
    }
}
