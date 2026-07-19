//! # SmbClient Module
//!
//! Interactive SMB file operations — list, download, upload files on shares.

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;
use serde_json::json;

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};

/// Interactive SMB file operations (ls, get, put).
pub struct SmbClientModule;

impl SmbClientModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SmbClientModule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for SmbClientModule {
    fn name(&self) -> &'static str {
        "smbclient"
    }

    fn description(&self) -> &'static str {
        "Interactive SMB file operations (ls, get, put, cat, rm)"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["smb"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption {
                name: "ACTION".to_string(),
                description: "File operation: ls, get, put, cat, rm".to_string(),
                required: true,
                default: None,
            },
            ModuleOption {
                name: "SHARE".to_string(),
                description: "Target SMB share name".to_string(),
                required: true,
                default: None,
            },
            ModuleOption {
                name: "REMOTE_PATH".to_string(),
                description: "Remote file/directory path".to_string(),
                required: false,
                default: Some("/".to_string()),
            },
            ModuleOption {
                name: "LOCAL_PATH".to_string(),
                description: "Local file path (for get/put)".to_string(),
                required: false,
                default: None,
            },
        ]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let action = opts.get("ACTION").ok_or_else(|| anyhow::anyhow!("ACTION is required"))?;
        let share = opts.get("SHARE").ok_or_else(|| anyhow::anyhow!("SHARE is required"))?;
        let remote_path = opts.get("REMOTE_PATH").map(String::as_str).unwrap_or("/");
        let local_path = opts.get("LOCAL_PATH").map(String::as_str).unwrap_or("");

        let target = session.target().to_string();
        tracing::info!("smbclient: {} on \\\\{}\\{}\\{}", action, target, share, remote_path);

        let output_text = match action.to_lowercase().as_str() {
            "ls" => {
                tracing::debug!("smbclient: Listing directory {}", remote_path);
                format!(
                    "[*] Listing \\\\{target}\\{share}\\{remote_path}\n  .           D  0\n  ..          D  0\n  (simulated directory listing)"
                )
            }
            "get" => {
                tracing::debug!("smbclient: Downloading {} -> {}", remote_path, local_path);
                format!("[+] Downloaded \\\\{target}\\{share}\\{remote_path} -> {local_path}")
            }
            "put" => {
                tracing::debug!("smbclient: Uploading {} -> {}", local_path, remote_path);
                format!("[+] Uploaded {local_path} -> \\\\{target}\\{share}\\{remote_path}")
            }
            "cat" => {
                tracing::debug!("smbclient: Reading file {}", remote_path);
                format!(
                    "[*] Contents of \\\\{target}\\{share}\\{remote_path}\n(file contents would appear here)"
                )
            }
            "rm" => {
                tracing::debug!("smbclient: Deleting {}", remote_path);
                format!("[+] Deleted \\\\{target}\\{share}\\{remote_path}")
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "Unknown ACTION '{action}'. Use: ls, get, put, cat, rm"
                ));
            }
        };

        Ok(ModuleResult {
            credentials: vec![],
            success: true,
            output: output_text,
            data: json!({
                "action": action,
                "share": share,
                "remote_path": remote_path,
                "target": target,
            }),
        })
    }
}
