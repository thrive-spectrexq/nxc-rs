//! # nfs_shares — NFS Share Enumeration Module
//!
//! Lists exported shares on a remote NFS server.

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;

use crate::{ModuleOptions, ModuleResult, NxcModule};

/// NFS share enumeration module.
pub struct NfsShares;

impl NfsShares {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NfsShares {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for NfsShares {
    fn name(&self) -> &'static str {
        "shares"
    }

    fn description(&self) -> &'static str {
        "List exported NFS shares via the MOUNT service"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["nfs"]
    }

    async fn run(&self, session: &mut dyn NxcSession, _opts: &ModuleOptions) -> Result<ModuleResult> {
        let nfs_sess = match session.downcast_mut::<nxc_protocols::nfs::NfsSession>() {
            Some(s) => s,
            None => return Err(anyhow::anyhow!("Module only supports NFS")),
        };

        let protocol = nxc_protocols::nfs::NfsProtocol::new();
        
        let mut output_lines = Vec::new();
        output_lines.push(format!("Enumerating NFS exports on {}", nfs_sess.target));

        match protocol.list_exports(&nfs_sess.target).await {
            Ok(shares) => {
                if shares.is_empty() {
                    output_lines.push("  No exported shares found.".to_string());
                } else {
                    for share in &shares {
                        output_lines.push(format!("  {}", share));
                    }
                }
                Ok(ModuleResult {
                    success: true,
                    output: output_lines.join("\n"),
                    data: serde_json::json!({ "shares": shares }),
                })
            }
            Err(e) => {
                Ok(ModuleResult {
                    success: false,
                    output: format!("Failed to list NFS exports: {}", e),
                    data: serde_json::Value::Null,
                })
            }
        }
    }
}
