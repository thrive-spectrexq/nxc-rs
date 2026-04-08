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
        &["nfs", "smb"]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        _opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        match session.protocol() {
            "nfs" => self.run_nfs(session).await,
            "smb" => self.run_smb(session).await,
            _ => Err(anyhow::anyhow!("Module only supports NFS and SMB")),
        }
    }
}

impl NfsShares {
    async fn run_nfs(&self, session: &mut dyn NxcSession) -> Result<ModuleResult> {
        let nfs_sess = session
            .as_any()
            .downcast_ref::<nxc_protocols::nfs::NfsSession>()
            .ok_or_else(|| anyhow::anyhow!("Invalid session type for NFS shares"))?;

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
                    credentials: vec![],
                    success: true,
                    output: output_lines.join("\n"),
                    data: serde_json::json!({ "shares": shares }),
                })
            }
            Err(e) => Ok(ModuleResult {
                credentials: vec![],
                success: false,
                output: format!("Failed to list NFS exports: {}", e),
                data: serde_json::Value::Null,
            }),
        }
    }

    async fn run_smb(&self, session: &mut dyn NxcSession) -> Result<ModuleResult> {
        let smb_sess = session
            .as_any()
            .downcast_ref::<nxc_protocols::smb::SmbSession>()
            .ok_or_else(|| anyhow::anyhow!("Invalid session type for SMB shares"))?;

        let protocol = nxc_protocols::smb::SmbProtocol::new();
        let shares = protocol.list_shares(smb_sess).await?;

        let mut output = String::from("Available SMB Shares:\n");
        for share in &shares {
            output.push_str(&format!("  {}\n", share));
        }

        Ok(ModuleResult {
            credentials: vec![],
            success: true,
            output,
            data: serde_json::json!({ "shares": shares }),
        })
    }
}
