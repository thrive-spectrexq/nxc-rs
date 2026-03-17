//! # enum_shares — SMB Share Enumeration Module
//!
//! Lists available SMB shares and tests read/write access.
//! Equivalent to `nxc smb <target> --shares`.

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};

/// SMB share enumeration module.
pub struct EnumShares;

impl EnumShares {
    pub fn new() -> Self {
        Self
    }
}

impl Default for EnumShares {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for EnumShares {
    fn name(&self) -> &'static str {
        "enum_shares"
    }

    fn description(&self) -> &'static str {
        "Enumerate SMB shares and test access permissions"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["smb"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![ModuleOption {
            name: "SHOW_ALL".to_string(),
            description: "Show all shares including hidden ones ($ suffix)".to_string(),
            required: false,
            default: Some("true".to_string()),
        }]
    }

    async fn run(&self, session: &mut dyn NxcSession, _opts: &ModuleOptions) -> Result<ModuleResult> {
        let smb_session = match session.protocol() {
            "smb" => unsafe {
                &*(session as *const dyn NxcSession as *const nxc_protocols::smb::SmbSession)
            },
            _ => return Err(anyhow::anyhow!("Module only supports SMB")),
        };

        let protocol = nxc_protocols::smb::SmbProtocol::new();
        let shares = protocol.list_shares(smb_session).await?;

        let mut output_lines = Vec::new();
        output_lines.push(format!(
            "{:<15} {:<10} {:<10} {}",
            "Share", "Read", "Write", "Remark"
        ));
        output_lines.push("-".repeat(50));

        let mut share_data = Vec::new();
        for share in shares {
            let read = if share.read_access { "READ" } else { "" };
            let write = if share.write_access { "WRITE" } else { "" };
            output_lines.push(format!(
                "{:<15} {:<10} {:<10} {}",
                share.name, read, write, share.remark
            ));

            share_data.push(serde_json::json!({
                "name": share.name,
                "read": share.read_access,
                "write": share.write_access,
                "remark": share.remark
            }));
        }

        Ok(ModuleResult {
            success: true,
            output: output_lines.join("\n"),
            data: serde_json::json!(share_data),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enum_shares_metadata() {
        let module = EnumShares::new();
        assert_eq!(module.name(), "enum_shares");
        assert!(module.supported_protocols().contains(&"smb"));
    }
}
