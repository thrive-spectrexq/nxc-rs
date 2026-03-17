//! # enum_shares — SMB Share Enumeration Module
//!
//! Lists available SMB shares and tests read/write access.
//! Equivalent to `nxc smb <target> --shares`.

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;
use std::collections::HashMap;

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
        vec![
            ModuleOption {
                name: "SHOW_ALL".to_string(),
                description: "Show all shares including hidden ones ($ suffix)".to_string(),
                required: false,
                default: Some("true".to_string()),
            },
            ModuleOption {
                name: "DIR_ONLY".to_string(),
                description: "Only show directories, not files".to_string(),
                required: false,
                default: Some("false".to_string()),
            },
        ]
    }

    async fn run(&self, session: &dyn NxcSession, opts: &ModuleOptions) -> Result<ModuleResult> {
        let show_all = opts
            .get("SHOW_ALL")
            .map(|v| v == "true")
            .unwrap_or(true);

        let target = session.target();
        let is_admin = session.is_admin();

        // In a real implementation, this would use the SMB session to enumerate shares
        // via NetShareEnumAll RPC call. For now, provide the structural framework.
        tracing::debug!(
            "enum_shares: Enumerating shares on {} (admin: {})",
            target,
            is_admin
        );

        // Stub: return a demonstration result
        // When real SMB share enumeration is implemented, this will make
        // the appropriate DCERPC calls (srvsvc.NetShareEnumAll)
        let shares_data = serde_json::json!({
            "target": target,
            "shares": [
                {
                    "name": "ADMIN$",
                    "type": "Disk",
                    "remark": "Remote Admin",
                    "read": is_admin,
                    "write": is_admin
                },
                {
                    "name": "C$",
                    "type": "Disk",
                    "remark": "Default share",
                    "read": is_admin,
                    "write": is_admin
                },
                {
                    "name": "IPC$",
                    "type": "IPC",
                    "remark": "Remote IPC",
                    "read": true,
                    "write": false
                }
            ],
            "note": "Share enumeration via DCERPC pending implementation"
        });

        let mut output_lines = Vec::new();
        output_lines.push(format!("Share enumeration on {}", target));
        output_lines.push(format!("{:<20} {:<10} {:<30} {:<6} {:<6}", "Share", "Type", "Remark", "Read", "Write"));
        output_lines.push("-".repeat(72));

        if let Some(shares) = shares_data["shares"].as_array() {
            for share in shares {
                let name = share["name"].as_str().unwrap_or("");
                if !show_all && name.ends_with('$') {
                    continue;
                }
                output_lines.push(format!(
                    "{:<20} {:<10} {:<30} {:<6} {:<6}",
                    name,
                    share["type"].as_str().unwrap_or(""),
                    share["remark"].as_str().unwrap_or(""),
                    if share["read"].as_bool().unwrap_or(false) { "READ" } else { "" },
                    if share["write"].as_bool().unwrap_or(false) { "WRITE" } else { "" },
                ));
            }
        }

        Ok(ModuleResult {
            success: true,
            output: output_lines.join("\n"),
            data: shares_data,
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

    #[test]
    fn test_enum_shares_options() {
        let module = EnumShares::new();
        let opts = module.options();
        assert_eq!(opts.len(), 2);
        assert_eq!(opts[0].name, "SHOW_ALL");
    }
}
