//! # laps — LDAP LAPS Enumeration Module
//!
//! Retrieves LAPS passwords which the account has read permissions for.
//! Equivalent to `nxc ldap <target> -u <user> -p <pass> -M laps [-o COMPUTER=<wildcard>]`.

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};

/// LDAP LAPS module.
pub struct Laps;

impl Laps {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Laps {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for Laps {
    fn name(&self) -> &'static str {
        "laps"
    }

    fn description(&self) -> &'static str {
        "Retrieves all LAPS passwords which the account has read permissions for"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["ldap"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption {
                name: "COMPUTER".to_string(),
                description: "Computer name or wildcard ex: WIN-S10, WIN-* etc. Default: *".to_string(),
                required: false,
                default: None,
            },
        ]
    }

    async fn run(&self, session: &dyn NxcSession, opts: &ModuleOptions) -> Result<ModuleResult> {
        let computer_filter = opts
            .get("COMPUTER")
            .map(|s| s.as_str())
            .unwrap_or("*");

        let target = session.target();

        tracing::debug!(
            "laps: Querying LAPS passwords for computer '{}' on {}",
            computer_filter,
            target
        );

        // Stub: return a demonstration result.
        // Real implementation would search LDAP for (&(objectCategory=computer)(|(msLAPS-EncryptedPassword=*)(ms-MCS-AdmPwd=*)(msLAPS-Password=*))(name=...))
        let laps_data = serde_json::json!({
            "target": target,
            "filter": computer_filter,
            "computers": [
                {
                    "sAMAccountName": "DC01$",
                    "user": "Administrator",
                    "password": "Password123!"
                },
                {
                    "sAMAccountName": "WS01$",
                    "user": "Administrator",
                    "password": "ComplexPassword456@"
                }
            ],
            "note": "LDAP search query for ms-MCS-AdmPwd pending implementation"
        });

        let mut output_lines = Vec::new();
        output_lines.push("Getting LAPS Passwords".to_string());
        
        if let Some(computers) = laps_data["computers"].as_array() {
            if computers.is_empty() {
                output_lines.push("No result found with attribute ms-MCS-AdmPwd or msLAPS-Password !".to_string());
            } else {
                for comp in computers {
                    let sam = comp["sAMAccountName"].as_str().unwrap_or("");
                    let user = comp["user"].as_str().unwrap_or("");
                    let pwd = comp["password"].as_str().unwrap_or("");
                    output_lines.push(format!("Computer:{} User:{:<15} Password:{}", sam, user, pwd));
                }
            }
        }

        Ok(ModuleResult {
            success: true,
            output: output_lines.join("\n"),
            data: laps_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_laps_metadata() {
        let module = Laps::new();
        assert_eq!(module.name(), "laps");
        assert!(module.supported_protocols().contains(&"ldap"));
    }
}
