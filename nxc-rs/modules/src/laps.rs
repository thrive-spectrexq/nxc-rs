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

        let ldap_session = match session.protocol() {
            "ldap" => unsafe { &*(session as *const dyn NxcSession as *const nxc_protocols::ldap::LdapSession) },
            _ => return Err(anyhow::anyhow!("Module only supports LDAP")),
        };

        let protocol = nxc_protocols::ldap::LdapProtocol::new();
        let base_dn = protocol.get_base_dn(ldap_session).await?;

        tracing::debug!(
            "laps: Querying LAPS passwords for computer '{}' in {}",
            computer_filter,
            base_dn
        );

        // Filter for computers with LAPS passwords (supporting both legacy ms-MCS-AdmPwd and new msLAPS-Password)
        let filter = format!(
            "(&(objectCategory=computer)(|(ms-MCS-AdmPwd=*)(msLAPS-Password=*)(msLAPS-EncryptedPassword=*))(name={}))",
            computer_filter
        );
        
        let attrs = vec!["sAMAccountName", "name", "ms-MCS-AdmPwd", "msLAPS-Password", "msLAPS-EncryptedPassword"];

        let entries = protocol.search(
            ldap_session,
            &base_dn,
            ldap3::Scope::Subtree,
            &filter,
            attrs,
        ).await?;

        let mut output_lines = Vec::new();
        let mut laps_results = Vec::new();

        output_lines.push("Retrieving LAPS Passwords...".to_string());

        if entries.is_empty() {
            output_lines.push(format!("No computers found matching filter: {}", computer_filter));
        } else {
            for entry in &entries {
                let name = entry.attrs.get("name").and_then(|v| v.first()).cloned().unwrap_or_default();
                let sam = entry.attrs.get("sAMAccountName").and_then(|v| v.first()).cloned().unwrap_or_default();
                
                // Try legacy LAPS
                let password = if let Some(p) = entry.attrs.get("ms-MCS-AdmPwd").and_then(|v| v.first()) {
                    p.clone()
                } else if let Some(p) = entry.attrs.get("msLAPS-Password").and_then(|v| v.first()) {
                    // New LAPS (cleartext if configured, though often encrypted)
                    p.clone()
                } else if entry.attrs.contains_key("msLAPS-EncryptedPassword") {
                    "[Encrypted - Decryption pending implementation]".to_string()
                } else {
                    continue;
                };

                output_lines.push(format!("Computer: {:<15} User: Administrator  Password: {}", name, password));
                
                laps_results.push(serde_json::json!({
                    "computer": name,
                    "sAMAccountName": sam,
                    "password": password
                }));
            }
        }

        if laps_results.is_empty() && !entries.is_empty() {
            output_lines.push("Matched computers but could not read LAPS attributes (permission denied?)".to_string());
        }

        Ok(ModuleResult {
            success: true,
            output: output_lines.join("\n"),
            data: serde_json::json!(laps_results),
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
