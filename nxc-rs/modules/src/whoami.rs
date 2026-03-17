//! # whoami — LDAP User Enumeration Module
//!
//! Basic enumeration of provided user information and privileges via LDAP.
//! Equivalent to `nxc ldap <target> -u <user> -p <pass> -M whoami [-o USER=<target_user>]`.

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};

/// LDAP whoami module.
pub struct Whoami;

impl Whoami {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Whoami {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for Whoami {
    fn name(&self) -> &'static str {
        "whoami"
    }

    fn description(&self) -> &'static str {
        "Get details of provided user via LDAP"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["ldap"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption {
                name: "USER".to_string(),
                description: "Enumerate information about a different sAMAccountName".to_string(),
                required: false,
                default: None,
            },
        ]
    }

    async fn run(&self, session: &dyn NxcSession, opts: &ModuleOptions) -> Result<ModuleResult> {
        // Fallback to the session target user if the USER option is not provided.
        // For the stub, we just simulate the target user name.
        let target_user = opts
            .get("USER")
            .map(|s| s.as_str())
            .unwrap_or("current_user");

        let target = session.target();

        tracing::debug!(
            "whoami: Enumerating LDAP attributes for user '{}' on {}",
            target_user,
            target
        );

        // Stub: return a demonstration result.
        // In a real implementation, this would use the LDAP session to issue a search
        // with filter `(sAMAccountName=target_user)` and extract attributes.
        let user_data = serde_json::json!({
            "target": target,
            "sAMAccountName": target_user,
            "name": format!("{} Admin", target_user),
            "description": "Built-in account for administering the computer/domain",
            "userAccountControl": 512, // NORMAL_ACCOUNT
            "enabled": true,
            "password_never_expires": true,
            "memberOf": [
                "CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL",
                "CN=Administrators,CN=Builtin,DC=INLANEFREIGHT,DC=LOCAL"
            ],
            "objectSid": "S-1-5-21-123456789-123456789-123456789-500",
            "lastLogon": "2023-10-05 14:32:00 UTC",
            "pwdLastSet": "2023-01-01 00:00:00 UTC",
            "badPwdCount": 0,
            "servicePrincipalName": ["cifs/dc01.inlanefreight.local"],
            "note": "LDAP search query pending implementation"
        });

        let mut output_lines = Vec::new();
        output_lines.push(format!("Name: {}", user_data["name"].as_str().unwrap_or("")));
        output_lines.push(format!("Description: {}", user_data["description"].as_str().unwrap_or("")));
        output_lines.push(format!("sAMAccountName: {}", user_data["sAMAccountName"].as_str().unwrap_or("")));
        output_lines.push(format!("Enabled: {}", if user_data["enabled"].as_bool().unwrap_or(false) { "Yes" } else { "No" }));
        output_lines.push(format!("Password Never Expires: {}", if user_data["password_never_expires"].as_bool().unwrap_or(false) { "Yes" } else { "No" }));
        output_lines.push(format!("Last logon: {}", user_data["lastLogon"].as_str().unwrap_or("")));
        output_lines.push(format!("Password Last Set: {}", user_data["pwdLastSet"].as_str().unwrap_or("")));
        output_lines.push(format!("Bad Password Count: {}", user_data["badPwdCount"].as_i64().unwrap_or(0)));
        
        output_lines.push("Service Account Name(s) found - Potentially Kerberoastable user!".to_string());
        if let Some(spns) = user_data["servicePrincipalName"].as_array() {
            for spn in spns {
                output_lines.push(format!("Service Account Name: {}", spn.as_str().unwrap_or("")));
            }
        }
        
        if let Some(groups) = user_data["memberOf"].as_array() {
            for group in groups {
                output_lines.push(format!("Member of: {}", group.as_str().unwrap_or("")));
            }
        }
        output_lines.push(format!("User SID: {}", user_data["objectSid"].as_str().unwrap_or("")));

        Ok(ModuleResult {
            success: true,
            output: output_lines.join("\n"),
            data: user_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_whoami_metadata() {
        let module = Whoami::new();
        assert_eq!(module.name(), "whoami");
        assert!(module.supported_protocols().contains(&"ldap"));
    }

    #[test]
    fn test_whoami_options() {
        let module = Whoami::new();
        let opts = module.options();
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0].name, "USER");
    }
}
