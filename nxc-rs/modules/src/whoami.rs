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
        vec![ModuleOption {
            name: "USER".to_string(),
            description: "Enumerate information about a different sAMAccountName".to_string(),
            required: false,
            default: None,
        }]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let target_user = opts.get("USER").map(std::string::String::as_str).unwrap_or(""); // If empty, we'll try to find the current user context

        let ldap_session = match session.protocol() {
            "ldap" => session.downcast_mut::<nxc_protocols::ldap::LdapSession>().unwrap_or_else(|| panic!("session downcast failed")),
            _ => return Err(anyhow::anyhow!("Module only supports LDAP")),
        };

        // We need the protocol handler to perform the search
        // In this architecture, protocols are stateless but provide the logic
        let protocol = nxc_protocols::ldap::LdapProtocol::new();

        // 1. Get Base DN
        let base_dn = protocol.get_base_dn(ldap_session).await?;

        // 2. Determine target user - if USER option not provided, use the authenticated user
        let user_to_query = if target_user.is_empty() {
            if let Some(creds) = &ldap_session.credentials {
                &creds.username
            } else {
                "current_user"
            }
        } else {
            target_user
        };

        tracing::debug!("whoami: Querying LDAP for user '{}' in {}", user_to_query, base_dn);

        // 3. Perform Search
        let filter = format!("(sAMAccountName={user_to_query})");
        let attrs = vec![
            "sAMAccountName",
            "name",
            "description",
            "userAccountControl",
            "memberOf",
            "objectSid",
            "lastLogon",
            "pwdLastSet",
            "servicePrincipalName",
        ];

        let entries =
            protocol.search(ldap_session, &base_dn, ldap3::Scope::Subtree, &filter, attrs).await?;

        if entries.is_empty() {
            return Ok(ModuleResult {
                credentials: vec![],
                success: false,
                output: format!("User '{user_to_query}' not found in LDAP"),
                data: serde_json::Value::Null,
            });
        }

        let entry = &entries[0];
        let mut user_data = serde_json::Map::new();
        let mut output_lines = Vec::new();

        for (attr, values) in &entry.attrs {
            user_data.insert(attr.clone(), serde_json::json!(values));
        }

        let get_attr = |name: &str| -> String {
            entry.attrs.get(name).and_then(|v| v.first()).cloned().unwrap_or_default()
        };

        output_lines.push(format!("Name: {}", get_attr("name")));
        output_lines.push(format!("Description: {}", get_attr("description")));
        output_lines.push(format!("sAMAccountName: {}", get_attr("sAMAccountName")));

        let uac = get_attr("userAccountControl").parse::<u32>().unwrap_or(0);
        output_lines.push(format!("Account Control: {uac}"));
        output_lines.push(format!("Enabled: {}", if uac & 2 == 0 { "Yes" } else { "No" }));

        if let Some(spns) = entry.attrs.get("servicePrincipalName") {
            if !spns.is_empty() {
                output_lines
                    .push("!!! Potentially Kerberoastable user (SPNs found) !!!".to_string());
                for spn in spns {
                    output_lines.push(format!("  SPN: {spn}"));
                }
            }
        }

        if let Some(groups) = entry.attrs.get("memberOf") {
            for group in groups {
                output_lines.push(format!("Member of: {group}"));
            }
        }

        output_lines.push(format!("SID: {}", get_attr("objectSid")));

        Ok(ModuleResult {
            credentials: vec![],
            success: true,
            output: output_lines.join("\n"),
            data: serde_json::Value::Object(user_data),
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
