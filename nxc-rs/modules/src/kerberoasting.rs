//! # kerberoasting — LDAP Kerberoasting Module
//!
//! Identifies users with Service Principal Names (SPNs) for Kerberoasting.

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};

/// Kerberoasting identification module.
pub struct Kerberoasting;

impl Kerberoasting {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Kerberoasting {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for Kerberoasting {
    fn name(&self) -> &'static str {
        "kerberoasting"
    }

    fn description(&self) -> &'static str {
        "Identify users with Service Principal Names (SPNs) for Kerberoasting"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["ldap"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![ModuleOption {
            name: "USER".to_string(),
            description: "Specific user to check".to_string(),
            required: false,
            default: None,
        }]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let user_filter = opts.get("USER").map(|s| s.as_str()).unwrap_or("*");

        let ldap_session = match session.protocol() {
            "ldap" => session
                .downcast_mut::<nxc_protocols::ldap::LdapSession>()
                .unwrap(),
            _ => return Err(anyhow::anyhow!("Module only supports LDAP")),
        };

        let protocol = nxc_protocols::ldap::LdapProtocol::new();
        let base_dn = protocol.get_base_dn(ldap_session).await?;

        tracing::debug!(
            "kerberoasting: Searching for Kerberoastable users in {}",
            base_dn
        );

        // Filter for users with SPNs that are not disabled
        let filter = format!(
            "(&(objectClass=user)(objectCategory=person)(servicePrincipalName=*)(sAMAccountName={})(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            user_filter
        );

        let attrs = vec![
            "sAMAccountName",
            "servicePrincipalName",
            "memberOf",
            "pwdLastSet",
            "lastLogon",
        ];

        let entries = protocol
            .search(
                ldap_session,
                &base_dn,
                ldap3::Scope::Subtree,
                &filter,
                attrs,
            )
            .await?;

        let mut output_lines = Vec::new();
        let mut results = Vec::new();

        output_lines.push(format!(
            "{:<20} {:<30} {:<15}",
            "Username", "SPN", "Password Last Set"
        ));
        output_lines.push("-".repeat(65));

        for entry in &entries {
            let sam = entry
                .attrs
                .get("sAMAccountName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let spns = entry
                .attrs
                .get("servicePrincipalName")
                .cloned()
                .unwrap_or_default();
            let pwd_last_set = entry
                .attrs
                .get("pwdLastSet")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            for spn in &spns {
                output_lines.push(format!("{:<20} {:<30} {:<15}", sam, spn, pwd_last_set));
                results.push(serde_json::json!({
                    "username": sam,
                    "spn": spn,
                    "pwdLastSet": pwd_last_set
                }));
            }
        }

        if results.is_empty() {
            output_lines.push("No Kerberoastable users found.".to_string());
        }

        Ok(ModuleResult {
            success: true,
            output: output_lines.join("\n"),
            data: serde_json::json!(results),
        })
    }
}
