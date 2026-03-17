//! # asreproasting — LDAP ASREProasting Module
//!
//! Identifies users with DONT_REQ_PREAUTH set in UserAccountControl for ASREProasting.

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};

/// ASREProasting identification module.
pub struct Asreproasting;

impl Asreproasting {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Asreproasting {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for Asreproasting {
    fn name(&self) -> &'static str {
        "asreproasting"
    }

    fn description(&self) -> &'static str {
        "Identify users with DONT_REQ_PREAUTH set for ASREProasting"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["ldap"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![]
    }

    async fn run(&self, session: &mut dyn NxcSession, _opts: &ModuleOptions) -> Result<ModuleResult> {
        let ldap_session = match session.protocol() {
            "ldap" => session.downcast_mut::<nxc_protocols::ldap::LdapSession>().unwrap(),
            _ => return Err(anyhow::anyhow!("Module only supports LDAP")),
        };

        let protocol = nxc_protocols::ldap::LdapProtocol::new();
        let base_dn = protocol.get_base_dn(ldap_session).await?;

        tracing::debug!(
            "asreproasting: Searching for ASREProastable users in {}",
            base_dn
        );

        // Filter: DONT_REQ_PREAUTH (0x400000 = 4194304)
        let filter = "(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=4194304))";

        let attrs = vec!["sAMAccountName", "userAccountControl", "pwdLastSet"];

        let entries = protocol
            .search(ldap_session, &base_dn, ldap3::Scope::Subtree, filter, attrs)
            .await?;

        let mut output_lines = Vec::new();
        let mut results = Vec::new();

        output_lines.push(format!(
            "{:<20} {:<20} {:<15}",
            "Username", "UAC", "Password Last Set"
        ));
        output_lines.push("-".repeat(55));

        for entry in &entries {
            let sam = entry
                .attrs
                .get("sAMAccountName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let uac = entry
                .attrs
                .get("userAccountControl")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let pwd_last_set = entry
                .attrs
                .get("pwdLastSet")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            output_lines.push(format!("{:<20} {:<20} {:<15}", sam, uac, pwd_last_set));
            results.push(serde_json::json!({
                "username": sam,
                "uac": uac,
                "pwdLastSet": pwd_last_set
            }));
        }

        if results.is_empty() {
            output_lines.push("No ASREProastable users found.".to_string());
        }

        Ok(ModuleResult {
            success: true,
            output: output_lines.join("\n"),
            data: serde_json::json!(results),
        })
    }
}
