use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{ldap::LdapSession, NxcSession};
use serde_json::json;
use tracing::info;

pub struct LdapMaQuota {}

impl LdapMaQuota {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for LdapMaQuota {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for LdapMaQuota {
    fn name(&self) -> &'static str {
        "ldap_ma_quota"
    }

    fn description(&self) -> &'static str {
        "Queries the Active Directory domain to determine the ms-DS-MachineAccountQuota."
    }

    fn supported_protocols(&self) -> &[&str] {
        &["ldap"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        _opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let ldap_sess = session
            .as_any_mut()
            .downcast_mut::<LdapSession>()
            .ok_or_else(|| anyhow!("Module requires an LDAP session"))?;

        info!(
            "Starting MachineAccountQuota enumeration on {}",
            ldap_sess.target
        );

        let mut output = String::from("MachineAccountQuota Enumeration:\n");
        let mut maq_value = -1;
        let mut is_vulnerable = false;

        // Perform LDAP search at the root naming context to extract default policy
        let protocol = nxc_protocols::ldap::LdapProtocol::new();
        let search_base = match protocol.get_base_dn(ldap_sess).await {
            Ok(base) => base,
            Err(_) => {
                return Ok(ModuleResult {
                    success: false,
                    output: "  [-] Could not resolve defaultNamingContext to query MAQ.\n"
                        .to_string(),
                    data: json!({}),
                    credentials: vec![],
                })
            }
        };

        let filter = "(objectClass=*)";
        let attrs = vec!["ms-DS-MachineAccountQuota"];

        if let Ok(entries) = protocol
            .search(ldap_sess, &search_base, ldap3::Scope::Base, filter, attrs)
            .await
        {
            if let Some(entry) = entries.first() {
                if let Some(quota_strs) = entry.attrs.get("ms-DS-MachineAccountQuota") {
                    if let Some(quota_str) = quota_strs.first() {
                        if let Ok(val) = quota_str.parse::<i32>() {
                            maq_value = val;
                            is_vulnerable = val > 0;
                        }
                    }
                }
            }
        }

        if maq_value >= 0 {
            output.push_str(&format!("  [!] ms-DS-MachineAccountQuota: {}\n", maq_value));
            if is_vulnerable {
                output.push_str(
                    "      -> DANGER: Unprivileged users can join machines to the domain!\n",
                );
            } else {
                output.push_str("      -> SECURE: Default machine account quota is restricted.\n");
            }
        } else {
            output.push_str("  [-] Could not resolve ms-DS-MachineAccountQuota attribute.\n");
        }

        Ok(ModuleResult {
            success: maq_value >= 0,
            output,
            data: json!({ "machine_account_quota": maq_value, "is_vulnerable": is_vulnerable }),
            credentials: vec![],
        })
    }
}
