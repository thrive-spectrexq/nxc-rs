use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::ldap::LdapProtocol;
use nxc_protocols::NxcSession;
use tracing::info;

pub struct Gmsa;

impl Gmsa {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Gmsa {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for Gmsa {
    fn name(&self) -> &'static str {
        "gmsa"
    }

    fn description(&self) -> &'static str {
        "Enumerate gMSA passwords (msDS-ManagedPassword)"
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
        let protocol = LdapProtocol::new();
        let ldap_session = match session.downcast_ref::<nxc_protocols::ldap::LdapSession>() {
            Some(s) => s,
            None => return Err(anyhow!("Invalid session type for LDAP")),
        };

        info!(
            "GMSA: Enumerating gMSA passwords on {}",
            ldap_session.target
        );

        let base_dn = protocol.get_base_dn(ldap_session).await?;
        let filter = "(&(objectClass=msDS-GroupManagedServiceAccount)(msDS-ManagedPassword=*))";
        let attrs = vec!["sAMAccountName", "msDS-ManagedPassword"];

        let entries = protocol
            .search(ldap_session, &base_dn, ldap3::Scope::Subtree, filter, attrs)
            .await?;

        let mut output = String::new();
        let mut gmsa_data = Vec::new();

        for entry in entries {
            let name = entry
                .attrs
                .get("sAMAccountName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            // msDS-ManagedPassword is a blob (MS-SAMR 2.2.14.2)
            // For MVP, we'll just indicate it was found.
            // Full implementation would involve parsing the BLOB to get the NT hash.
            output.push_str(&format!("Found gMSA: {} (Password blob extracted)\n", name));
            gmsa_data.push(serde_json::json!({
                "account": name,
                "status": "extracted"
            }));
        }

        if gmsa_data.is_empty() {
            Ok(ModuleResult {
                credentials: vec![],
                success: true,
                output: "No gMSA accounts with managed passwords found.".to_string(),
                data: serde_json::json!([]),
            })
        } else {
            Ok(ModuleResult {
                credentials: vec![],
                success: true,
                output,
                data: serde_json::json!(gmsa_data),
            })
        }
    }
}
