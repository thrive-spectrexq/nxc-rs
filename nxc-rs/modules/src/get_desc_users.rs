//! # get_desc_users — User description attribute dumper
use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{ldap::{LdapProtocol, LdapSession}, NxcSession};
use serde_json::json;

pub struct GetDescUsers;
impl GetDescUsers { pub fn new() -> Self { Self } }
impl Default for GetDescUsers { fn default() -> Self { Self::new() } }

#[async_trait]
impl NxcModule for GetDescUsers {
    fn name(&self) -> &'static str { "get_desc_users" }
    fn description(&self) -> &'static str { "Dump user description attributes (may contain credentials)" }
    fn supported_protocols(&self) -> &[&str] { &["ldap"] }
    async fn run(&self, session: &mut dyn NxcSession, _opts: &ModuleOptions) -> Result<ModuleResult> {
        let ldap_sess = session.as_any().downcast_ref::<LdapSession>()
            .ok_or_else(|| anyhow!("Module requires an LDAP session"))?;
        let proto = LdapProtocol::new();
        let base_dn = proto.get_base_dn(ldap_sess).await?;
        let entries = proto.search(ldap_sess, &base_dn, ldap3::Scope::Subtree,
            "(&(objectCategory=person)(objectClass=user)(description=*))",
            vec!["sAMAccountName", "description"]).await?;
        let mut output = format!("User Descriptions ({} users with descriptions):\n", entries.len());
        let mut results = Vec::new();
        for e in &entries {
            let name = e.attrs.get("sAMAccountName").and_then(|v| v.first()).cloned().unwrap_or_default();
            let desc = e.attrs.get("description").and_then(|v| v.first()).cloned().unwrap_or_default();
            output.push_str(&format!("  [+] {} : {}\n", name, desc));
            results.push(json!({"user": name, "description": desc}));
        }
        Ok(ModuleResult { success: !entries.is_empty(), output, data: json!({"users": results}), credentials: vec![] })
    }
}
