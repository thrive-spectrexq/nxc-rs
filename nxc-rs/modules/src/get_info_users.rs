//! # get_info_users — Detailed user information dumper
use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{
    ldap::{LdapProtocol, LdapSession},
    NxcSession,
};
use serde_json::json;

pub struct GetInfoUsers;
impl GetInfoUsers {
    pub fn new() -> Self {
        Self
    }
}
impl Default for GetInfoUsers {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for GetInfoUsers {
    fn name(&self) -> &'static str {
        "get_info_users"
    }
    fn description(&self) -> &'static str {
        "Dump detailed user attributes (lastLogon, pwdLastSet, badPwdCount, etc.)"
    }
    fn supported_protocols(&self) -> &[&str] {
        &["ldap"]
    }
    async fn run(
        &self,
        session: &mut dyn NxcSession,
        _opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let ldap_sess = session
            .as_any()
            .downcast_ref::<LdapSession>()
            .ok_or_else(|| anyhow!("Module requires an LDAP session"))?;
        let proto = LdapProtocol::new();
        let base_dn = proto.get_base_dn(ldap_sess).await?;
        let entries = proto
            .search(
                ldap_sess,
                &base_dn,
                ldap3::Scope::Subtree,
                "(&(objectCategory=person)(objectClass=user))",
                vec![
                    "sAMAccountName",
                    "lastLogon",
                    "pwdLastSet",
                    "badPwdCount",
                    "logonCount",
                    "userAccountControl",
                    "adminCount",
                ],
            )
            .await?;
        let mut output = format!("User Information ({} users):\n", entries.len());
        let mut results = Vec::new();
        for e in &entries {
            let name =
                e.attrs.get("sAMAccountName").and_then(|v| v.first()).cloned().unwrap_or_default();
            let admin_count =
                e.attrs.get("adminCount").and_then(|v| v.first()).cloned().unwrap_or_default();
            let bad_pwd =
                e.attrs.get("badPwdCount").and_then(|v| v.first()).cloned().unwrap_or_default();
            if admin_count == "1" {
                output.push_str(&format!("  [!] {name} (adminCount=1, badPwd={bad_pwd})\n"));
            }
            results.push(json!({"user": name, "adminCount": admin_count, "badPwdCount": bad_pwd}));
        }
        Ok(ModuleResult {
            success: true,
            output,
            data: json!({"users": results}),
            credentials: vec![],
        })
    }
}
