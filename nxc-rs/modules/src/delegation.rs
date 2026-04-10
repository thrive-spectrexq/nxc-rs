//! # delegation — Kerberos delegation finder
use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{
    ldap::{LdapProtocol, LdapSession},
    NxcSession,
};
use serde_json::json;

pub struct Delegation;
impl Delegation {
    pub fn new() -> Self {
        Self
    }
}
impl Default for Delegation {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for Delegation {
    fn name(&self) -> &'static str {
        "delegation"
    }
    fn description(&self) -> &'static str {
        "Find unconstrained, constrained, and RBCD delegation configurations"
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
        let mut output = String::from("Kerberos Delegation Enumeration:\n");
        // Unconstrained delegation
        let uc_filter = "(userAccountControl:1.2.840.113556.1.4.803:=524288)";
        let uc_entries = proto
            .search(
                ldap_sess,
                &base_dn,
                ldap3::Scope::Subtree,
                uc_filter,
                vec!["sAMAccountName", "distinguishedName"],
            )
            .await?;
        output.push_str(&format!("\n  [+] Unconstrained Delegation ({}):\n", uc_entries.len()));
        for e in &uc_entries {
            let name =
                e.attrs.get("sAMAccountName").and_then(|v| v.first()).cloned().unwrap_or_default();
            output.push_str(&format!("      - {name}\n"));
        }
        // Constrained delegation
        let cd_filter = "(msDS-AllowedToDelegateTo=*)";
        let cd_entries = proto
            .search(
                ldap_sess,
                &base_dn,
                ldap3::Scope::Subtree,
                cd_filter,
                vec!["sAMAccountName", "msDS-AllowedToDelegateTo"],
            )
            .await?;
        output.push_str(&format!("\n  [+] Constrained Delegation ({}):\n", cd_entries.len()));
        for e in &cd_entries {
            let name =
                e.attrs.get("sAMAccountName").and_then(|v| v.first()).cloned().unwrap_or_default();
            let targets = e.attrs.get("msDS-AllowedToDelegateTo").cloned().unwrap_or_default();
            output.push_str(&format!("      - {} -> [{}]\n", name, targets.join(", ")));
        }
        // RBCD
        let rbcd_filter = "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)";
        let rbcd_entries = proto
            .search(ldap_sess, &base_dn, ldap3::Scope::Subtree, rbcd_filter, vec!["sAMAccountName"])
            .await?;
        output.push_str(&format!(
            "\n  [+] Resource-Based Constrained Delegation ({}):\n",
            rbcd_entries.len()
        ));
        for e in &rbcd_entries {
            let name =
                e.attrs.get("sAMAccountName").and_then(|v| v.first()).cloned().unwrap_or_default();
            output.push_str(&format!("      - {name}\n"));
        }
        let total = uc_entries.len() + cd_entries.len() + rbcd_entries.len();
        Ok(ModuleResult {
            success: total > 0,
            output,
            data: json!({"unconstrained": uc_entries.len(), "constrained": cd_entries.len(), "rbcd": rbcd_entries.len()}),
            credentials: vec![],
        })
    }
}
