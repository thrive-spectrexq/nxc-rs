//! # enum_trusts — Domain trust enumeration
use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{
    ldap::{LdapProtocol, LdapSession},
    NxcSession,
};
use serde_json::json;

pub struct EnumTrusts;
impl EnumTrusts {
    pub fn new() -> Self {
        Self
    }
}
impl Default for EnumTrusts {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for EnumTrusts {
    fn name(&self) -> &'static str {
        "enum_trusts"
    }
    fn description(&self) -> &'static str {
        "Enumerate Active Directory domain trusts"
    }
    fn supported_protocols(&self) -> &[&str] {
        &["ldap", "smb"]
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
                "(objectClass=trustedDomain)",
                vec!["trustPartner", "trustDirection", "trustType", "trustAttributes"],
            )
            .await?;
        let mut output = format!("Domain Trust Enumeration ({} trusts found):\n", entries.len());
        let mut trusts = Vec::new();
        for entry in &entries {
            let partner = entry
                .attrs
                .get("trustPartner")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let direction = entry
                .attrs
                .get("trustDirection")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let dir_str = match direction.as_str() {
                "1" => "Inbound",
                "2" => "Outbound",
                "3" => "Bidirectional",
                _ => "Unknown",
            };
            let t_type =
                entry.attrs.get("trustType").and_then(|v| v.first()).cloned().unwrap_or_default();
            let type_str = match t_type.as_str() {
                "1" => "Downlevel",
                "2" => "Uplevel",
                "3" => "MIT",
                _ => "Unknown",
            };
            output
                .push_str(&format!("  [+] {partner} | Direction: {dir_str} | Type: {type_str}\n"));
            trusts.push(json!({"partner": partner, "direction": dir_str, "type": type_str}));
        }
        if entries.is_empty() {
            output.push_str("  [-] No domain trusts found\n");
        }
        Ok(ModuleResult {
            success: !entries.is_empty(),
            output,
            data: json!({"trusts": trusts}),
            credentials: vec![],
        })
    }
}
