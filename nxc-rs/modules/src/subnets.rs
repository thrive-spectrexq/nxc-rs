//! # subnets — AD Sites and Services subnet enumeration
use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{
    ldap::{LdapProtocol, LdapSession},
    NxcSession,
};
use serde_json::json;

pub struct Subnets;
impl Subnets {
    pub fn new() -> Self {
        Self
    }
}
impl Default for Subnets {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for Subnets {
    fn name(&self) -> &'static str {
        "subnets"
    }
    fn description(&self) -> &'static str {
        "Enumerate AD Sites and Services subnets"
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
        let config_dn = format!("CN=Subnets,CN=Sites,CN=Configuration,{base_dn}");
        let entries = proto
            .search(
                ldap_sess,
                &config_dn,
                ldap3::Scope::Subtree,
                "(objectClass=subnet)",
                vec!["cn", "siteObject", "description"],
            )
            .await?;
        let mut output = format!("AD Subnets ({}):\n", entries.len());
        let mut subnets = Vec::new();
        for e in &entries {
            let name = e.attrs.get("cn").and_then(|v| v.first()).cloned().unwrap_or_default();
            let site =
                e.attrs.get("siteObject").and_then(|v| v.first()).cloned().unwrap_or_default();
            let site_cn = site.split(',').next().unwrap_or(&site).replace("CN=", "");
            output.push_str(&format!("  [+] {name} -> Site: {site_cn}\n"));
            subnets.push(json!({"subnet": name, "site": site_cn}));
        }
        Ok(ModuleResult {
            success: !entries.is_empty(),
            output,
            data: json!({"subnets": subnets}),
            credentials: vec![],
        })
    }
}
