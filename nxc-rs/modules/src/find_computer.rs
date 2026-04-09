//! # find_computer — Computer object finder
use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{ldap::{LdapProtocol, LdapSession}, NxcSession};
use serde_json::json;

pub struct FindComputer;
impl FindComputer { pub fn new() -> Self { Self } }
impl Default for FindComputer { fn default() -> Self { Self::new() } }

#[async_trait]
impl NxcModule for FindComputer {
    fn name(&self) -> &'static str { "find_computer" }
    fn description(&self) -> &'static str { "Find computer objects in AD with optional OS filtering" }
    fn supported_protocols(&self) -> &[&str] { &["ldap"] }
    fn options(&self) -> Vec<ModuleOption> {
        vec![ModuleOption { name: "OS".into(), description: "Filter by OS (e.g. 'Windows Server 2019')".into(), required: false, default: None }]
    }
    async fn run(&self, session: &mut dyn NxcSession, opts: &ModuleOptions) -> Result<ModuleResult> {
        let ldap_sess = session.as_any().downcast_ref::<LdapSession>()
            .ok_or_else(|| anyhow!("Module requires an LDAP session"))?;
        let proto = LdapProtocol::new();
        let base_dn = proto.get_base_dn(ldap_sess).await?;
        let os_filter = opts.get("OS").map(|os| format!("(operatingSystem=*{}*)", os)).unwrap_or_default();
        let filter = format!("(&(objectCategory=computer){})", os_filter);
        let entries = proto.search(ldap_sess, &base_dn, ldap3::Scope::Subtree, &filter,
            vec!["cn", "operatingSystem", "operatingSystemVersion", "dNSHostName", "lastLogonTimestamp"]).await?;
        let mut output = format!("Computer Objects ({}):\n", entries.len());
        let mut computers = Vec::new();
        for e in &entries {
            let name = e.attrs.get("cn").and_then(|v| v.first()).cloned().unwrap_or_default();
            let os = e.attrs.get("operatingSystem").and_then(|v| v.first()).cloned().unwrap_or_default();
            let dns = e.attrs.get("dNSHostName").and_then(|v| v.first()).cloned().unwrap_or_default();
            output.push_str(&format!("  [+] {} | {} | {}\n", name, os, dns));
            computers.push(json!({"name": name, "os": os, "dns": dns}));
        }
        Ok(ModuleResult { success: true, output, data: json!({"computers": computers}), credentials: vec![] })
    }
}
