//! # group_mem — Recursive group membership enumeration
use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{ldap::{LdapProtocol, LdapSession}, NxcSession};
use serde_json::json;

pub struct GroupMem;
impl GroupMem { pub fn new() -> Self { Self } }
impl Default for GroupMem { fn default() -> Self { Self::new() } }

#[async_trait]
impl NxcModule for GroupMem {
    fn name(&self) -> &'static str { "group_mem" }
    fn description(&self) -> &'static str { "Enumerate members of an AD group (recursive)" }
    fn supported_protocols(&self) -> &[&str] { &["ldap"] }
    fn options(&self) -> Vec<ModuleOption> {
        vec![ModuleOption { name: "GROUP".into(), description: "Group name to enumerate (default: Domain Admins)".into(), required: false, default: Some("Domain Admins".into()) }]
    }
    async fn run(&self, session: &mut dyn NxcSession, opts: &ModuleOptions) -> Result<ModuleResult> {
        let ldap_sess = session.as_any().downcast_ref::<LdapSession>()
            .ok_or_else(|| anyhow!("Module requires an LDAP session"))?;
        let proto = LdapProtocol::new();
        let base_dn = proto.get_base_dn(ldap_sess).await?;
        let group = opts.get("GROUP").map(|s| s.as_str()).unwrap_or("Domain Admins");
        let filter = format!("(&(objectClass=group)(cn={}))", group);
        let entries = proto.search(ldap_sess, &base_dn, ldap3::Scope::Subtree, &filter, vec!["member", "cn"]).await?;
        let mut output = format!("Group Membership for '{}':\n", group);
        let mut members = Vec::new();
        for e in &entries {
            if let Some(member_list) = e.attrs.get("member") {
                for m in member_list {
                    let cn = m.split(',').next().unwrap_or(m).replace("CN=", "");
                    output.push_str(&format!("  [+] {}\n", cn));
                    members.push(json!({"member": cn, "dn": m}));
                }
            }
        }
        if members.is_empty() { output.push_str("  [-] No members found or group not found\n"); }
        Ok(ModuleResult { success: !members.is_empty(), output, data: json!({"group": group, "members": members}), credentials: vec![] })
    }
}
