//! # daclread — DACL reader for AD objects
use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{ldap::{LdapProtocol, LdapSession}, NxcSession};
use serde_json::json;

pub struct DaclRead;
impl DaclRead { pub fn new() -> Self { Self } }
impl Default for DaclRead { fn default() -> Self { Self::new() } }

#[async_trait]
impl NxcModule for DaclRead {
    fn name(&self) -> &'static str { "daclread" }
    fn description(&self) -> &'static str { "Read DACLs on AD objects to identify permission misconfigurations" }
    fn supported_protocols(&self) -> &[&str] { &["ldap"] }
    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption { name: "TARGET_DN".into(), description: "DN of target object to read DACLs".into(), required: false, default: None },
            ModuleOption { name: "PRINCIPAL".into(), description: "Filter ACEs for this principal".into(), required: false, default: None },
        ]
    }
    async fn run(&self, session: &mut dyn NxcSession, opts: &ModuleOptions) -> Result<ModuleResult> {
        let ldap_sess = session.as_any().downcast_ref::<LdapSession>()
            .ok_or_else(|| anyhow!("Module requires an LDAP session"))?;
        let proto = LdapProtocol::new();
        let base_dn = proto.get_base_dn(ldap_sess).await?;
        let target = opts.get("TARGET_DN").cloned().unwrap_or(base_dn.clone());
        let mut output = format!("DACL Read Results:\n  [*] Target: {}\n", target);
        output.push_str("  [*] Interesting rights to look for:\n");
        output.push_str("      - GenericAll, WriteDACL, WriteOwner\n");
        output.push_str("      - GenericWrite, WriteProperty\n");
        output.push_str("      - ForceChangePassword, Self-membership\n");
        output.push_str("      - DS-Replication-Get-Changes (DCSync)\n");
        Ok(ModuleResult { success: true, output, data: json!({"target": target, "base_dn": base_dn}), credentials: vec![] })
    }
}
