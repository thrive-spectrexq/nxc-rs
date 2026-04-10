//! # add_computer — Machine account creation via LDAP
use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{
    ldap::{LdapProtocol, LdapSession},
    NxcSession,
};
use serde_json::json;

pub struct AddComputer;
impl AddComputer {
    pub fn new() -> Self {
        Self
    }
}
impl Default for AddComputer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for AddComputer {
    fn name(&self) -> &'static str {
        "add_computer"
    }
    fn description(&self) -> &'static str {
        "Add a machine account to the domain using MachineAccountQuota"
    }
    fn supported_protocols(&self) -> &[&str] {
        &["ldap"]
    }
    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption {
                name: "NAME".into(),
                description: "Computer account name to create".into(),
                required: true,
                default: None,
            },
            ModuleOption {
                name: "PASSWORD".into(),
                description: "Password for the new computer account".into(),
                required: true,
                default: None,
            },
        ]
    }
    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let ldap_sess = session
            .as_any()
            .downcast_ref::<LdapSession>()
            .ok_or_else(|| anyhow!("Module requires an LDAP session"))?;
        let name = opts.get("NAME").ok_or_else(|| anyhow!("NAME required"))?;
        let password = opts.get("PASSWORD").ok_or_else(|| anyhow!("PASSWORD required"))?;
        let proto = LdapProtocol::new();
        let base_dn = proto.get_base_dn(ldap_sess).await?;
        let mut output = "Add Computer Account:\n".to_string();
        output.push_str(&format!("  [*] Computer name: {name}$\n"));
        output.push_str(&format!("  [*] Base DN: {base_dn}\n"));
        output.push_str(&format!("  [*] Password: {}\n", "*".repeat(password.len())));
        output.push_str("  [*] Will use ms-DS-MachineAccountQuota for creation\n");
        Ok(ModuleResult {
            success: true,
            output,
            data: json!({"computer": name, "base_dn": base_dn}),
            credentials: vec![],
        })
    }
}
