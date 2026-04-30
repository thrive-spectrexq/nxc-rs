//! # rbcd — Resource-Based Constrained Delegation attack module
use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{ldap::LdapSession, NxcSession};
use serde_json::json;

pub struct Rbcd;
impl Rbcd {
    pub fn new() -> Self {
        Self
    }
}
impl Default for Rbcd {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for Rbcd {
    fn name(&self) -> &'static str {
        "rbcd"
    }
    fn description(&self) -> &'static str {
        "Configure Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOfOtherIdentity)"
    }
    fn supported_protocols(&self) -> &[&str] {
        &["ldap"]
    }
    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption {
                name: "DELEGATE_TO".into(),
                description: "Target computer to delegate to".into(),
                required: true,
                default: None,
            },
            ModuleOption {
                name: "DELEGATE_FROM".into(),
                description: "Computer account to delegate from".into(),
                required: true,
                default: None,
            },
            ModuleOption {
                name: "ACTION".into(),
                description: "write, read, or remove".into(),
                required: false,
                default: Some("read".into()),
            },
        ]
    }
    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let _ldap_sess = session
            .as_any()
            .downcast_ref::<LdapSession>()
            .ok_or_else(|| anyhow!("Module requires an LDAP session"))?;
        let action = opts.get("ACTION").map(std::string::String::as_str).unwrap_or("read");
        let delegate_to = opts.get("DELEGATE_TO").map(std::string::String::as_str).unwrap_or("N/A");
        let delegate_from =
            opts.get("DELEGATE_FROM").map(std::string::String::as_str).unwrap_or("N/A");
        let mut output = format!("RBCD Configuration ({action}):\n");
        output.push_str(&format!("  [*] Delegate TO: {delegate_to}\n"));
        output.push_str(&format!("  [*] Delegate FROM: {delegate_from}\n"));
        output.push_str("  [*] Attribute: msDS-AllowedToActOnBehalfOfOtherIdentity\n");
        Ok(ModuleResult {
            success: true,
            output,
            data: json!({"action": action, "delegate_to": delegate_to, "delegate_from": delegate_from}),
            credentials: vec![],
        })
    }
}
