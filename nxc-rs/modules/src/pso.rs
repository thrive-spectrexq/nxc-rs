//! # pso — Password Settings Objects (Fine-Grained Password Policy)
use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{
    ldap::{LdapProtocol, LdapSession},
    NxcSession,
};
use serde_json::json;

pub struct Pso;
impl Pso {
    pub fn new() -> Self {
        Self
    }
}
impl Default for Pso {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for Pso {
    fn name(&self) -> &'static str {
        "pso"
    }
    fn description(&self) -> &'static str {
        "Dump Fine-Grained Password Policies (Password Settings Objects)"
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
                "(objectClass=msDS-PasswordSettings)",
                vec![
                    "cn",
                    "msDS-MinimumPasswordLength",
                    "msDS-PasswordComplexityEnabled",
                    "msDS-LockoutThreshold",
                    "msDS-PasswordHistoryLength",
                ],
            )
            .await?;
        let mut output = format!("Password Settings Objects ({}):\n", entries.len());
        let mut psos = Vec::new();
        for e in &entries {
            let name = e.attrs.get("cn").and_then(|v| v.first()).cloned().unwrap_or_default();
            let min_len = e
                .attrs
                .get("msDS-MinimumPasswordLength")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let lockout = e
                .attrs
                .get("msDS-LockoutThreshold")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            output
                .push_str(&format!("  [+] {name} (MinLen: {min_len}, Lockout: {lockout})\n"));
            psos.push(json!({"name": name, "min_length": min_len, "lockout_threshold": lockout}));
        }
        if entries.is_empty() {
            output.push_str("  [-] No PSOs found (using Default Domain Policy)\n");
        }
        Ok(ModuleResult { success: true, output, data: json!({"psos": psos}), credentials: vec![] })
    }
}
