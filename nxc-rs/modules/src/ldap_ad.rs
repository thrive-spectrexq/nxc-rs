//! # LDAP Advanced AD Enumeration Module
//!
//! Provides in-depth analysis of AD objects:
//! - GPO: List Group Policy Objects and their paths.
//! - Trusts: Map directional and transitive domain trusts.
//! - ACLs: Find delegation and interesting security attributes.

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::ldap::{LdapProtocol, LdapSession};
use nxc_protocols::NxcSession;
use serde_json::json;

pub struct LdapAdModule;

impl Default for LdapAdModule {
    fn default() -> Self {
        Self::new()
    }
}

impl LdapAdModule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl NxcModule for LdapAdModule {
    fn name(&self) -> &'static str {
        "ldap_ad"
    }

    fn description(&self) -> &'static str {
        "Advanced AD enumeration (GPOs, Trusts, Delegation)"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["ldap"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![ModuleOption {
            name: "type".into(),
            description: "Type of enum: gpo, trusts, delegation, all".into(),
            required: false,
            default: Some("all".into()),
        }]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let ldap_sess = session
            .as_any()
            .downcast_ref::<LdapSession>()
            .ok_or_else(|| anyhow!("Invalid session type"))?;

        let proto = LdapProtocol::new();
        let enum_type = opts.get("type").map(std::string::String::as_str).unwrap_or("all");

        let mut output = String::new();
        let mut results = json!({});

        if enum_type == "gpo" || enum_type == "all" {
            let gpos = self.enum_gpos(&proto, ldap_sess).await?;
            output.push_str(&format!("\n[+] Group Policy Objects ({}):\n", gpos.len()));
            for gpo in &gpos {
                output.push_str(&format!("  - {} ({})\n", gpo["name"], gpo["path"]));
            }
            results["gpos"] = json!(gpos);
        }

        if enum_type == "trusts" || enum_type == "all" {
            let trusts = self.enum_trusts(&proto, ldap_sess).await?;
            output.push_str(&format!("\n[+] Domain Trusts ({}):\n", trusts.len()));
            for trust in &trusts {
                output.push_str(&format!(
                    "  - {} (Direction: {}, Type: {})\n",
                    trust["partner"], trust["direction"], trust["type"]
                ));
            }
            results["trusts"] = json!(trusts);
        }

        if enum_type == "delegation" || enum_type == "all" {
            let delegation = self.enum_delegation(&proto, ldap_sess).await?;
            output.push_str(&format!(
                "\n[+] Constrained/Unconstrained Delegation ({}):\n",
                delegation.len()
            ));
            for item in &delegation {
                output.push_str(&format!("  - {} (Type: {})\n", item["name"], item["type"]));
            }
            results["delegation"] = json!(delegation);
        }

        Ok(ModuleResult { success: true, output, data: results, credentials: vec![] })
    }
}

impl LdapAdModule {
    async fn enum_gpos(
        &self,
        proto: &LdapProtocol,
        session: &LdapSession,
    ) -> Result<Vec<serde_json::Value>> {
        let base_dn = proto.get_base_dn(session).await?;
        let filter = "(objectCategory=groupPolicyContainer)";
        let entries = proto
            .search(
                session,
                &base_dn,
                ldap3::Scope::Subtree,
                filter,
                vec!["displayName", "gPCFileSysPath"],
            )
            .await?;

        let mut results = Vec::new();
        for entry in entries {
            let name =
                entry.attrs.get("displayName").and_then(|v| v.first()).cloned().unwrap_or_default();
            let path = entry
                .attrs
                .get("gPCFileSysPath")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            results.push(json!({"name": name, "path": path}));
        }
        Ok(results)
    }

    async fn enum_trusts(
        &self,
        proto: &LdapProtocol,
        session: &LdapSession,
    ) -> Result<Vec<serde_json::Value>> {
        let base_dn = proto.get_base_dn(session).await?;
        let filter = "(objectClass=trustedDomain)";
        let entries = proto
            .search(
                session,
                &base_dn,
                ldap3::Scope::Subtree,
                filter,
                vec!["trustPartner", "trustDirection", "trustType"],
            )
            .await?;

        let mut results = Vec::new();
        for entry in entries {
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
            let direction_str = match direction.as_str() {
                "1" => "Inbound",
                "2" => "Outbound",
                "3" => "Bidirectional",
                _ => "Unknown",
            };
            let t_type =
                entry.attrs.get("trustType").and_then(|v| v.first()).cloned().unwrap_or_default();
            results.push(json!({"partner": partner, "direction": direction_str, "type": t_type}));
        }
        Ok(results)
    }

    async fn enum_delegation(
        &self,
        proto: &LdapProtocol,
        session: &LdapSession,
    ) -> Result<Vec<serde_json::Value>> {
        let base_dn = proto.get_base_dn(session).await?;
        // Unconstrained: userAccountControl & 0x80000
        // Constrained: msDS-AllowedToDelegateTo exists
        let filter =
            "(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(msDS-AllowedToDelegateTo=*))";
        let entries = proto
            .search(
                session,
                &base_dn,
                ldap3::Scope::Subtree,
                filter,
                vec!["sAMAccountName", "userAccountControl", "msDS-AllowedToDelegateTo"],
            )
            .await?;

        let mut results = Vec::new();
        for entry in entries {
            let name = entry
                .attrs
                .get("sAMAccountName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let uac = entry
                .attrs
                .get("userAccountControl")
                .and_then(|v| v.first())
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(0);

            let mut d_type = String::new();
            if uac & 524288 != 0 {
                d_type.push_str("Unconstrained");
            }
            if entry.attrs.contains_key("msDS-AllowedToDelegateTo") {
                if !d_type.is_empty() {
                    d_type.push_str(", ");
                }
                d_type.push_str("Constrained");
            }

            results.push(json!({"name": name, "type": d_type}));
        }
        Ok(results)
    }
}
