//! # laps — LDAP LAPS Enumeration Module
//!
//! Retrieves LAPS passwords which the account has read permissions for.
//! Equivalent to `nxc ldap <target> -u <user> -p <pass> -M laps [-o COMPUTER=<wildcard>]`.

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};

/// LDAP LAPS module.
pub struct Laps;

impl Laps {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Laps {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for Laps {
    fn name(&self) -> &'static str {
        "laps"
    }

    fn description(&self) -> &'static str {
        "Retrieves all LAPS passwords which the account has read permissions for"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["ldap"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![ModuleOption {
            name: "COMPUTER".to_string(),
            description: "Computer name or wildcard ex: WIN-S10, WIN-* etc. Default: *".to_string(),
            required: false,
            default: None,
        }]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let computer_filter = opts.get("COMPUTER").map(|s| s.as_str()).unwrap_or("*");

        let ldap_session = match session.protocol() {
            "ldap" => session.downcast_mut::<nxc_protocols::ldap::LdapSession>().unwrap(),
            _ => return Err(anyhow::anyhow!("Module only supports LDAP")),
        };

        let protocol = nxc_protocols::ldap::LdapProtocol::new();
        let base_dn = protocol.get_base_dn(ldap_session).await?;

        tracing::debug!(
            "laps: Querying LAPS passwords for computer '{}' in {}",
            computer_filter,
            base_dn
        );

        // Filter for computers with any LAPS attributes
        let filter = format!(
            "(&(objectCategory=computer)(|(ms-MCS-AdmPwd=*)(msLAPS-Password=*)(msLAPS-EncryptedPassword=*))(name={computer_filter}))"
        );

        let attrs = vec![
            "sAMAccountName",
            "name",
            "ms-MCS-AdmPwd",
            "msLAPS-Password",
            "msLAPS-EncryptedPassword",
            "msLAPS-PasswordExpirationTime",
        ];

        let entries =
            protocol.search(ldap_session, &base_dn, ldap3::Scope::Subtree, &filter, attrs).await?;

        let mut output_lines = Vec::new();
        let mut laps_results = Vec::new();

        output_lines.push("🛸 <b>LAPS Intelligence Extraction</b>\n".to_string());

        if entries.is_empty() {
            output_lines.push(format!("No computers found matching filter: {computer_filter}"));
        } else {
            for entry in &entries {
                let name =
                    entry.attrs.get("name").and_then(|v| v.first()).cloned().unwrap_or_default();
                let sam = entry
                    .attrs
                    .get("sAMAccountName")
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_default();

                let mut expiration = "Never".to_string();
                if let Some(exp_str) =
                    entry.attrs.get("msLAPS-PasswordExpirationTime").and_then(|v| v.first())
                {
                    if let Ok(exp_val) = exp_str.parse::<i64>() {
                        // Windows FileTime is 100ns intervals since 1601-01-01
                        let secs = (exp_val / 10_000_000) - 11_644_473_600;
                        if let Some(dt) = chrono::DateTime::from_timestamp(secs, 0) {
                            expiration = dt.format("%Y-%m-%d %H:%M:%S").to_string();
                        }
                    }
                }

                let (version, password) = if let Some(p) =
                    entry.attrs.get("ms-MCS-AdmPwd").and_then(|v| v.first())
                {
                    ("Legacy", p.clone())
                } else if let Some(p) = entry.attrs.get("msLAPS-Password").and_then(|v| v.first()) {
                    ("New-Clear", p.clone())
                } else if let Some(p_bin) =
                    entry.bin_attrs.get("msLAPS-EncryptedPassword").and_then(|v| v.first())
                {
                    (
                        "New-Encrypted",
                        format!(
                            "[Encrypted Blob: {}...]",
                            hex::encode(&p_bin[..16.min(p_bin.len())])
                        ),
                    )
                } else {
                    continue;
                };

                let line = format!(
                    "{name:<15} | {version:<12} | Exp: {expiration:<19} | Pwd: {password}"
                );
                output_lines.push(line);

                laps_results.push(serde_json::json!({
                    "computer": name,
                    "sAMAccountName": sam,
                    "version": version,
                    "expiration": expiration,
                    "password": password
                }));
            }
        }

        if laps_results.is_empty() && !entries.is_empty() {
            output_lines.push(
                "Matched computers but could not read LAPS attributes (permission denied?)"
                    .to_string(),
            );
        }

        Ok(ModuleResult {
            credentials: vec![],
            success: true,
            output: output_lines.join("\n"),
            data: serde_json::json!(laps_results),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_laps_metadata() {
        let module = Laps::new();
        assert_eq!(module.name(), "laps");
        assert!(module.supported_protocols().contains(&"ldap"));
    }
}
