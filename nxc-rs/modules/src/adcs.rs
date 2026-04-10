//! # AD CS Enumeration Module
//!
//! Enumerates Active Directory Certificate Services (AD CS) templates and CAs.

use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;
use tracing::{debug, info};

pub struct AdcsModule;

impl Default for AdcsModule {
    fn default() -> Self {
        Self::new()
    }
}

impl AdcsModule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl NxcModule for AdcsModule {
    fn name(&self) -> &'static str {
        "adcs"
    }

    fn description(&self) -> &'static str {
        "Enumerate AD CS Certificate Authorities and Templates"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["ldap"]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        _opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        info!("LDAP: Starting AD CS enumeration on {}", session.target());

        let mut output = String::new();
        let mut data_templates = Vec::new();
        let mut data_cas = Vec::new();

        if let Some(ldap_sess) = session.as_any().downcast_ref::<nxc_protocols::ldap::LdapSession>()
        {
            let protocol = nxc_protocols::ldap::LdapProtocol::new();
            let base_dn = protocol.get_base_dn(ldap_sess).await?;
            let config_dn = format!("CN=Configuration,{base_dn}");

            output.push_str(&format!("[*] AD CS Enumeration for {base_dn}\n"));
            output.push_str("--------------------------------------------------\n");

            // 1. Certification Authorities
            debug!("LDAP: Querying Certification Authorities in {}", config_dn);
            let ca_dn = format!(
                "CN=Certification Authorities,CN=Public Key Services,CN=Services,{config_dn}"
            );
            let ca_entries = protocol
                .search(
                    ldap_sess,
                    &ca_dn,
                    ldap3::Scope::OneLevel,
                    "(objectClass=certificationAuthority)",
                    vec!["cn"],
                )
                .await?;

            output.push_str("\n[+] Certification Authorities:\n");
            for entry in ca_entries {
                let cn = entry.attrs.get("cn").and_then(|v| v.first()).cloned().unwrap_or_default();
                output.push_str(&format!("  - {cn}\n"));
                data_cas.push(cn);
            }

            // 2. Enrollment Services (CAs that actually issue certs)
            debug!("LDAP: Querying Enrollment Services in {}", config_dn);
            let enroll_dn =
                format!("CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_dn}");
            let enroll_entries = protocol
                .search(
                    ldap_sess,
                    &enroll_dn,
                    ldap3::Scope::OneLevel,
                    "(objectClass=pkiEnrollmentService)",
                    vec!["cn", "dNSHostName", "cACertificate"],
                )
                .await?;

            output.push_str("\n[+] Enrollment Services (Active CAs):\n");
            for entry in enroll_entries {
                let cn = entry.attrs.get("cn").and_then(|v| v.first()).cloned().unwrap_or_default();
                let host = entry
                    .attrs
                    .get("dNSHostName")
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_default();
                output.push_str(&format!("  - {cn} (Host: {host})\n"));
            }

            // 3. Certificate Templates
            debug!("LDAP: Querying Certificate Templates in {}", config_dn);
            let template_dn = format!(
                "CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_dn}"
            );
            let template_entries = protocol
                .search(
                    ldap_sess,
                    &template_dn,
                    ldap3::Scope::OneLevel,
                    "(objectClass=pkicertificateTemplate)",
                    vec![
                        "cn",
                        "displayName",
                        "msPKI-Certificate-Name-Flag",
                        "msPKI-Enrollment-Flag",
                        "msPKI-RA-Signature",
                        "pKIExtendedKeyUsage",
                    ],
                )
                .await?;

            output.push_str("\n[+] Certificate Templates & Vulnerabilities:\n");
            for entry in template_entries {
                let cn = entry.attrs.get("cn").and_then(|v| v.first()).cloned().unwrap_or_default();
                let display_name = entry
                    .attrs
                    .get("displayName")
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_default();

                let name_flags = entry
                    .attrs
                    .get("msPKI-Certificate-Name-Flag")
                    .and_then(|v| v.first())
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(0);
                let enrollment_flags = entry
                    .attrs
                    .get("msPKI-Enrollment-Flag")
                    .and_then(|v| v.first())
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(0);
                let _ra_signature = entry
                    .attrs
                    .get("msPKI-RA-Signature")
                    .and_then(|v| v.first())
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(0);
                let ekus = entry.attrs.get("pKIExtendedKeyUsage").cloned().unwrap_or_default();

                let mut vulns = Vec::new();

                // ESC1: Enrollee Supplies Subject + Client Auth EKU + no manager approval
                let is_esc1 = (name_flags & 0x00000001 != 0) && // CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
                              (enrollment_flags & 0x00000001 == 0) && // CT_FLAG_PEND_ALL_REQUESTS (no manager approval)
                              ekus.iter().any(|e| e == "1.3.6.1.5.5.7.3.2" || e == "2.5.29.37.0"); // Client Auth or Any Purpose

                if is_esc1 {
                    vulns.push("ESC1");
                }

                // ESC2: Any Purpose EKU or No EKU (which often means Any Purpose)
                let is_esc2 = ekus.iter().any(|e| e == "2.5.29.37.0") || ekus.is_empty();
                if is_esc2 {
                    vulns.push("ESC2");
                }

                // ESC3: Certificate Request Agent EKU (Enrollment Agent)
                let is_esc3 = ekus.iter().any(|e| e == "1.3.6.1.4.1.311.20.2.1");
                if is_esc3 {
                    vulns.push("ESC3");
                }

                if !vulns.is_empty() {
                    output.push_str(&format!(
                        "  [!] {} ({}) - Vulnerable: {}\n",
                        cn,
                        display_name,
                        vulns.join(", ")
                    ));
                } else {
                    output.push_str(&format!("  - {cn} ({display_name})\n"));
                }

                data_templates.push(serde_json::json!({
                    "cn": cn,
                    "display_name": display_name,
                    "vulnerabilities": vulns
                }));
            }
        } else {
            return Err(anyhow::anyhow!(
                "Module adcs only supports LDAP protocol session downcasting."
            ));
        }

        Ok(ModuleResult {
            credentials: vec![],
            success: true,
            output,
            data: serde_json::json!({
                "templates": data_templates,
                "cas": data_cas
            }),
        })
    }
}

// Removed get_root_dn stub as base_dn discovery is now integrated into the protocol handler.
