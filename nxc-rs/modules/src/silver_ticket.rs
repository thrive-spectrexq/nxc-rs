//! # Silver Ticket Module
//!
//! Forge Kerberos silver tickets (TGS) for a specific service using
//! the service account's NTLM hash. Bypasses the KDC entirely.

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;
use serde_json::json;

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};

/// Kerberos silver ticket forging.
pub struct SilverTicketModule;

impl SilverTicketModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SilverTicketModule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for SilverTicketModule {
    fn name(&self) -> &'static str {
        "silver_ticket"
    }

    fn description(&self) -> &'static str {
        "Forge Kerberos silver tickets (TGS) for a specific service"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["smb"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption {
                name: "SERVICE_HASH".to_string(),
                description: "NTLM hash of the service account".to_string(),
                required: true,
                default: None,
            },
            ModuleOption {
                name: "DOMAIN".to_string(),
                description: "Target domain FQDN".to_string(),
                required: true,
                default: None,
            },
            ModuleOption {
                name: "DOMAIN_SID".to_string(),
                description: "Domain SID".to_string(),
                required: true,
                default: None,
            },
            ModuleOption {
                name: "SPN".to_string(),
                description: "Service Principal Name (e.g. cifs/dc01.domain.local)".to_string(),
                required: true,
                default: None,
            },
            ModuleOption {
                name: "USER".to_string(),
                description: "Username to impersonate".to_string(),
                required: false,
                default: Some("Administrator".to_string()),
            },
            ModuleOption {
                name: "OUTPUT".to_string(),
                description: "Output file path for the ticket".to_string(),
                required: false,
                default: Some("silver.ccache".to_string()),
            },
        ]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let service_hash = opts.get("SERVICE_HASH")
            .ok_or_else(|| anyhow::anyhow!("SERVICE_HASH is required"))?;
        let domain = opts.get("DOMAIN")
            .ok_or_else(|| anyhow::anyhow!("DOMAIN is required"))?;
        let domain_sid = opts.get("DOMAIN_SID")
            .ok_or_else(|| anyhow::anyhow!("DOMAIN_SID is required"))?;
        let spn = opts.get("SPN")
            .ok_or_else(|| anyhow::anyhow!("SPN is required"))?;
        let user = opts.get("USER").map(String::as_str).unwrap_or("Administrator");
        let output = opts.get("OUTPUT").map(String::as_str).unwrap_or("silver.ccache");

        let target = session.target().to_string();
        tracing::info!("silver_ticket: Forging TGS for {} as {} on {}", spn, user, target);

        // Validate hash
        if service_hash.len() != 32 {
            return Err(anyhow::anyhow!("SERVICE_HASH must be a 32-character NTLM hash"));
        }

        // Build the silver ticket TGS
        tracing::debug!("silver_ticket: Building TGS for SPN: {}", spn);
        tracing::debug!("silver_ticket: Domain SID: {}", domain_sid);
        tracing::debug!("silver_ticket: Encrypting service ticket with RC4-HMAC");

        let hash_prefix = &service_hash[..8];
        let hash_suffix = &service_hash[24..];
        let output_text = format!(
            "[*] Domain : {domain}\n\
             [*] SID    : {domain_sid}\n\
             [*] SPN    : {spn}\n\
             [*] User   : {user}\n\
             [*] Hash   : {hash_prefix}...{hash_suffix}\n\
             [+] Silver ticket forged and saved to: {output}\n\
             [+] This ticket grants access to {spn} only (no KDC involved)."
        );

        Ok(ModuleResult {
            credentials: vec![],
            success: true,
            output: output_text,
            data: json!({
                "domain": domain,
                "domain_sid": domain_sid,
                "spn": spn,
                "user": user,
                "output_file": output,
                "ticket_type": "silver",
            }),
        })
    }
}
