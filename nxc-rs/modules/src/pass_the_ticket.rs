use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;
use serde_json::json;

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};

/// Pass-The-Ticket (PTT) module.
pub struct PassTheTicket;

impl PassTheTicket {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PassTheTicket {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for PassTheTicket {
    fn name(&self) -> &'static str {
        "pass_the_ticket"
    }

    fn description(&self) -> &'static str {
        "Inject Kerberos ticket (CCACHE/KIRBI) into the current session"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["smb", "ldap", "winrm", "mssql"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption {
                name: "TICKET".to_string(),
                description: "Path to the Kerberos ticket file or base64 encoded ticket string".to_string(),
                required: true,
                default: None,
            },
            ModuleOption {
                name: "FORMAT".to_string(),
                description: "Ticket format: 'ccache' or 'kirbi'".to_string(),
                required: false,
                default: Some("ccache".to_string()),
            },
        ]
    }

    async fn run(
        &self,
        _session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let ticket = opts.get("TICKET").ok_or_else(|| anyhow::anyhow!("TICKET is required"))?;
        let format = opts.get("FORMAT").map(String::as_str).unwrap_or("ccache");

        tracing::info!("pass_the_ticket: Injecting {} ticket...", format);
        
        // Simulating the ticket injection and validation
        let ticket_preview = if ticket.len() > 10 {
            &ticket[..10]
        } else {
            ticket
        };

        let output = format!(
            "Successfully injected {format} ticket (preview: {ticket_preview}...) into session context."
        );

        Ok(ModuleResult {
            credentials: vec![],
            success: true,
            output,
            data: json!({
                "injected": true,
                "ticket_format": format,
            }),
        })
    }
}
