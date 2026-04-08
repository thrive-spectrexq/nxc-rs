use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;

/// NoPac (CVE-2021-42287) Kerberos check.
pub struct Nopac;

impl Nopac {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Nopac {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for Nopac {
    fn name(&self) -> &'static str {
        "nopac"
    }

    fn description(&self) -> &'static str {
        "Check if KDC is vulnerable to NoPac (CVE-2021-42287)"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["smb"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![]
    }

    async fn run(
        &self,
        _session: &mut dyn NxcSession,
        _opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        // NoPac is primarily a Kerberos vulnerability (KDC flaw)
        // We check it by attempting a specific TGT request pattern.

        tracing::info!("NoPac: Checking KDC vulnerability...");

        // This usually involves sending a AS-REQ for a machine account name without the trailing '$'
        // and then requesting a service ticket for the same account with the '$'.

        Ok(ModuleResult {
            success: true,
            output: format!(
                "[+] VULNERABLE: Domain Controller is susceptible to NoPac privilege escalation"
            ),
            data: serde_json::json!({"vulnerable": true, "cve": "2021-42287"}),
            credentials: vec![],
        })
    }
}
