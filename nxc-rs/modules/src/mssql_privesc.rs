use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{mssql::MssqlSession, mssql::MssqlProtocol, NxcSession};
use serde_json::json;
use tracing::info;

pub struct MssqlPrivesc {}

impl MssqlPrivesc {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for MssqlPrivesc {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for MssqlPrivesc {
    fn name(&self) -> &'static str {
        "mssql_privesc"
    }

    fn description(&self) -> &'static str {
        "Checks for MSSQL Privilege Escalation paths via IMPERSONATE rights and TRUSTWORTHY databases."
    }

    fn supported_protocols(&self) -> &[&str] {
        &["mssql"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        _opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let mssql_sess = session
            .as_any()
            .downcast_ref::<MssqlSession>()
            .ok_or_else(|| anyhow!("Module requires an MSSQL session"))?;

        info!("Starting MSSQL Privilege Escalation checks on {}", mssql_sess.target);

        let mut output = String::from("MSSQL Privilege Escalation Checks:\n");
        let mut privsec_found = false;
        
        let protocol = MssqlProtocol::new();
        let mut findings = Vec::new();

        // 1. Check for IMPERSONATE privileges
        let sql_impersonate = "
            SELECT p.name AS principal_name, p.type_desc AS principal_type, 
                   pe.permission_name, pe.state_desc,
                   tp.name AS grantee_name
            FROM sys.server_permissions pe
            JOIN sys.server_principals p ON pe.grantor_principal_id = p.principal_id
            JOIN sys.server_principals tp ON pe.grantee_principal_id = tp.principal_id
            WHERE pe.permission_name = 'IMPERSONATE' AND tp.name = SUSER_NAME();
        ";

        if let Ok(res) = protocol.query_json(mssql_sess, sql_impersonate).await {
            if !res.is_empty() {
                privsec_found = true;
                output.push_str("  [!] IMPERSONATE Privilege Grants Found:\n");
                for row in &res {
                    if let Some(target) = row.get("principal_name").and_then(|v| v.as_str()) {
                        output.push_str(&format!("      -> Can impersonate: {}\n", target));
                        findings.push(json!({"type": "IMPERSONATE", "target": target}));
                    }
                }
            }
        }

        // 2. Check for TRUSTWORTHY databases owned by sysadmins
        // Note: For full accuracy you'd check if the user is dbo on that DB, but just listing them is a strong flag
        let sql_trustworthy = "
            SELECT d.name AS db_name, SUSER_SNAME(d.owner_sid) AS owner_name, is_trustworthy_on
            FROM sys.databases d
            WHERE d.is_trustworthy_on = 1 AND d.name != 'msdb';
        ";

        if let Ok(res) = protocol.query_json(mssql_sess, sql_trustworthy).await {
            if !res.is_empty() {
                // If they exist, it's worth reporting. We won't assert full exploitability generically.
                privsec_found = true;
                output.push_str("  [!] TRUSTWORTHY Databases Found (potential privesc if dbo):\n");
                for row in &res {
                    let db_name = row.get("db_name").and_then(|v| v.as_str()).unwrap_or("UNKNOWN");
                    let owner = row.get("owner_name").and_then(|v| v.as_str()).unwrap_or("UNKNOWN");
                    output.push_str(&format!("      -> DB: {}, Owner: {}\n", db_name, owner));
                    findings.push(json!({"type": "TRUSTWORTHY_DB", "db": db_name, "owner": owner}));
                }
            }
        }

        if !privsec_found {
            output.push_str("  [-] No obvious low-hanging privilege escalations (IMPERSONATE/TRUSTWORTHY) discovered.\n");
        }

        Ok(ModuleResult {
            success: privsec_found,
            output,
            data: json!({ "privesc_paths": findings }),
            credentials: vec![],
        })
    }
}
