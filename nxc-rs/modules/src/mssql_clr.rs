//! # MSSQL CLR (Common Language Runtime) Module
//!
//! Provides advanced post-exploitation for MSSQL:
//! - clr_enable: Enable CLR execution on the target.
//! - clr_list: List existing loaded assemblies.
//! - clr_exec: (Simplified) Foundation for assembly execution.

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::mssql::{MssqlProtocol, MssqlSession};
use nxc_protocols::NxcSession;
use serde_json::json;

pub struct MssqlClr;

impl Default for MssqlClr {
    fn default() -> Self {
        Self::new()
    }
}

impl MssqlClr {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl NxcModule for MssqlClr {
    fn name(&self) -> &'static str {
        "mssql_clr"
    }

    fn description(&self) -> &'static str {
        "MSSQL CLR Management (Enable, List, and Prep)"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["mssql"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![ModuleOption {
            name: "action".into(),
            description: "Action: enable, list, disable".into(),
            required: false,
            default: Some("list".into()),
        }]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let mssql_sess = session
            .as_any()
            .downcast_ref::<MssqlSession>()
            .ok_or_else(|| anyhow!("Invalid session type"))?;

        let proto = MssqlProtocol::new();
        let action = opts.get("action").map(|s| s.as_str()).unwrap_or("list");

        let mut output = String::new();
        let mut results = json!({});

        match action {
            "enable" => {
                self.enable_clr(&proto, mssql_sess).await?;
                output.push_str("[+] CLR execution enabled on target.\n");
                results["status"] = json!("enabled");
            }
            "disable" => {
                self.disable_clr(&proto, mssql_sess).await?;
                output.push_str("[+] CLR execution disabled on target.\n");
                results["status"] = json!("disabled");
            }
            _ => {
                let assemblies = self.list_assemblies(&proto, mssql_sess).await?;
                output.push_str(&format!("\n[+] Loaded Assemblies ({}):\n", assemblies.len()));
                for ass in &assemblies {
                    output.push_str(&format!(
                        "  - {} (Permissions: {})\n",
                        ass["name"], ass["permission_set"]
                    ));
                }
                results["assemblies"] = json!(assemblies);
            }
        }

        Ok(ModuleResult { success: true, output, data: results, credentials: vec![] })
    }
}

impl MssqlClr {
    async fn enable_clr(&self, proto: &MssqlProtocol, session: &MssqlSession) -> Result<()> {
        let sql = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'clr enabled', 1; RECONFIGURE; EXEC sp_configure 'clr strict security', 0; RECONFIGURE;";
        proto.query_json(session, sql).await?;
        Ok(())
    }

    async fn disable_clr(&self, proto: &MssqlProtocol, session: &MssqlSession) -> Result<()> {
        let sql = "EXEC sp_configure 'clr enabled', 0; RECONFIGURE;";
        proto.query_json(session, sql).await?;
        Ok(())
    }

    async fn list_assemblies(
        &self,
        proto: &MssqlProtocol,
        session: &MssqlSession,
    ) -> Result<Vec<serde_json::Value>> {
        let sql =
            "SELECT name, permission_set_desc as permission_set, create_date FROM sys.assemblies";
        proto.query_json(session, sql).await
    }
}
