//! # mssql_enum — MSSQL Enumeration Module
//!
//! Enumerates SQL Logins and Databases.

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::mssql::{MssqlProtocol, MssqlSession};
use nxc_protocols::NxcSession;

use crate::{ModuleOptions, ModuleResult, NxcModule};

/// MSSQL Enumeration module.
pub struct MssqlEnum;

impl MssqlEnum {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MssqlEnum {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for MssqlEnum {
    fn name(&self) -> &'static str {
        "mssql_enum"
    }

    fn description(&self) -> &'static str {
        "Enumerate SQL Logins and Databases"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["mssql"]
    }

    async fn run(&self, session: &dyn NxcSession, _opts: &ModuleOptions) -> Result<ModuleResult> {
        let mssql_session = match session.protocol() {
            "mssql" => unsafe { &*(session as *const dyn NxcSession as *const MssqlSession) },
            _ => return Err(anyhow::anyhow!("Module only supports MSSQL")),
        };

        let protocol = MssqlProtocol::new();
        let mut output_lines = Vec::new();
        let mut data = serde_json::Map::new();

        // 1. Enumerate Logins
        output_lines.push("[*] Enumerating SQL Logins:".to_string());
        match protocol
            .query_json(
                mssql_session,
                "SELECT name, type_desc, is_disabled FROM sys.sql_logins",
            )
            .await
        {
            Ok(logins) => {
                let mut login_list = Vec::new();
                for login in &logins {
                    if let Some(obj) = login.as_object() {
                        let name = obj
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown");
                        let disabled =
                            obj.get("is_disabled").and_then(|v| v.as_i64()).unwrap_or(0) == 1;
                        output_lines.push(format!("    - {} (Disabled: {})", name, disabled));
                        login_list.push(login.clone());
                    }
                }
                data.insert("logins".to_string(), serde_json::Value::Array(login_list));
            }
            Err(e) => output_lines.push(format!("    [!] Failed to enumerate logins: {}", e)),
        }

        output_lines.push("".to_string());

        // 2. Enumerate Databases
        output_lines.push("[*] Enumerating Databases:".to_string());
        match protocol
            .query_json(mssql_session, "SELECT name, state_desc FROM sys.databases")
            .await
        {
            Ok(dbs) => {
                let mut db_list = Vec::new();
                for db in &dbs {
                    if let Some(obj) = db.as_object() {
                        let name = obj
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown");
                        let state = obj
                            .get("state_desc")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown");
                        output_lines.push(format!("    - {} (State: {})", name, state));
                        db_list.push(db.clone());
                    }
                }
                data.insert("databases".to_string(), serde_json::Value::Array(db_list));
            }
            Err(e) => output_lines.push(format!("    [!] Failed to enumerate databases: {}", e)),
        }

        Ok(ModuleResult {
            success: true,
            output: output_lines.join("\n"),
            data: serde_json::Value::Object(data),
        })
    }
}
