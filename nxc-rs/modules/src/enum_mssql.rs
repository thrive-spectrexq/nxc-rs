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

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        _opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let mssql_session = match session.protocol() {
            "mssql" => session
                .as_any()
                .downcast_ref::<MssqlSession>()
                .ok_or_else(|| anyhow::anyhow!("Invalid session type"))?,
            _ => return Err(anyhow::anyhow!("Module only supports MSSQL")),
        };

        let protocol = MssqlProtocol::new();
        let mut output_lines = Vec::new();
        let mut data = serde_json::Map::new();

        // 1. Enumerate Logins
        output_lines.push("[*] Enumerating SQL Logins:".to_string());
        match protocol
            .query_json(mssql_session, "SELECT name, type_desc, is_disabled FROM sys.sql_logins")
            .await
        {
            Ok(logins) => {
                let mut login_list = Vec::new();
                for login in &logins {
                    if let Some(obj) = login.as_object() {
                        let name = obj.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown");
                        let disabled =
                            obj.get("is_disabled").and_then(serde_json::Value::as_i64).unwrap_or(0)
                                == 1;
                        output_lines.push(format!("    - {name} (Disabled: {disabled})"));
                        login_list.push(login.clone());
                    }
                }
                data.insert("logins".to_string(), serde_json::Value::Array(login_list));
            }
            Err(e) => output_lines.push(format!("    [!] Failed to enumerate logins: {e}")),
        }

        output_lines.push("".to_string());

        // 2. Enumerate Databases
        output_lines.push("[*] Enumerating Databases:".to_string());
        match protocol.query_json(mssql_session, "SELECT name, state_desc FROM sys.databases").await
        {
            Ok(dbs) => {
                let mut db_list = Vec::new();
                for db in &dbs {
                    if let Some(obj) = db.as_object() {
                        let name = obj.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown");
                        let state =
                            obj.get("state_desc").and_then(|v| v.as_str()).unwrap_or("Unknown");
                        output_lines.push(format!("    - {name} (State: {state})"));
                        db_list.push(db.clone());
                    }
                }
                data.insert("databases".to_string(), serde_json::Value::Array(db_list));
            }
            Err(e) => output_lines.push(format!("    [!] Failed to enumerate databases: {e}")),
        }

        output_lines.push("".to_string());

        // 3. Enumerate IMPERSONATE privileges
        output_lines.push("[*] Enumerating IMPERSONATE Privileges:".to_string());
        match protocol
            .query_json(
                mssql_session,
                "SELECT grantor.name as Grantor, grantee.name as Grantee, permission_name \
                 FROM sys.server_permissions \
                 JOIN sys.server_principals as grantor ON grantor.principal_id = grantor_principal_id \
                 JOIN sys.server_principals as grantee ON grantee.principal_id = grantee_principal_id \
                 WHERE permission_name = 'IMPERSONATE'",
            )
            .await
        {
            Ok(perms) => {
                let mut perm_list = Vec::new();
                for perm in &perms {
                    if let Some(obj) = perm.as_object() {
                        let grantor = obj.get("Grantor").and_then(|v| v.as_str()).unwrap_or("?");
                        let grantee = obj.get("Grantee").and_then(|v| v.as_str()).unwrap_or("?");
                        output_lines.push(format!("    - {grantee} can IMPERSONATE {grantor}"));
                        perm_list.push(perm.clone());
                    }
                }
                data.insert("impersonate_perms".to_string(), serde_json::Value::Array(perm_list));
            }
            Err(e) => output_lines.push(format!("    [!] Failed to check impersonate perms: {e}")),
        }

        Ok(ModuleResult {
            credentials: vec![],
            success: true,
            output: output_lines.join("\n"),
            data: serde_json::Value::Object(data),
        })
    }
}
