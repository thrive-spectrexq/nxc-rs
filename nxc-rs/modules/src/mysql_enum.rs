use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::mysql::{MysqlProtocol, MysqlSession};
use nxc_protocols::NxcSession;

pub struct MysqlEnum;

impl MysqlEnum {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl NxcModule for MysqlEnum {
    fn name(&self) -> &'static str {
        "mysql_enum"
    }

    fn description(&self) -> &'static str {
        "Enumerate MySQL databases"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["mysql"]
    }

    async fn run(&self, session: &mut dyn NxcSession, _opts: &ModuleOptions) -> Result<ModuleResult> {
        let mysql_sess = session
            .as_any()
            .downcast_ref::<MysqlSession>()
            .ok_or_else(|| anyhow::anyhow!("Invalid session type"))?;

        let protocol = MysqlProtocol::new();
        let dbs = protocol.list_databases(mysql_sess).await?;

        Ok(ModuleResult {
            success: true,
            output: dbs.join(", "),
            data: serde_json::json!({ "databases": dbs }),
        })
    }
}
