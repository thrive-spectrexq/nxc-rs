use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::postgresql::{PostgresProtocol, PostgresSession};
use nxc_protocols::NxcSession;

pub struct PostgresEnum;

impl PostgresEnum {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl NxcModule for PostgresEnum {
    fn name(&self) -> &'static str {
        "pg_enum"
    }

    fn description(&self) -> &'static str {
        "Enumerate PostgreSQL databases"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["postgres", "postgresql"]
    }

    async fn run(&self, session: &mut dyn NxcSession, _opts: &ModuleOptions) -> Result<ModuleResult> {
        let pg_sess = session
            .as_any()
            .downcast_ref::<PostgresSession>()
            .ok_or_else(|| anyhow::anyhow!("Invalid session type"))?;

        let protocol = PostgresProtocol::new();
        let dbs = protocol.list_databases(pg_sess).await?;

        Ok(ModuleResult {
            credentials: vec![], success: true,
            output: dbs.join(", "),
            data: serde_json::json!({ "databases": dbs }),
        })
    }
}
