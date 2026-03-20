use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::redis::{RedisProtocol, RedisSession};
use nxc_protocols::NxcSession;

pub struct RedisInfo;

impl RedisInfo {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl NxcModule for RedisInfo {
    fn name(&self) -> &'static str {
        "redis_info"
    }

    fn description(&self) -> &'static str {
        "Enumerate Redis server information"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["redis"]
    }

    async fn run(&self, session: &mut dyn NxcSession, _opts: &ModuleOptions) -> Result<ModuleResult> {
        let redis_sess = session
            .as_any()
            .downcast_ref::<RedisSession>()
            .ok_or_else(|| anyhow::anyhow!("Invalid session type"))?;

        let protocol = RedisProtocol::new();
        let info = protocol.get_info(redis_sess).await?;

        Ok(ModuleResult {
            success: true,
            output: info.clone(),
            data: serde_json::json!({ "info": info }),
        })
    }
}
