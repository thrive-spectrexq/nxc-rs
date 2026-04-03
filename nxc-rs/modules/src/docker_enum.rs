use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::docker::{DockerProtocol, DockerSession};
use nxc_protocols::NxcSession;

pub struct DockerEnum;

impl DockerEnum {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl NxcModule for DockerEnum {
    fn name(&self) -> &'static str {
        "docker_enum"
    }

    fn description(&self) -> &'static str {
        "Enumerate Docker containers or repositories"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["docker"]
    }

    async fn run(&self, session: &mut dyn NxcSession, _opts: &ModuleOptions) -> Result<ModuleResult> {
        let docker_sess = session
            .as_any()
            .downcast_ref::<DockerSession>()
            .ok_or_else(|| anyhow::anyhow!("Invalid session type"))?;

        let protocol = DockerProtocol::new();
        let info = protocol.enumerate(docker_sess).await?;

        Ok(ModuleResult {
            credentials: vec![], success: true,
            output: info.clone(),
            data: serde_json::json!({ "info": info }),
        })
    }
}
