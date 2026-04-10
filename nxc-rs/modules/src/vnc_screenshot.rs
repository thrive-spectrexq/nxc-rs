use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::vnc::VncProtocol;
use nxc_protocols::NxcSession;

pub struct VncScreenshot;

impl VncScreenshot {
    pub fn new() -> Self {
        Self
    }
}

impl Default for VncScreenshot {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for VncScreenshot {
    fn name(&self) -> &'static str {
        "vnc_screenshot"
    }

    fn description(&self) -> &'static str {
        "Capture a screenshot from the VNC session"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["vnc"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![ModuleOption {
            name: "path".into(),
            description: "Folder to save screenshots".into(),
            required: false,
            default: Some("./screenshots".into()),
        }]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        _opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let protocol = VncProtocol::new();
        match protocol.capture_screenshot(session).await {
            Ok(path) => Ok(ModuleResult {
                credentials: vec![],
                success: true,
                output: format!("Screenshot saved to {path}"),
                data: serde_json::json!({ "path": path }),
            }),
            Err(e) => Ok(ModuleResult {
                credentials: vec![],
                success: false,
                output: format!("Failed to capture screenshot: {e}"),
                data: serde_json::json!({ "error": e.to_string() }),
            }),
        }
    }
}
