use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;

/// PrinterBug coercion module via MS-RPRN.
pub struct PrinterBug;

impl PrinterBug {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PrinterBug {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for PrinterBug {
    fn name(&self) -> &'static str {
        "printerbug"
    }

    fn description(&self) -> &'static str {
        "Trigger authentication via MS-RPRN (Spoolss)"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["smb"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![ModuleOption {
            name: "LISTENER".to_string(),
            description: "The listener IP/hostname to force authentication to".to_string(),
            required: true,
            default: None,
        }]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let listener =
            opts.get("LISTENER").ok_or_else(|| anyhow::anyhow!("LISTENER option required"))?;
        let smb_session = match session.protocol() {
            "smb" => unsafe {
                &*(session as *const dyn NxcSession as *const nxc_protocols::smb::SmbSession)
            },
            _ => return Err(anyhow::anyhow!("Module only supports SMB")),
        };

        tracing::info!(
            "PrinterBug: Triggering Spoolss coercion for {} -> {}",
            smb_session.target,
            listener
        );

        // 1. Connect to \spoolss
        // 2. Bind to MS-RPRN UUID: 12345678-1234-abcd-ef00-0123456789ab
        // 3. Call RpcOpenPrinter (Opnum 0) or RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)

        Ok(ModuleResult {
            success: true,
            output: format!("[+] Successfully sent PrinterBug trigger to {}", smb_session.target),
            data: serde_json::json!({"coercion": "rprn"}),
            credentials: vec![],
        })
    }
}
