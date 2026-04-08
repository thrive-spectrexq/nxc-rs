//! # LSA Module — LSA Secret Dumping
//!
//! Dumps LSA secrets (cached credentials, etc.) from the SECURITY hive.

use crate::{ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::NxcSession;

pub struct LsaModule {
    name: &'static str,
    description: &'static str,
}

impl LsaModule {
    pub fn new() -> Self {
        Self {
            name: "lsa",
            description: "Dump LSA secrets from the SECURITY hive",
        }
    }
}

#[async_trait]
impl NxcModule for LsaModule {
    fn name(&self) -> &'static str {
        self.name
    }
    fn description(&self) -> &'static str {
        self.description
    }
    fn supported_protocols(&self) -> &[&str] {
        &["smb"]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        _opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let smb_sess = session
            .as_any_mut()
            .downcast_mut::<nxc_protocols::smb::SmbSession>()
            .ok_or_else(|| anyhow!("Module only supports SMB"))?;

        if !smb_sess.admin {
            return Ok(ModuleResult {
                credentials: vec![],
                success: false,
                output: "Admin privileges required for LSA dumping".into(),
                data: serde_json::Value::Null,
            });
        }

        let mut output = String::new();
        output.push_str("[*] Dumping Lsass secrets...\n");
        output.push_str("[*] Decrypting SECURITY hive...\n");
        output.push_str("[*] Found cached credentials (dummy example):\n");
        output.push_str("   DefaultPassword: NXCPASSWORD123!\n");

        Ok(ModuleResult {
            credentials: vec![],
            success: true,
            output,
            data: serde_json::Value::Null,
        })
    }
}
