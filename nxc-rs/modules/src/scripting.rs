//! # scripting — Rhai Scripting Module Support
//!
//! Enables dynamic module execution using Rhai scripts.
//! Scripts can be loaded from the filesystem and executed against sessions.

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;
use rhai::{Dynamic, Engine, Map, AST};
use std::path::PathBuf;

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};

/// A module implemented as a Rhai script.
pub struct ScriptModule {
    name: String,
    description: String,
    path: PathBuf,
    ast: AST,
}

impl ScriptModule {
    pub fn new(name: String, path: PathBuf, engine: &Engine) -> Result<Self> {
        let ast = engine.compile_file(path.clone())?;

        // Try to get description from script-level documentation or a specific function
        // For now, simpler: use filename
        let description = format!("Script module loaded from {}", path.display());

        Ok(Self {
            name,
            description,
            path,
            ast,
        })
    }
}

#[async_trait]
impl NxcModule for ScriptModule {
    fn name(&self) -> &'static str {
        // We need 'static str, which is tricky for dynamic modules.
        // For now, we'll leak the name to get a 'static reference.
        // In a long-running app this is a leak, but for a CLI it's fine.
        Box::leak(self.name.clone().into_boxed_str())
    }

    fn description(&self) -> &'static str {
        Box::leak(self.description.clone().into_boxed_str())
    }

    fn supported_protocols(&self) -> &[&str] {
        // Scripts can manually check protocol, but we'll default to allowing all
        &["smb", "wmi", "winrm", "mssql", "ldap", "ftp", "ssh", "adb"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        // In a more advanced version, we could query a 'get_options' function in Rhai.
        // For the MVP, scripts can access any options passed via CLI.
        vec![]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let engine = Engine::new();
        let mut scope = rhai::Scope::new();

        // 1. Setup Context (as a Map)
        let mut context = Map::new();
        context.insert("protocol".into(), session.protocol().into());
        context.insert("target".into(), session.target().into());
        context.insert("is_admin".into(), session.is_admin().into());

        // 2. Prepare Options
        let mut options = Map::new();
        for (k, v) in opts {
            options.insert(k.clone().into(), v.clone().into());
        }

        // 3. Execute the 'run' function in the script
        // Note: Using engine.call_fn with explicit arguments
        let result: Dynamic = engine.call_fn(&mut scope, &self.ast, "run", (context, options))?;

        Ok(ModuleResult {
            credentials: vec![],
            success: true,
            output: result.to_string(),
            data: serde_json::json!({
                "script_path": self.path.to_string_lossy(),
                "result": result.to_string()
            }),
        })
    }
}
