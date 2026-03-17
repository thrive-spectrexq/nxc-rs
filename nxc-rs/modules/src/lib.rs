//! # nxc-modules — NetExec-RS Module System
//!
//! Modules are Rust structs implementing `NxcModule`, compiled into the binary.
//! They are invoked per-protocol with `-M <module> [-o KEY=VALUE]` flags.

pub mod enum_shares;
pub mod whoami;
pub mod laps;
pub mod enum_dns;

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── Module Option ──────────────────────────────────────────────

/// Describes a configurable option for a module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleOption {
    pub name: String,
    pub description: String,
    pub required: bool,
    pub default: Option<String>,
}

/// Parsed module options from `-o KEY=VALUE` flags.
pub type ModuleOptions = HashMap<String, String>;

/// Result of a module execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleResult {
    pub success: bool,
    pub output: String,
    pub data: serde_json::Value,
}

// ─── NxcModule Trait ────────────────────────────────────────────

/// Trait for nxc modules (secretsdump, bloodhound, kerberoast, etc.).
#[async_trait]
pub trait NxcModule: Send + Sync {
    /// Module name (e.g. "secretsdump", "bloodhound").
    fn name(&self) -> &'static str;

    /// Human-readable description.
    fn description(&self) -> &'static str;

    /// Which protocols this module works with (e.g. ["smb", "ldap"]).
    fn supported_protocols(&self) -> &[&str];

    /// Configurable options for `-o` parsing.
    fn options(&self) -> Vec<ModuleOption> {
        vec![]
    }

    /// Execute the module against an authenticated session.
    async fn run(&self, session: &dyn NxcSession, opts: &ModuleOptions) -> Result<ModuleResult>;
}

// ─── Module Registry ────────────────────────────────────────────

/// Registry of all compiled-in modules.
pub struct ModuleRegistry {
    modules: HashMap<String, Box<dyn NxcModule>>,
}

impl Default for ModuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleRegistry {
    pub fn new() -> Self {
        let mut modules: HashMap<String, Box<dyn NxcModule>> = HashMap::new();

        // Register built-in modules
        modules.insert("enum_shares".into(), Box::new(enum_shares::EnumShares::new()));
        modules.insert("whoami".into(), Box::new(whoami::Whoami::new()));
        modules.insert("laps".into(), Box::new(laps::Laps::new()));
        modules.insert("enum_dns".into(), Box::new(enum_dns::EnumDns::new()));

        Self { modules }
    }

    /// Register a module.
    pub fn register(&mut self, module: Box<dyn NxcModule>) {
        self.modules.insert(module.name().to_string(), module);
    }

    /// Get a module by name.
    pub fn get(&self, name: &str) -> Option<&dyn NxcModule> {
        self.modules.get(name).map(|m| m.as_ref())
    }

    /// List all modules, optionally filtered by protocol.
    pub fn list(&self, protocol: Option<&str>) -> Vec<&dyn NxcModule> {
        self.modules
            .values()
            .filter(|m| {
                protocol
                    .map(|p| m.supported_protocols().contains(&p))
                    .unwrap_or(true)
            })
            .map(|m| m.as_ref())
            .collect()
    }
}
