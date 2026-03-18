//! # nxc-modules — NetExec-RS Module System
//!
//! Modules are Rust structs implementing `NxcModule`, compiled into the binary.
//! They are invoked per-protocol with `-M <module> [-o KEY=VALUE]` flags.

pub mod gmsa;
pub mod adcs;
pub mod bloodhound;
pub mod wmi_enum;
pub mod psrp;
pub mod adb_screenshot;
pub mod asreproasting;
pub mod enum_dns;
pub mod secretsdump;
pub mod enum_mssql;
pub mod enum_shares;
pub mod iot_cam;
pub mod kerberoasting;
pub mod laps;
pub mod ls;
pub mod shares;
pub mod vnc_screenshot;
pub mod whoami;
pub mod wifi_recon;

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
    async fn run(&self, session: &mut dyn NxcSession, opts: &ModuleOptions)
        -> Result<ModuleResult>;
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
        let enum_shares: Box<dyn NxcModule> = Box::new(enum_shares::EnumShares::new());
        modules.insert("enum_shares".into(), enum_shares);

        let whoami: Box<dyn NxcModule> = Box::new(whoami::Whoami::new());
        modules.insert("whoami".into(), whoami);

        let laps: Box<dyn NxcModule> = Box::new(laps::Laps::new());
        modules.insert("laps".into(), laps);

        let enum_dns: Box<dyn NxcModule> = Box::new(enum_dns::EnumDns::new());
        modules.insert("enum_dns".into(), enum_dns);

        let kerberoasting: Box<dyn NxcModule> = Box::new(kerberoasting::Kerberoasting::new());
        modules.insert("kerberoasting".into(), kerberoasting);

        let asreproasting: Box<dyn NxcModule> = Box::new(asreproasting::Asreproasting::new());
        modules.insert("asreproasting".into(), asreproasting);

        let secretsdump: Box<dyn NxcModule> = Box::new(secretsdump::SecretsDumpModule::new());
        modules.insert("secretsdump".into(), secretsdump);

        let mssql_enum: Box<dyn NxcModule> = Box::new(enum_mssql::MssqlEnum::new());
        modules.insert("mssql_enum".into(), mssql_enum);

        let ls_mod: Box<dyn NxcModule> = Box::new(ls::FtpLs::new());
        modules.insert("ls".into(), ls_mod);

        let shares_mod: Box<dyn NxcModule> = Box::new(shares::NfsShares::new());
        modules.insert("shares".into(), shares_mod);

        let vnc_screenshot: Box<dyn NxcModule> = Box::new(vnc_screenshot::VncScreenshot::new());
        modules.insert("screenshot".into(), vnc_screenshot);

        let iot_cam: Box<dyn NxcModule> = Box::new(iot_cam::IotCam::new());
        modules.insert("iot_cam".into(), iot_cam);

        let wifi_recon: Box<dyn NxcModule> = Box::new(wifi_recon::WifiRecon::new());
        modules.insert("wifi_recon".into(), wifi_recon);

        let gmsa: Box<dyn NxcModule> = Box::new(gmsa::Gmsa::new());
        modules.insert("gmsa".into(), gmsa);

        let adcs: Box<dyn NxcModule> = Box::new(adcs::AdcsModule::new());
        modules.insert("adcs".into(), adcs);

        let bloodhound: Box<dyn NxcModule> = Box::new(bloodhound::BloodhoundModule::new());
        modules.insert("bloodhound".into(), bloodhound);

        let wmi_enum: Box<dyn NxcModule> = Box::new(wmi_enum::WmiEnumModule::new());
        modules.insert("wmi_enum".into(), wmi_enum);

        let psrp: Box<dyn NxcModule> = Box::new(psrp::PsrpModule::new());
        modules.insert("psrp".into(), psrp);

        let adb_screenshot: Box<dyn NxcModule> = Box::new(adb_screenshot::AdbScreenshot::new());
        modules.insert("adb_screenshot".into(), adb_screenshot);

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
