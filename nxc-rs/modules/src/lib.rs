//! # nxc-modules — NetExec-RS Module System
//!
//! Modules are Rust structs implementing `NxcModule`, compiled into the binary.
//! They are invoked per-protocol with `-M <module> [-o KEY=VALUE]` flags.

// ─── Module declarations (sorted alphabetically) ────────────────
pub mod adb_screenshot;
pub mod adb_shell;
pub mod adcs;
pub mod add_computer;
pub mod advanced_recon;
pub mod asreproasting;
pub mod atexec;
pub mod backup_operator;
pub mod bloodhound;
pub mod clm_bypass;
pub mod cms_enum;
pub mod coerce_plus;
pub mod cors_vuln;
pub mod cred_harvesting;
pub mod daclread;
pub mod dcom_exec;
pub mod dcshadow;
pub mod dcsync;
pub mod delegation;
pub mod docker_enum;
pub mod dpapi;
pub mod enum_av;
pub mod enum_dns;
pub mod enum_impersonate;
pub mod enum_mssql;
pub mod enum_pipes;
pub mod enum_shares;
pub mod enum_trusts;
pub mod event_log_clear;
pub mod execute_assembly;
pub mod find_computer;
pub mod ftp_anon;
pub mod get;
pub mod get_desc_users;
pub mod get_info_users;
pub mod gmsa;
pub mod golden_ticket;
pub mod gpp_autologin;
pub mod gpp_password;
pub mod graphql_enum;
pub mod group_mem;
pub mod http_paths;
pub mod iot_cam;
pub mod jwt_audit;
pub mod kerberoasting;
pub mod laps;
pub mod ldap_ad;
pub mod ldap_enumeration;
pub mod ldap_ma_quota;
pub mod ldap_query;
pub mod lfi_fuzzer;
pub mod ls;
pub mod lsa;
pub mod lsassy;
pub mod method_fuzz;
pub mod ms17_010;
pub mod mssql_clr;
pub mod mssql_modules;
pub mod mssql_privesc;
pub mod mssql_unc;
pub mod mysql_enum;
pub mod named_pipe_pivot;
pub mod net_discovery;
pub mod nopac;
pub mod ntds;
pub mod ntds_dump_raw;
pub mod ntlmv1;
#[cfg(feature = "opcua-support")]
pub mod opcua_enum;
pub mod pass_the_ticket;
pub mod pe_loader {
    pub use super::advanced_recon::PeLoader;
}
pub mod persistence;
pub mod petitpotam;
pub mod pg_enum;
pub mod ppid_spoof;
pub mod printerbug;
pub mod printnightmare;
pub mod psexec;
pub mod pso;
pub mod psrp;
pub mod put;
pub mod rbcd;
pub mod rdp_exec;
pub mod rdp_sec_check;
pub mod redis_info;
pub mod reg_persist;
pub mod reg_query;
pub mod reg_winlogon;
pub mod runasppl;
pub mod sam;
pub mod sccm;
pub mod scripting;
pub mod secretsdump;
pub mod shadow_credentials;
pub mod shadowcoerce;
pub mod shares;
pub mod silver_ticket;
pub mod skeleton_key;
pub mod smb_ghost;
pub mod smbclient;
pub mod smbexec;
pub mod snmp_enum;
pub mod spider_plus;
pub mod spooler;
pub mod ssh_auth_methods;
pub mod ssrf_fuzzer;
pub mod subnets;
#[cfg(test)]
pub mod test_helpers;
pub mod token_impersonation;
pub mod uac;
pub mod vhost_enum;
pub mod vnc_screenshot;
pub mod waf_detect;
pub mod wdigest;
pub mod web_auth_brute;
pub mod web_crawler;
pub mod web_dav;
pub mod web_fuzzer;
pub mod web_vuln;
pub mod whoami;
pub mod wifi_recon;
pub mod wmi_enum;
pub mod wmi_persist;
pub mod wmiexec;
pub mod winrm_exec;
pub mod zerologon;

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── Module Option ──────────────────────────────────────────────

/// Describes a single configurable option for a module.
///
/// Modules expose these via [`NxcModule::options`] so that the CLI
/// can validate `-o KEY=VALUE` flags and render `--help` text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleOption {
    pub name: String,
    pub description: String,
    pub required: bool,
    pub default: Option<String>,
}

/// Parsed module options from `-o KEY=VALUE` flags.
pub type ModuleOptions = HashMap<String, String>;

/// Result returned by [`NxcModule::run`] after module execution.
///
/// Contains the success status, human-readable output, structured
/// JSON data, and any credentials harvested during the run.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModuleResult {
    pub success: bool,
    pub output: String,
    pub data: serde_json::Value,
    pub credentials: Vec<nxc_auth::Credentials>,
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

// ─── Helper Macro ───────────────────────────────────────────────

/// Registers a module into the `HashMap`, boxing it as `dyn NxcModule`.
///
/// Usage: `register_module!(map, "name", module_path::Struct::new());`
macro_rules! register_module {
    ($map:ident, $name:expr, $ctor:expr) => {
        $map.insert($name.into(), Box::new($ctor) as Box<dyn NxcModule>);
    };
}

// ─── Module Registry ────────────────────────────────────────────

/// Central registry of all compiled-in [`NxcModule`] implementations.
///
/// Constructed once at startup via [`ModuleRegistry::new`], which
/// registers every built-in module and dynamically loads any `.rhai`
/// script modules found in `./modules/`.
///
/// Use [`get`](Self::get) to look up a module by name, or
/// [`list`](Self::list) to enumerate modules (optionally filtered
/// by protocol).
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

        // ─── Core / multi-protocol modules ──────────────────────────
        register_module!(modules, "enum_shares", enum_shares::EnumShares::new());
        register_module!(modules, "whoami", whoami::Whoami::new());
        register_module!(modules, "laps", laps::Laps::new());
        register_module!(modules, "enum_dns", enum_dns::EnumDns::new());
        register_module!(modules, "kerberoasting", kerberoasting::Kerberoasting::new());
        register_module!(modules, "asreproasting", asreproasting::Asreproasting::new());
        register_module!(modules, "secretsdump", secretsdump::SecretsDumpModule::new());
        register_module!(modules, "mssql_enum", enum_mssql::MssqlEnum::new());
        register_module!(modules, "ls", ls::FtpLs::new());
        register_module!(modules, "shares", shares::NfsShares::new());
        register_module!(modules, "screenshot", vnc_screenshot::VncScreenshot::new());
        register_module!(modules, "iot_cam", iot_cam::IotCam::new());
        register_module!(modules, "net_discovery", net_discovery::NetDiscovery::new());
        register_module!(modules, "gmsa", gmsa::Gmsa::new());
        register_module!(modules, "adcs", adcs::AdcsModule::new());
        register_module!(modules, "bloodhound", bloodhound::BloodhoundModule::new());
        register_module!(modules, "wmi_enum", wmi_enum::WmiEnumModule::new());
        register_module!(modules, "wmi_persist", wmi_persist::WmiPersistModule::new());
        register_module!(modules, "lsassy", lsassy::LsassyModule::new());
        register_module!(modules, "dcshadow", dcshadow::DcshadowModule::new());
        register_module!(modules, "sam", sam::SamModule::new());
        register_module!(modules, "lsa", lsa::LsaModule::new());

        // ─── Dynamic Script Modules ─────────────────────────────────
        let engine = rhai::Engine::new();
        let script_dir = std::path::Path::new("./modules");
        if script_dir.exists() && script_dir.is_dir() {
            if let Ok(entries) = std::fs::read_dir(script_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) == Some("rhai") {
                        if let Some(file_stem) = path.file_stem().and_then(|s| s.to_str()) {
                            let module_name = file_stem.to_string();
                            match scripting::ScriptModule::new(module_name.clone(), path, &engine) {
                                Ok(script_mod) => {
                                    tracing::info!("Loaded script module: {}", module_name);
                                    let boxed_mod: Box<dyn NxcModule> = Box::new(script_mod);
                                    modules.insert(module_name, boxed_mod);
                                }
                                Err(e) => {
                                    tracing::error!(
                                        "Failed to load script module {}: {}",
                                        module_name,
                                        e
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        // ─── Protocol-specific modules ──────────────────────────────
        register_module!(modules, "psrp", psrp::PsrpModule::new());
        register_module!(modules, "adb_screenshot", adb_screenshot::AdbScreenshot::new());
        register_module!(modules, "adb_shell", adb_shell::AdbShell::new());
        register_module!(modules, "http_paths", http_paths::HttpPathsModule::new());
        register_module!(modules, "redis_info", redis_info::RedisInfo::new());
        register_module!(modules, "pg_enum", pg_enum::PostgresEnum::new());
        register_module!(modules, "mysql_enum", mysql_enum::MysqlEnum::new());

        #[cfg(feature = "opcua-support")]
        register_module!(modules, "opcua_enum", opcua_enum::OpcUaEnum::new());

        register_module!(modules, "snmp_enum", snmp_enum::SnmpEnum::new());
        // NOTE: duplicate `dcshadow` registration removed (was a bug)
        register_module!(modules, "dcom_exec", dcom_exec::DcomExec::new());
        register_module!(modules, "docker_enum", docker_enum::DockerEnum::new());
        register_module!(modules, "smbexec", smbexec::SmbExec::new());
        register_module!(modules, "get", get::GetModule::new());
        register_module!(modules, "put", put::PutModule::new());
        register_module!(modules, "ldap_ad", ldap_ad::LdapAdModule::new());
        register_module!(modules, "mssql_clr", mssql_clr::MssqlClr::new());
        register_module!(modules, "ntds", ntds::Ntds::new());
        register_module!(modules, "petitpotam", petitpotam::Petitpotam::new());
        register_module!(modules, "printerbug", printerbug::PrinterBug::new());
        register_module!(modules, "zerologon", zerologon::Zerologon::new());
        register_module!(modules, "nopac", nopac::Nopac::new());
        register_module!(modules, "dpapi", dpapi::Dpapi::new());
        register_module!(modules, "execute-assembly", execute_assembly::ExecuteAssembly::new());
        register_module!(modules, "spider_plus", spider_plus::SpiderPlus::new());
        register_module!(modules, "coerce_plus", coerce_plus::CoercePlus::new());

        // ─── Web modules ────────────────────────────────────────────
        register_module!(modules, "web_crawler", web_crawler::WebCrawler::new());
        register_module!(modules, "web_fuzzer", web_fuzzer::WebFuzzer::new());
        register_module!(modules, "web_vuln", web_vuln::WebVuln::new());
        register_module!(modules, "vhost_enum", vhost_enum::VhostEnum::new());
        register_module!(modules, "cms_enum", cms_enum::CmsEnum::new());
        register_module!(modules, "graphql_enum", graphql_enum::GraphqlEnum::new());
        register_module!(modules, "waf_detect", waf_detect::WafDetect::new());
        register_module!(modules, "web_auth_brute", web_auth_brute::WebAuthBrute::new());
        register_module!(modules, "cors_vuln", cors_vuln::CorsVuln::new());
        register_module!(modules, "web_dav", web_dav::WebDav::new());
        register_module!(modules, "method_fuzz", method_fuzz::MethodFuzz::new());
        register_module!(modules, "lfi_fuzzer", lfi_fuzzer::LfiFuzzer::new());
        register_module!(modules, "ssrf_fuzzer", ssrf_fuzzer::SsrfFuzzer::new());
        register_module!(modules, "jwt_audit", jwt_audit::JwtAudit::new());

        // ─── Additional SMB/LDAP/network modules ────────────────────
        register_module!(modules, "ldap_ma_quota", ldap_ma_quota::LdapMaQuota::new());
        register_module!(modules, "smb_ghost", smb_ghost::SmbGhost::new());
        register_module!(modules, "mssql_privesc", mssql_privesc::MssqlPrivesc::new());
        register_module!(modules, "mssql_unc", mssql_unc::MssqlUnc::new());
        register_module!(modules, "ftp_anon", ftp_anon::FtpAnon::new());
        register_module!(modules, "rdp_sec_check", rdp_sec_check::RdpSecCheck::new());
        register_module!(modules, "ssh_auth_methods", ssh_auth_methods::SshAuthMethods::new());

        // ─── Phase 1: SMB/AD Core (19 modules) ─────────────────────
        register_module!(modules, "enum_av", enum_av::EnumAv::new());
        register_module!(modules, "gpp_password", gpp_password::GppPassword::new());
        register_module!(modules, "gpp_autologin", gpp_autologin::GppAutologin::new());
        register_module!(modules, "ms17_010", ms17_010::Ms17010::new());
        register_module!(modules, "enum_impersonate", enum_impersonate::EnumImpersonate::new());
        register_module!(modules, "runasppl", runasppl::RunAsPpl::new());
        register_module!(modules, "wdigest", wdigest::Wdigest::new());
        register_module!(modules, "uac", uac::Uac::new());
        register_module!(modules, "reg_query", reg_query::RegQuery::new());
        register_module!(modules, "reg_winlogon", reg_winlogon::RegWinlogon::new());
        register_module!(modules, "spooler", spooler::Spooler::new());
        register_module!(modules, "printnightmare", printnightmare::PrintNightmare::new());
        register_module!(modules, "ntlmv1", ntlmv1::Ntlmv1::new());
        register_module!(modules, "enum_trusts", enum_trusts::EnumTrusts::new());
        register_module!(modules, "ntds_dump_raw", ntds_dump_raw::NtdsDumpRaw::new());
        register_module!(modules, "backup_operator", backup_operator::BackupOperator::new());
        register_module!(modules, "sccm", sccm::Sccm::new());
        register_module!(modules, "add_computer", add_computer::AddComputer::new());
        register_module!(modules, "shadowcoerce", shadowcoerce::ShadowCoerce::new());
        register_module!(modules, "shadow_credentials", shadow_credentials::ShadowCredentials::new());

        // ─── Phase 2: LDAP/AD Enumeration (14 modules) ─────────────
        register_module!(modules, "daclread", daclread::DaclRead::new());
        register_module!(modules, "delegation", delegation::Delegation::new());
        register_module!(modules, "rbcd", rbcd::Rbcd::new());
        register_module!(modules, "get_desc_users", get_desc_users::GetDescUsers::new());
        register_module!(modules, "get_info_users", get_info_users::GetInfoUsers::new());
        register_module!(modules, "group_mem", group_mem::GroupMem::new());
        register_module!(modules, "subnets", subnets::Subnets::new());
        register_module!(modules, "pso", pso::Pso::new());
        register_module!(modules, "find_computer", find_computer::FindComputer::new());
        register_module!(modules, "get_network", ldap_enumeration::GetNetwork::new());
        register_module!(modules, "get_unixpassword", ldap_enumeration::GetUnixPassword::new());
        register_module!(modules, "ldap_checker", ldap_enumeration::LdapChecker::new());
        register_module!(modules, "obsolete", ldap_enumeration::Obsolete::new());
        register_module!(modules, "pre2k", ldap_enumeration::Pre2k::new());
        register_module!(modules, "pass_the_ticket", pass_the_ticket::PassTheTicket::new());

        // ─── Phase 3: MSSQL Modules (6 modules) ────────────────────
        register_module!(modules, "mssql_coerce", mssql_modules::MssqlCoerce::new());
        register_module!(modules, "mssql_dumper", mssql_modules::MssqlDumper::new());
        register_module!(modules, "mssql_cbt", mssql_modules::MssqlCbt::new());
        register_module!(modules, "enable_cmdshell", mssql_modules::EnableCmdShell::new());
        register_module!(modules, "enum_links", mssql_modules::EnumLinks::new());
        register_module!(modules, "enum_logins", mssql_modules::EnumLogins::new());

        // ─── Phase 4: Credential Harvesting (10 modules) ───────────
        register_module!(modules, "firefox", cred_harvesting::FirefoxCreds::new());
        register_module!(modules, "winscp", cred_harvesting::WinscpCreds::new());
        register_module!(modules, "keepass_discover", cred_harvesting::KeepassDiscover::new());
        register_module!(modules, "keepass_trigger", cred_harvesting::KeepassTrigger::new());
        register_module!(modules, "mremoteng", cred_harvesting::MremotengCreds::new());
        register_module!(modules, "rdcman", cred_harvesting::RdcmanCreds::new());
        register_module!(modules, "putty", cred_harvesting::PuttySessions::new());
        register_module!(modules, "mobaxterm", cred_harvesting::MobaxtermCreds::new());
        register_module!(modules, "aws_credentials", cred_harvesting::AwsCredentials::new());
        register_module!(modules, "veeam", cred_harvesting::VeeamCreds::new());

        // ─── Phase 5: Persistence & Lateral Movement (9 modules) ───
        register_module!(modules, "schtask_as", persistence::SchtaskAs::new());
        register_module!(modules, "slinky", persistence::Slinky::new());
        register_module!(modules, "scuffy", persistence::Scuffy::new());
        register_module!(modules, "drop_sc", persistence::DropSc::new());
        register_module!(modules, "drop_library_ms", persistence::DropLibraryMs::new());
        register_module!(modules, "met_inject", persistence::MetInject::new());
        register_module!(modules, "empire_exec", persistence::EmpireExec::new());
        register_module!(modules, "web_delivery", persistence::WebDelivery::new());
        register_module!(modules, "lockscreendoors", persistence::LockScreenDoors::new());

        // ─── Phase 6: RS-Exclusive Advanced (6 modules) ────────────
        register_module!(modules, "amsi_bypass", advanced_recon::AmsiBypass::new());
        register_module!(modules, "bof_loader", advanced_recon::BofLoader::new());
        register_module!(modules, "pe_loader", advanced_recon::PeLoader::new());
        register_module!(modules, "etw_patcher", advanced_recon::EtwPatcher::new());
        register_module!(modules, "defender_enum", advanced_recon::DefenderEnum::new());
        register_module!(modules, "dpapi_masterkey", advanced_recon::DpapiMasterkey::new());

        // ─── Wireless Reconnaissance ────────────────────────────────
        register_module!(modules, "wifi_recon", wifi_recon::WifiRecon::new());

        // ─── Phase 2D: Lateral Movement, Persistence, Evasion (15 modules) ───
        register_module!(modules, "psexec", psexec::PsExecModule::new());
        register_module!(modules, "wmiexec", wmiexec::WmiExecModule::new());
        register_module!(modules, "atexec", atexec::AtExecModule::new());
        register_module!(modules, "smbclient", smbclient::SmbClientModule::new());
        register_module!(modules, "rdp_exec", rdp_exec::RdpExecModule::new());
        register_module!(modules, "golden_ticket", golden_ticket::GoldenTicketModule::new());
        register_module!(modules, "silver_ticket", silver_ticket::SilverTicketModule::new());
        register_module!(modules, "skeleton_key", skeleton_key::SkeletonKeyModule::new());
        register_module!(modules, "dcsync", dcsync::DcSyncModule::new());
        register_module!(modules, "reg_persist", reg_persist::RegPersistModule::new());
        register_module!(modules, "clm_bypass", clm_bypass::ClmBypassModule::new());
        register_module!(modules, "ppid_spoof", ppid_spoof::PpidSpoofModule::new());
        register_module!(modules, "token_impersonation", token_impersonation::TokenImpersonationModule::new());
        register_module!(modules, "named_pipe_pivot", named_pipe_pivot::NamedPipePivotModule::new());
        register_module!(modules, "event_log_clear", event_log_clear::EventLogClearModule::new());

        Self { modules }
    }

    /// Register a module.
    pub fn register(&mut self, module: Box<dyn NxcModule>) {
        self.modules.insert(module.name().to_string(), module);
    }

    /// Get a module by name.
    pub fn get(&self, name: &str) -> Option<&dyn NxcModule> {
        self.modules.get(name).map(std::convert::AsRef::as_ref)
    }

    /// List all modules, optionally filtered by protocol.
    pub fn list(&self, protocol: Option<&str>) -> Vec<&dyn NxcModule> {
        self.modules
            .values()
            .filter(|m| protocol.map(|p| m.supported_protocols().contains(&p)).unwrap_or(true))
            .map(std::convert::AsRef::as_ref)
            .collect()
    }

    /// Returns the total number of registered modules (built-in + script).
    pub fn count(&self) -> usize {
        self.modules.len()
    }

    /// Returns all unique protocol names across every registered module.
    pub fn protocols(&self) -> Vec<&str> {
        let mut protos: Vec<&str> = self
            .modules
            .values()
            .flat_map(|m| m.supported_protocols().iter().copied())
            .collect();
        protos.sort_unstable();
        protos.dedup();
        protos
    }
}
