//! # nxc-modules — NetExec-RS Module System
//!
//! Modules are Rust structs implementing `NxcModule`, compiled into the binary.
//! They are invoked per-protocol with `-M <module> [-o KEY=VALUE]` flags.

pub mod gmsa;
pub mod adcs;
pub mod bloodhound;
pub mod wmi_enum;
pub mod wmi_persist;
pub mod lsassy;
pub mod dcshadow;
pub mod sam;
pub mod lsa;
pub mod scripting;
pub mod psrp;
pub mod adb_screenshot;
pub mod adb_shell;
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
pub mod net_discovery;
pub mod http_paths;
pub mod redis_info;
pub mod pg_enum;
pub mod mysql_enum;
pub mod snmp_enum;
pub mod docker_enum;
pub mod smbexec;
pub mod get;
pub mod put;
pub mod ldap_ad;
pub mod mssql_clr;
pub mod ntds;
pub mod petitpotam;
pub mod printerbug;
pub mod zerologon;
pub mod nopac;
pub mod dpapi;
pub mod execute_assembly;
pub mod spider_plus;
pub mod coerce_plus;
pub mod web_crawler;
pub mod web_fuzzer;
pub mod web_vuln;
pub mod vhost_enum;
pub mod cms_enum;
pub mod graphql_enum;
pub mod waf_detect;
pub mod web_auth_brute;
pub mod cors_vuln;
pub mod web_dav;
pub mod method_fuzz;
pub mod lfi_fuzzer;
pub mod ssrf_fuzzer;
pub mod jwt_audit;
pub mod ldap_ma_quota;
pub mod smb_ghost;
pub mod mssql_privesc;
pub mod mssql_unc;
pub mod ftp_anon;
pub mod rdp_sec_check;
pub mod ssh_auth_methods;

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

        let net_discovery: Box<dyn NxcModule> = Box::new(net_discovery::NetDiscovery::new());
        modules.insert("net_discovery".into(), net_discovery);

        let gmsa: Box<dyn NxcModule> = Box::new(gmsa::Gmsa::new());
        modules.insert("gmsa".into(), gmsa);

        let adcs: Box<dyn NxcModule> = Box::new(adcs::AdcsModule::new());
        modules.insert("adcs".into(), adcs);

        let bloodhound: Box<dyn NxcModule> = Box::new(bloodhound::BloodhoundModule::new());
        modules.insert("bloodhound".into(), bloodhound);

        let wmi_enum: Box<dyn NxcModule> = Box::new(wmi_enum::WmiEnumModule::new());
        modules.insert("wmi_enum".into(), wmi_enum);

        let wmi_persist: Box<dyn NxcModule> = Box::new(wmi_persist::WmiPersistModule::new());
        modules.insert("wmi_persist".into(), wmi_persist);

        let lsassy: Box<dyn NxcModule> = Box::new(lsassy::LsassyModule::new());
        modules.insert("lsassy".into(), lsassy);

        let dcshadow: Box<dyn NxcModule> = Box::new(dcshadow::DcshadowModule::new());
        modules.insert("dcshadow".into(), dcshadow);

        let sam_mod: Box<dyn NxcModule> = Box::new(sam::SamModule::new());
        modules.insert("sam".into(), sam_mod);

        let lsa_mod: Box<dyn NxcModule> = Box::new(lsa::LsaModule::new());
        modules.insert("lsa".into(), lsa_mod);

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
                                    tracing::error!("Failed to load script module {}: {}", module_name, e);
                                }
                            }
                        }
                    }
                }
            }
        }

        let psrp: Box<dyn NxcModule> = Box::new(psrp::PsrpModule::new());
        modules.insert("psrp".into(), psrp);

        let adb_screenshot: Box<dyn NxcModule> = Box::new(adb_screenshot::AdbScreenshot::new());
        modules.insert("adb_screenshot".into(), adb_screenshot);

        let adb_shell: Box<dyn NxcModule> = Box::new(adb_shell::AdbShell::new());
        modules.insert("adb_shell".into(), adb_shell);

        let http_paths: Box<dyn NxcModule> = Box::new(http_paths::HttpPathsModule::new());
        modules.insert("http_paths".into(), http_paths);

        let redis_info: Box<dyn NxcModule> = Box::new(redis_info::RedisInfo::new());
        modules.insert("redis_info".into(), redis_info);

        let pg_enum: Box<dyn NxcModule> = Box::new(pg_enum::PostgresEnum::new());
        modules.insert("pg_enum".into(), pg_enum);

        let mysql_enum: Box<dyn NxcModule> = Box::new(mysql_enum::MysqlEnum::new());
        modules.insert("mysql_enum".into(), mysql_enum);

        let snmp_enum: Box<dyn NxcModule> = Box::new(snmp_enum::SnmpEnum::new());
        modules.insert("snmp_enum".into(), snmp_enum);

        let docker_enum: Box<dyn NxcModule> = Box::new(docker_enum::DockerEnum::new());
        modules.insert("docker_enum".into(), docker_enum);

        let smbexec: Box<dyn NxcModule> = Box::new(smbexec::SmbExec::new());
        modules.insert("smbexec".into(), smbexec);

        let get_mod: Box<dyn NxcModule> = Box::new(get::GetModule::new());
        modules.insert("get".into(), get_mod);

        let put_mod: Box<dyn NxcModule> = Box::new(put::PutModule::new());
        modules.insert("put".into(), put_mod);

        let ldap_ad: Box<dyn NxcModule> = Box::new(ldap_ad::LdapAdModule::new());
        modules.insert("ldap_ad".into(), ldap_ad);

        let mssql_clr: Box<dyn NxcModule> = Box::new(mssql_clr::MssqlClr::new());
        modules.insert("mssql_clr".into(), mssql_clr);

        let ntds: Box<dyn NxcModule> = Box::new(ntds::Ntds::new());
        modules.insert("ntds".into(), ntds);

        let petitpotam: Box<dyn NxcModule> = Box::new(petitpotam::Petitpotam::new());
        modules.insert("petitpotam".into(), petitpotam);

        let printerbug: Box<dyn NxcModule> = Box::new(printerbug::PrinterBug::new());
        modules.insert("printerbug".into(), printerbug);

        let zerologon: Box<dyn NxcModule> = Box::new(zerologon::Zerologon::new());
        modules.insert("zerologon".into(), zerologon);

        let nopac: Box<dyn NxcModule> = Box::new(nopac::Nopac::new());
        modules.insert("nopac".into(), nopac);

        let dpapi: Box<dyn NxcModule> = Box::new(dpapi::Dpapi::new());
        modules.insert("dpapi".into(), dpapi);

        let execute_assembly: Box<dyn NxcModule> = Box::new(execute_assembly::ExecuteAssembly::new());
        modules.insert("execute-assembly".into(), execute_assembly);

        let spider_plus: Box<dyn NxcModule> = Box::new(spider_plus::SpiderPlus::new());
        modules.insert("spider_plus".into(), spider_plus);

        let coerce_plus: Box<dyn NxcModule> = Box::new(coerce_plus::CoercePlus::new());
        modules.insert("coerce_plus".into(), coerce_plus);

        let web_crawler: Box<dyn NxcModule> = Box::new(web_crawler::WebCrawler::new());
        modules.insert("web_crawler".into(), web_crawler);

        let web_fuzzer: Box<dyn NxcModule> = Box::new(web_fuzzer::WebFuzzer::new());
        modules.insert("web_fuzzer".into(), web_fuzzer);

        let web_vuln: Box<dyn NxcModule> = Box::new(web_vuln::WebVuln::new());
        modules.insert("web_vuln".into(), web_vuln);

        let vhost_enum: Box<dyn NxcModule> = Box::new(vhost_enum::VhostEnum::new());
        modules.insert("vhost_enum".into(), vhost_enum);

        let cms_enum: Box<dyn NxcModule> = Box::new(cms_enum::CmsEnum::new());
        modules.insert("cms_enum".into(), cms_enum);

        let graphql_enum: Box<dyn NxcModule> = Box::new(graphql_enum::GraphqlEnum::new());
        modules.insert("graphql_enum".into(), graphql_enum);

        let waf_detect: Box<dyn NxcModule> = Box::new(waf_detect::WafDetect::new());
        modules.insert("waf_detect".into(), waf_detect);

        let web_auth_brute: Box<dyn NxcModule> = Box::new(web_auth_brute::WebAuthBrute::new());
        modules.insert("web_auth_brute".into(), web_auth_brute);

        let cors_vuln: Box<dyn NxcModule> = Box::new(cors_vuln::CorsVuln::new());
        modules.insert("cors_vuln".into(), cors_vuln);

        let web_dav: Box<dyn NxcModule> = Box::new(web_dav::WebDav::new());
        modules.insert("web_dav".into(), web_dav);

        let method_fuzz: Box<dyn NxcModule> = Box::new(method_fuzz::MethodFuzz::new());
        modules.insert("method_fuzz".into(), method_fuzz);

        let lfi_fuzzer: Box<dyn NxcModule> = Box::new(lfi_fuzzer::LfiFuzzer::new());
        modules.insert("lfi_fuzzer".into(), lfi_fuzzer);

        let ssrf_fuzzer: Box<dyn NxcModule> = Box::new(ssrf_fuzzer::SsrfFuzzer::new());
        modules.insert("ssrf_fuzzer".into(), ssrf_fuzzer);

        let jwt_audit: Box<dyn NxcModule> = Box::new(jwt_audit::JwtAudit::new());
        modules.insert("jwt_audit".into(), jwt_audit);

        let ldap_ma_quota: Box<dyn NxcModule> = Box::new(ldap_ma_quota::LdapMaQuota::new());
        modules.insert("ldap_ma_quota".into(), ldap_ma_quota);

        let smb_ghost: Box<dyn NxcModule> = Box::new(smb_ghost::SmbGhost::new());
        modules.insert("smb_ghost".into(), smb_ghost);

        let mssql_privesc: Box<dyn NxcModule> = Box::new(mssql_privesc::MssqlPrivesc::new());
        modules.insert("mssql_privesc".into(), mssql_privesc);

        let mssql_unc: Box<dyn NxcModule> = Box::new(mssql_unc::MssqlUnc::new());
        modules.insert("mssql_unc".into(), mssql_unc);

        let ftp_anon: Box<dyn NxcModule> = Box::new(ftp_anon::FtpAnon::new());
        modules.insert("ftp_anon".into(), ftp_anon);

        let rdp_sec_check: Box<dyn NxcModule> = Box::new(rdp_sec_check::RdpSecCheck::new());
        modules.insert("rdp_sec_check".into(), rdp_sec_check);

        let ssh_auth_methods: Box<dyn NxcModule> = Box::new(ssh_auth_methods::SshAuthMethods::new());
        modules.insert("ssh_auth_methods".into(), ssh_auth_methods);

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
