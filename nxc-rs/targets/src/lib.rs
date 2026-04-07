//! # nxc-targets — NetExec-RS Target Parsing & Execution Engine
//!
//! Handles target specification (CIDR, ranges, files, hostnames) and
//! drives the concurrent multi-target execution engine.

use anyhow::Result;
use nxc_auth::Credentials;
use nxc_protocols::NxcProtocol;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use nxc_db::{NxcDb, HostInfo, Credential};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use chrono::Utc;

// ─── Target Types ───────────────────────────────────────────────

/// A resolved target for protocol execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub port: Option<u16>,
}

impl Target {
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            hostname: None,
            port: None,
        }
    }

    pub fn with_hostname(mut self, hostname: &str) -> Self {
        self.hostname = Some(hostname.to_string());
        self
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Display string for output formatting.
    pub fn display(&self) -> String {
        if let Some(ref hostname) = self.hostname {
            format!("{} ({})", self.ip, hostname)
        } else {
            self.ip.to_string()
        }
    }
}

// ─── Target Parsing ─────────────────────────────────────────────

/// Parse a target specification string into a list of targets.
///
/// Supports: single IP, CIDR notation, dash ranges, hostnames, file paths.
pub fn parse_targets(spec: &str) -> Result<Vec<Target>> {
    let spec = spec.trim();

    // Check if it's a file path
    if std::path::Path::new(spec).exists() && !spec.contains('/') || spec.ends_with(".txt") {
        return parse_target_file(spec);
    }

    // Check for CIDR notation
    if spec.contains('/') {
        return parse_cidr(spec);
    }

    // Check for dash range (e.g. 192.168.1.1-254)
    if spec.contains('-') && !spec.contains(':') {
        return parse_range(spec);
    }

    // Try as a single IP
    if let Ok(ip) = spec.parse::<IpAddr>() {
        return Ok(vec![Target::new(ip)]);
    }

    // Treat as hostname — DNS resolution will happen at connect time
    Ok(vec![Target {
        ip: "0.0.0.0".parse().unwrap(),
        hostname: Some(spec.to_string()),
        port: None,
    }])
}

/// Parse targets from a file (one per line).
fn parse_target_file(path: &str) -> Result<Vec<Target>> {
    let contents = std::fs::read_to_string(path)?;
    let mut targets = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        targets.extend(parse_targets(line)?);
    }
    Ok(targets)
}

/// Parse CIDR notation (e.g. 192.168.1.0/24).
fn parse_cidr(spec: &str) -> Result<Vec<Target>> {
    let parts: Vec<&str> = spec.split('/').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid CIDR notation: {}", spec);
    }
    let base_ip: std::net::Ipv4Addr = parts[0].parse()?;
    let prefix_len: u32 = parts[1].parse()?;
    if prefix_len > 32 {
        anyhow::bail!("Invalid CIDR prefix length: {}", prefix_len);
    }

    let base = u32::from(base_ip);
    let mask = if prefix_len == 0 {
        0
    } else {
        !((1u32 << (32 - prefix_len)) - 1)
    };
    let network = base & mask;
    let broadcast = network | !mask;
    let mut targets = Vec::new();

    // Skip network and broadcast for /24 and larger
    let (start, end) = if prefix_len >= 31 {
        (network, broadcast)
    } else {
        (network + 1, broadcast - 1)
    };

    for ip_int in start..=end {
        let ip = std::net::Ipv4Addr::from(ip_int);
        targets.push(Target::new(IpAddr::V4(ip)));
    }
    Ok(targets)
}

/// Parse dash range (e.g. 192.168.1.1-254).
fn parse_range(spec: &str) -> Result<Vec<Target>> {
    let dash_pos = spec.rfind('-').unwrap();
    let base = &spec[..dash_pos];
    let end_octet: u8 = spec[dash_pos + 1..].parse()?;

    let base_ip: std::net::Ipv4Addr = base.parse()?;
    let base_int = u32::from(base_ip);
    let start_octet = (base_int & 0xFF) as u8;

    let mut targets = Vec::new();
    for octet in start_octet..=end_octet {
        let ip_int = (base_int & 0xFFFFFF00) | octet as u32;
        let ip = std::net::Ipv4Addr::from(ip_int);
        targets.push(Target::new(IpAddr::V4(ip)));
    }
    Ok(targets)
}

// ─── Execution Engine ───────────────────────────────────────────

/// Configuration for the execution engine.
#[derive(Debug, Clone)]
pub struct ExecutionOpts {
    pub threads: usize,
    pub timeout: Duration,
    pub jitter_ms: Option<u64>,
    pub shuffle: bool,
    pub proxy: Option<String>,
    pub continue_on_success: bool,
    pub no_bruteforce: bool,
    pub modules: Vec<String>,
    pub module_opts: std::collections::HashMap<String, String>,
}

impl Default for ExecutionOpts {
    fn default() -> Self {
        Self {
            threads: 256,
            timeout: Duration::from_secs(30),
            jitter_ms: None,
            shuffle: false,
            proxy: None,
            continue_on_success: false,
            no_bruteforce: false,
            modules: Vec::new(),
            module_opts: std::collections::HashMap::new(),
        }
    }
}

/// Result from a single target execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub target: String,
    pub protocol: String,
    pub username: String,
    pub success: bool,
    pub admin: bool,
    pub message: String,
    pub duration_ms: u64,
    pub module_data: std::collections::HashMap<String, serde_json::Value>,
}

/// The concurrent execution engine.
///
/// Drives multi-target, multi-credential protocol execution
/// with bounded concurrency via Tokio semaphore.
pub struct ExecutionEngine {
    opts: ExecutionOpts,
    db: Option<Arc<NxcDb>>,
}

impl ExecutionEngine {
    pub fn new(opts: ExecutionOpts) -> Self {
        Self { opts, db: None }
    }

    pub fn with_db(mut self, db: Arc<NxcDb>) -> Self {
        self.db = Some(db);
        self
    }

    pub fn opts(&self) -> &ExecutionOpts {
        &self.opts
    }

    /// Execute the given protocol against the targets using the provided credentials.
    pub async fn run(
        &self,
        protocol: Arc<dyn NxcProtocol>,
        targets: Vec<Target>,
        creds: Vec<Credentials>,
    ) -> Vec<ExecutionResult> {
        let mut targets = targets;
        if self.opts.shuffle {
            use rand::seq::SliceRandom;
            let mut rng = rand::thread_rng();
            targets.shuffle(&mut rng);
        }

        let semaphore = Arc::new(Semaphore::new(self.opts.threads));
        let mut join_handles: Vec<JoinHandle<ExecutionResult>> = Vec::new();
        let db = self.db.clone();

        for target in targets {
            for cred in creds.iter() {
                // Apply jitter if specified
                if let Some(jitter) = self.opts.jitter_ms {
                    if jitter > 0 {
                        tokio::time::sleep(Duration::from_millis(jitter)).await;
                    }
                }

                let permit = semaphore.clone().acquire_owned().await.unwrap();
                let protocol_clone = protocol.clone();
                let target_clone = target.clone();
                let cred_clone = cred.clone();
                let timeout_duration = self.opts.timeout;
                let modules = self.opts.modules.clone();
                let module_opts = self.opts.module_opts.clone();
                let proxy_clone = self.opts.proxy.clone();

                let db_clone = db.clone();

                let handle = tokio::spawn(async move {
                    let start_time = std::time::Instant::now();

                    let result = tokio::time::timeout(timeout_duration, async {
                        // Attempt connection
                        let target_str = target_clone.display();
                        let mut session = match protocol_clone
                            .connect(&target_str, protocol_clone.default_port(), proxy_clone.as_deref())
                            .await
                        {
                            Ok(s) => s,
                            Err(e) => {
                                return ExecutionResult {
                                    target: target_str,
                                    protocol: protocol_clone.name().to_string(),
                                    username: cred_clone.username.clone(),
                                    success: false,
                                    admin: false,
                                    message: format!("Connection failed: {}", e),
                                    duration_ms: start_time.elapsed().as_millis() as u64,
                                    module_data: std::collections::HashMap::new(),
                                }
                            }
                        };

                        // Attempt auth
                        match protocol_clone
                            .authenticate(session.as_mut(), &cred_clone)
                            .await
                        {
                            Ok(auth_res) => {
                                let mut final_message = auth_res.message.clone();
                                
                                // Save to database if successful and DB available
                                let mut host_id = None;
                                if let Some(ref db_instance) = db_clone {
                                    let now = Utc::now().timestamp();
                                    host_id = db_instance.upsert_host(&HostInfo {
                                        id: None,
                                        workspace: db_instance.current_workspace().to_string(),
                                        ip: target_clone.ip.to_string(),
                                        hostname: target_clone.hostname.clone(),
                                        domain: None, // Could be extracted from protocol sessions if they provide it
                                        os: None,
                                        os_version: None,
                                        smb_signing: None,
                                        signing_required: None,
                                        is_dc: false,
                                        first_seen: now,
                                        last_seen: now,
                                    }).ok();

                                    if auth_res.success {
                                        let _ = db_instance.add_credential(&Credential {
                                            id: None,
                                            workspace: db_instance.current_workspace().to_string(),
                                            domain: None,
                                            username: cred_clone.username.clone(),
                                            password: cred_clone.password.clone(),
                                            nt_hash: cred_clone.nt_hash.clone(),
                                            lm_hash: None,
                                            aes_128: None,
                                            aes_256: None,
                                            source: Some(protocol_clone.name().to_string()),
                                            host_id,
                                            created_at: now,
                                        });
                                    }
                                }

                                // Execute modules if requested
                                let mut module_data = std::collections::HashMap::new();
                                if auth_res.success && !modules.is_empty() {
                                    let registry = nxc_modules::ModuleRegistry::new();
                                    for module_name in &modules {
                                        if let Some(module) = registry.get(module_name) {
                                            match module.run(session.as_mut(), &module_opts).await {
                                                Ok(mod_res) => {
                                                    if mod_res.success {
                                                        final_message.push_str(&format!(" | Module {}: {}", module_name, mod_res.output));
                                                        module_data.insert(module_name.clone(), mod_res.data);
                                                        
                                                        // Save module-discovered credentials to DB
                                                        if let Some(ref db_instance) = db_clone {
                                                            let now = Utc::now().timestamp();
                                                            for m_cred in mod_res.credentials {
                                                                let _ = db_instance.upsert_credential(&Credential {
                                                                    id: None,
                                                                    workspace: db_instance.current_workspace().to_string(),
                                                                    domain: m_cred.domain.clone(),
                                                                    username: m_cred.username.clone(),
                                                                    password: m_cred.password.clone(),
                                                                    nt_hash: m_cred.nt_hash.clone(),
                                                                    lm_hash: m_cred.lm_hash.clone(),
                                                                    aes_128: m_cred.aes_128_key.clone(),
                                                                    aes_256: m_cred.aes_256_key.clone(),
                                                                    source: Some(format!("{}:{}", protocol_clone.name(), module_name)),
                                                                    host_id,
                                                                    created_at: now,
                                                                });
                                                            }
                                                        }
                                                    } else {
                                                        final_message.push_str(&format!(" | Module {} Failed: {}", module_name, mod_res.output));
                                                    }
                                                }
                                                Err(e) => {
                                                    final_message.push_str(&format!(" | Module {} Error: {}", module_name, e));
                                                }
                                            }
                                        } else {
                                            final_message.push_str(&format!(" | Module {} not found", module_name));
                                        }
                                    }
                                }

                                ExecutionResult {
                                    target: target_str.clone(),
                                    protocol: protocol_clone.name().to_string(),
                                    username: cred_clone.username.clone(),
                                    success: auth_res.success,
                                    admin: auth_res.admin,
                                    message: final_message,
                                    duration_ms: start_time.elapsed().as_millis() as u64,
                                    module_data,
                                }
                            }
                            Err(e) => ExecutionResult {
                                target: target_str,
                                protocol: protocol_clone.name().to_string(),
                                username: cred_clone.username.clone(),
                                success: false,
                                admin: false,
                                message: format!("Auth error: {}", e),
                                duration_ms: start_time.elapsed().as_millis() as u64,
                                module_data: std::collections::HashMap::new(),
                            },
                        }
                    })
                    .await;

                    // Drop permit to allow next task
                    drop(permit);

                    match result {
                        Ok(exec_res) => exec_res,
                        Err(_) => ExecutionResult {
                            target: target_clone.display(),
                            protocol: protocol_clone.name().to_string(),
                            username: cred_clone.username.clone(),
                            success: false,
                            admin: false,
                            message: "Timeout".to_string(),
                            duration_ms: start_time.elapsed().as_millis() as u64,
                            module_data: std::collections::HashMap::new(),
                        },
                    }
                });

                join_handles.push(handle);
            }
        }

        let mut results = Vec::new();
        for handle in join_handles {
            if let Ok(res) = handle.await {
                results.push(res);
            }
        }

        results
    }
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_ip() {
        let targets = parse_targets("192.168.1.10").unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].ip.to_string(), "192.168.1.10");
    }

    #[test]
    fn test_parse_cidr_24() {
        let targets = parse_targets("192.168.1.0/24").unwrap();
        assert_eq!(targets.len(), 254); // .1 through .254
    }

    #[test]
    fn test_parse_range() {
        let targets = parse_targets("192.168.1.1-10").unwrap();
        assert_eq!(targets.len(), 10);
    }

    #[test]
    fn test_target_display() {
        let t = Target::new("10.0.0.1".parse().unwrap()).with_hostname("dc01.corp.local");
        assert_eq!(t.display(), "10.0.0.1 (dc01.corp.local)");
    }

    #[tokio::test]
    async fn test_execution_engine_concurrency() {
        use anyhow::Result;
        use async_trait::async_trait;
        use nxc_auth::{AuthResult, Credentials};
        use nxc_protocols::{CommandOutput, NxcProtocol, NxcSession};
        use std::sync::Arc;

        // A mock protocol that simulates network success/failure based on target IP
        struct MockSession {
            target: String,
        }
        impl NxcSession for MockSession {
            fn protocol(&self) -> &'static str {
                "mock"
            }
            fn target(&self) -> &str {
                &self.target
            }
            fn is_admin(&self) -> bool {
                true
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
            fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
                self
            }
        }

        struct MockProtocol;
        #[async_trait]
        impl NxcProtocol for MockProtocol {
            fn name(&self) -> &'static str {
                "mock"
            }
            fn default_port(&self) -> u16 {
                1234
            }
            fn supports_exec(&self) -> bool {
                false
            }
            fn supported_modules(&self) -> &[&str] {
                &[]
            }

            async fn connect(&self, target: &str, _port: u16, _proxy: Option<&str>) -> Result<Box<dyn NxcSession>> {
                if target == "192.168.1.99" {
                    return Err(anyhow::anyhow!("Connection timeout mock"));
                }
                Ok(Box::new(MockSession {
                    target: target.to_string(),
                }))
            }

            async fn authenticate(
                &self,
                _session: &mut dyn NxcSession,
                creds: &Credentials,
            ) -> Result<AuthResult> {
                if creds.password.as_deref() == Some("Password123!") {
                    Ok(AuthResult::success(true))
                } else {
                    Ok(AuthResult::failure("Bad password", None))
                }
            }

            async fn execute(
                &self,
                _session: &dyn NxcSession,
                _cmd: &str,
            ) -> Result<CommandOutput> {
                Err(anyhow::anyhow!("Not supported"))
            }
        }

        let opts = ExecutionOpts {
            threads: 5,
            timeout: std::time::Duration::from_secs(5),
            jitter_ms: None,
            shuffle: false,
            proxy: None,
            continue_on_success: false,
            no_bruteforce: false,
            modules: Vec::new(),
            module_opts: std::collections::HashMap::new(),
        };

        let engine = ExecutionEngine::new(opts);
        let smb_proto: Arc<dyn nxc_protocols::NxcProtocol> = Arc::new(MockProtocol);

        let targets = vec![
            Target::new("192.168.1.10".parse().unwrap()),
            Target::new("192.168.1.11".parse().unwrap()),
            Target::new("192.168.1.12".parse().unwrap()),
            Target::new("192.168.1.99".parse().unwrap()), // Mocks connection failure
        ];

        let creds = vec![
            Credentials::password("admin", "wrong", None),
            Credentials::password("admin", "Password123!", None),
            Credentials::password("user", "pass", None),
        ];

        // 4 targets * 3 creds = 12 total tasks
        let results = engine.run(smb_proto, targets, creds).await;

        assert_eq!(results.len(), 12);

        // Check the connection failure for .99 matches the mock behavior
        let failures = results
            .iter()
            .filter(|r| r.target == "192.168.1.99")
            .count();
        assert_eq!(failures, 3);

        // Assert admin auth logic passed correctly for others
        let admins = results.iter().filter(|r| r.success && r.admin).count();
        assert_eq!(admins, 3); // 1 admin win per successful host (10, 11, 12)
    }

    #[tokio::test]
    async fn test_execution_engine_db_persistence() -> Result<()> {
        use anyhow::Result;
        use async_trait::async_trait;
        use nxc_db::NxcDb;
        use nxc_protocols::{NxcProtocol, NxcSession, CommandOutput};
        use nxc_auth::{AuthResult, Credentials};
        use std::sync::Arc;
        use tempfile::tempdir;

        let dir = tempdir()?;
        let db_path = dir.path().join("test.db");
        let db = Arc::new(NxcDb::new(&db_path, "test_ws")?);

        let opts = ExecutionOpts::default();
        let engine = ExecutionEngine::new(opts).with_db(db.clone());

        // Simple mock protocol for test
        struct MockProto;
        #[async_trait]
        impl NxcProtocol for MockProto {
            fn name(&self) -> &'static str { "mock" }
            fn default_port(&self) -> u16 { 0 }
            fn supports_exec(&self) -> bool { false }
            fn supported_modules(&self) -> &[&str] { &[] }
            async fn connect(&self, target: &str, _port: u16, _proxy: Option<&str>) -> Result<Box<dyn NxcSession>> {
                struct MockSess { t: String }
                impl NxcSession for MockSess {
                    fn protocol(&self) -> &'static str { "mock" }
                    fn target(&self) -> &str { &self.t }
                    fn is_admin(&self) -> bool { true }
                    fn as_any(&self) -> &dyn std::any::Any { self }
                    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }
                }
                Ok(Box::new(MockSess { t: target.to_string() }))
            }
            async fn authenticate(
                &self,
                _session: &mut dyn NxcSession,
                _creds: &Credentials,
            ) -> Result<AuthResult> {
                Ok(AuthResult::success(true))
            }
            async fn execute(&self, _session: &dyn NxcSession, _cmd: &str) -> Result<CommandOutput> {
                Err(anyhow::anyhow!("mock"))
            }
        }

        let targets = vec![Target::new("127.0.0.1".parse().unwrap())];
        let creds = vec![Credentials::password("admin", "pass", None)];

        engine.run(Arc::new(MockProto), targets, creds).await;

        let hosts = db.list_hosts_in("test_ws")?;
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].ip, "127.0.0.1");

        let saved_creds = db.list_credentials_in("test_ws")?;
        assert_eq!(saved_creds.len(), 1);
        assert_eq!(saved_creds[0].username, "admin");

        Ok(())
    }
}
