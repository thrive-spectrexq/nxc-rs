//! # nxc-targets — NetExec-RS Target Parsing & Execution Engine
//!
//! Handles target specification (CIDR, ranges, files, hostnames) and
//! drives the concurrent multi-target execution engine.

use anyhow::Result;
use chrono::Utc;
use nxc_auth::Credentials;
use nxc_db::{Credential, HostInfo, NxcDb};
use nxc_protocols::connection::ConnectionManager;
use nxc_protocols::NxcProtocol;
use nxc_resilience::RetryPolicy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

// ─── Target Types ───────────────────────────────────────────────

/// Address of a target — either a resolved IP or an unresolved hostname.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TargetAddr {
    /// A resolved IP address.
    Ip(IpAddr),
    /// An unresolved hostname (DNS resolution happens at connect time).
    Hostname(String),
}

impl TargetAddr {
    /// Returns the IP if resolved, or None for unresolved hostnames.
    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            TargetAddr::Ip(ip) => Some(*ip),
            TargetAddr::Hostname(_) => None,
        }
    }

    /// Returns a connection string suitable for TCP connect.
    pub fn to_connect_string(&self) -> String {
        match self {
            TargetAddr::Ip(ip) => ip.to_string(),
            TargetAddr::Hostname(h) => h.clone(),
        }
    }
}

impl std::fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetAddr::Ip(ip) => write!(f, "{ip}"),
            TargetAddr::Hostname(h) => write!(f, "{h}"),
        }
    }
}

/// A resolved target for protocol execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub addr: TargetAddr,
    pub hostname: Option<String>,
    pub port: Option<u16>,
}

impl Target {
    pub fn new(ip: IpAddr) -> Self {
        Self { addr: TargetAddr::Ip(ip), hostname: None, port: None }
    }

    pub fn from_hostname(hostname: &str) -> Self {
        Self {
            addr: TargetAddr::Hostname(hostname.to_string()),
            hostname: Some(hostname.to_string()),
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

    /// The IP as a string. For hostnames, returns the hostname itself.
    pub fn ip_string(&self) -> String {
        self.addr.to_connect_string()
    }

    /// Display string for output formatting.
    pub fn display(&self) -> String {
        match &self.addr {
            TargetAddr::Ip(ip) => {
                if let Some(ref hostname) = self.hostname {
                    format!("{ip} ({hostname})")
                } else {
                    ip.to_string()
                }
            }
            TargetAddr::Hostname(h) => h.clone(),
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
    Ok(vec![Target::from_hostname(spec)])
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
        anyhow::bail!("Invalid CIDR notation: {spec}");
    }
    let base_ip: std::net::Ipv4Addr = parts[0].parse()?;
    let prefix_len: u32 = parts[1].parse()?;
    if prefix_len > 32 {
        anyhow::bail!("Invalid CIDR prefix length: {prefix_len}");
    }

    let base = u32::from(base_ip);
    let mask = if prefix_len == 0 { 0 } else { !((1u32 << (32 - prefix_len)) - 1) };
    let network = base & mask;
    let broadcast = network | !mask;
    let mut targets = Vec::new();

    // Skip network and broadcast for /24 and larger
    let (start, end) =
        if prefix_len >= 31 { (network, broadcast) } else { (network + 1, broadcast - 1) };

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
    pub module_opts: HashMap<String, String>,
    pub verify_ssl: bool,
    /// Max failed login attempts globally before stopping.
    pub gfail_limit: Option<u32>,
    /// Max failed login attempts per username before skipping that user.
    pub ufail_limit: Option<u32>,
    /// Max failed login attempts per host before skipping that host.
    pub fail_limit: Option<u32>,
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
            module_opts: HashMap::new(),
            verify_ssl: false,
            gfail_limit: None,
            ufail_limit: None,
            fail_limit: None,
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
    pub module_data: HashMap<String, serde_json::Value>,
}

/// The concurrent execution engine.
///
/// Drives multi-target, multi-credential protocol execution
/// with bounded concurrency via Tokio semaphore.
pub struct ExecutionEngine {
    opts: ExecutionOpts,
    db: Option<Arc<NxcDb>>,
    manager: Arc<ConnectionManager>,
}

impl ExecutionEngine {
    pub fn new(opts: ExecutionOpts) -> Self {
        let manager =
            ConnectionManager::new().with_timeout_manager(nxc_resilience::TimeoutManager {
                connect: opts.timeout,
                ..Default::default()
            });

        Self { opts, db: None, manager: Arc::new(manager) }
    }

    pub fn with_db(mut self, db: Arc<NxcDb>) -> Self {
        self.db = Some(db);
        self
    }

    /// Set a custom retry policy for the engine.
    pub fn with_retry_policy(mut self, policy: RetryPolicy) -> Self {
        // Re-create the manager with the updated policy since ConnectionManager
        // doesn't implement Clone and is behind an Arc.
        let new_manager = ConnectionManager::new().with_retry_policy(policy);
        self.manager = Arc::new(new_manager);
        self
    }

    pub fn opts(&self) -> &ExecutionOpts {
        &self.opts
    }

    pub fn manager(&self) -> &Arc<ConnectionManager> {
        &self.manager
    }

    pub fn manager_mut(&mut self) -> &mut Arc<ConnectionManager> {
        &mut self.manager
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
            let mut rng = rand::rng();
            targets.shuffle(&mut rng);
        }

        // ── Fail-limit counters (thread-safe atomics) ──
        let global_fails = Arc::new(AtomicU32::new(0));
        let gfail_limit = self.opts.gfail_limit;
        let ufail_limit = self.opts.ufail_limit;
        let fail_limit = self.opts.fail_limit;

        // Per-user and per-host counters keyed by string
        let user_fails: Arc<dashmap::DashMap<String, AtomicU32>> =
            Arc::new(dashmap::DashMap::new());
        let host_fails: Arc<dashmap::DashMap<String, AtomicU32>> =
            Arc::new(dashmap::DashMap::new());

        let total_tasks = targets.len() * creds.len();
        let pb = if total_tasks > 1 {
            let pb = indicatif::ProgressBar::new(total_tasks as u64);
            pb.set_style(
                indicatif::ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
                    .unwrap()
                    .progress_chars("#>-"),
            );
            pb.set_message("spidering...");
            Some(pb)
        } else {
            None
        };

        let semaphore = Arc::new(Semaphore::new(self.opts.threads));
        let mut join_handles: Vec<JoinHandle<ExecutionResult>> = Vec::new();
        let db = self.db.clone();
        let manager = self.manager.clone();

        for target in targets {
            let target_str = target.ip_string();

            // Circuit breaker check: skip target if circuit is open
            if !manager.is_target_available(&target_str).await {
                if let Some(ref p) = pb {
                    p.inc(creds.len() as u64);
                }
                continue;
            }

            for cred in creds.iter() {
                // ── Pre-flight fail-limit checks ──
                // Global limit
                if let Some(limit) = gfail_limit {
                    if global_fails.load(Ordering::Relaxed) >= limit {
                        tracing::warn!("Global fail limit ({limit}) reached — stopping");
                        if let Some(ref p) = pb {
                            p.inc(1);
                        }
                        continue;
                    }
                }
                // Per-user limit
                if let Some(limit) = ufail_limit {
                    let count = user_fails
                        .entry(cred.username.clone())
                        .or_insert_with(|| AtomicU32::new(0));
                    if count.load(Ordering::Relaxed) >= limit {
                        tracing::debug!(
                            "User fail limit ({limit}) reached for {} — skipping",
                            cred.username
                        );
                        if let Some(ref p) = pb {
                            p.inc(1);
                        }
                        continue;
                    }
                }
                // Per-host limit
                if let Some(limit) = fail_limit {
                    let count = host_fails
                        .entry(target_str.clone())
                        .or_insert_with(|| AtomicU32::new(0));
                    if count.load(Ordering::Relaxed) >= limit {
                        tracing::debug!(
                            "Host fail limit ({limit}) reached for {target_str} — skipping"
                        );
                        if let Some(ref p) = pb {
                            p.inc(1);
                        }
                        continue;
                    }
                }

                let permit = semaphore.clone().acquire_owned().await.unwrap();
                let protocol_clone = protocol.clone();
                let target_clone = target.clone();
                let cred_clone = cred.clone();
                let opts_clone = self.opts.clone();
                let db_clone = db.clone();
                let pb_clone = pb.clone();
                let manager_clone = manager.clone();
                let global_fails_clone = global_fails.clone();
                let user_fails_clone = user_fails.clone();
                let host_fails_clone = host_fails.clone();

                let handle = tokio::spawn(async move {
                    let start_time = std::time::Instant::now();

                    // Apply jitter if specified (inside the task to not block submission)
                    if let Some(jitter) = opts_clone.jitter_ms {
                        if jitter > 0 {
                            tokio::time::sleep(Duration::from_millis(jitter)).await;
                        }
                    }

                    let result = tokio::time::timeout(opts_clone.timeout, async {
                        // Attempt connection with resilience
                        let target_str = target_clone.display();
                        let target_ip = target_clone.ip_string();
                        let port = protocol_clone.default_port();
                        let proxy = opts_clone.proxy.as_deref();

                        let mut session = match manager_clone
                            .call(&target_ip, || {
                                let p = protocol_clone.clone();
                                let t = target_str.clone();
                                let pr = proxy.map(|s| s.to_string());
                                async move { p.connect(&t, port, pr.as_deref()).await }
                            })
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
                                    message: format!("Connection failed: {e}"),
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

                                // Save to database if DB available (using spawn_blocking for synchronous SQLite)
                                let mut host_id = None;
                                if let Some(ref db_instance) = db_clone {
                                    let db_p = db_instance.clone();
                                    let t_p = target_clone.clone();
                                    let c_p = cred_clone.clone();
                                    let a_p = auth_res.clone();
                                    let proto_name = protocol_clone.name().to_string();

                                    let db_res = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<i64>> {
                                        let now = Utc::now().timestamp();
                                        let h_id = db_p.upsert_host(&HostInfo {
                                            id: None,
                                            workspace: db_p.current_workspace().to_string(),
                                            ip: t_p.ip_string(),
                                            hostname: t_p.hostname.clone(),
                                            domain: None,
                                            os: None,
                                            os_version: None,
                                            smb_signing: None,
                                            signing_required: None,
                                            is_dc: false,
                                            first_seen: now,
                                            last_seen: now,
                                        })?;

                                        if a_p.success {
                                            let _ = db_p.add_credential(&Credential {
                                                id: None,
                                                workspace: db_p.current_workspace().to_string(),
                                                domain: None,
                                                username: c_p.username.clone(),
                                                password: c_p.password.clone(),
                                                nt_hash: c_p.nt_hash.clone(),
                                                lm_hash: None,
                                                aes_128: None,
                                                aes_256: None,
                                                source: Some(proto_name),
                                                host_id: Some(h_id),
                                                created_at: now,
                                            })?;
                                        }
                                        Ok(Some(h_id))
                                    }).await;

                                    host_id = db_res.ok().and_then(|r| r.ok()).flatten();
                                }

                                // Execute modules if requested
                                let mut module_data = std::collections::HashMap::new();
                                if auth_res.success && !opts_clone.modules.is_empty() {
                                    let registry = nxc_modules::ModuleRegistry::new();
                                    for module_name in &opts_clone.modules {
                                        if let Some(module) = registry.get(module_name) {
                                            match module.run(session.as_mut(), &opts_clone.module_opts).await {
                                                Ok(mod_res) => {
                                                    if mod_res.success {
                                                        final_message.push_str(&format!(
                                                            " | Module {}: {}",
                                                            module_name, mod_res.output
                                                        ));
                                                        module_data.insert(
                                                            module_name.clone(),
                                                            mod_res.data,
                                                        );

                                                        // Save module-discovered credentials to DB
                                                        if let Some(ref db_instance) = db_clone {
                                                            let db_p = db_instance.clone();
                                                            let m_name = module_name.clone();
                                                            let p_name = protocol_clone.name().to_string();
                                                            let m_creds = mod_res.credentials.clone();
                                                            let h_id = host_id;

                                                            let _ = tokio::task::spawn_blocking(move || {
                                                                let now = Utc::now().timestamp();
                                                                for m_cred in m_creds {
                                                                    let _ = db_p.upsert_credential(
                                                                        &Credential {
                                                                            id: None,
                                                                            workspace: db_p
                                                                                .current_workspace()
                                                                                .to_string(),
                                                                            domain: m_cred.domain.clone(),
                                                                            username: m_cred.username.clone(),
                                                                            password: m_cred.password.clone(),
                                                                            nt_hash: m_cred.nt_hash.clone(),
                                                                            lm_hash: m_cred.lm_hash.clone(),
                                                                            aes_128: m_cred.aes_128_key.clone(),
                                                                            aes_256: m_cred.aes_256_key.clone(),
                                                                            source: Some(format!("{p_name}:{m_name}")),
                                                                            host_id: h_id,
                                                                            created_at: now,
                                                                        },
                                                                    );
                                                                }
                                                            }).await;
                                                        }
                                                    } else {
                                                        final_message.push_str(&format!(
                                                            " | Module {} Failed: {}",
                                                            module_name, mod_res.output
                                                        ));
                                                    }
                                                }
                                                Err(e) => {
                                                    final_message.push_str(&format!(
                                                        " | Module {module_name} Error: {e}"
                                                    ));
                                                }
                                            }
                                        } else {
                                            final_message.push_str(&format!(
                                                " | Module {module_name} not found"
                                            ));
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
                            Err(e) => {
                                // Increment fail counters on auth error
                                global_fails_clone.fetch_add(1, Ordering::Relaxed);
                                user_fails_clone
                                    .entry(cred_clone.username.clone())
                                    .or_insert_with(|| AtomicU32::new(0))
                                    .fetch_add(1, Ordering::Relaxed);
                                host_fails_clone
                                    .entry(target_str.clone())
                                    .or_insert_with(|| AtomicU32::new(0))
                                    .fetch_add(1, Ordering::Relaxed);

                                ExecutionResult {
                                    target: target_str,
                                    protocol: protocol_clone.name().to_string(),
                                    username: cred_clone.username.clone(),
                                    success: false,
                                    admin: false,
                                    message: format!("Auth error: {e}"),
                                    duration_ms: start_time.elapsed().as_millis() as u64,
                                    module_data: HashMap::new(),
                                }
                            },
                        }
                    })
                    .await;

                    // Drop permit to allow next task
                    drop(permit);
                    if let Some(ref p) = pb_clone {
                        p.inc(1);
                    }

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

        if let Some(p) = pb {
            p.finish_and_clear();
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
        assert_eq!(targets[0].ip_string(), "192.168.1.10");
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

            async fn connect(
                &self,
                target: &str,
                _port: u16,
                _proxy: Option<&str>,
            ) -> Result<Box<dyn NxcSession>> {
                if target == "192.168.1.99" {
                    return Err(anyhow::anyhow!("Connection timeout mock"));
                }
                Ok(Box::new(MockSession { target: target.to_string() }))
            }

            async fn authenticate(
                &self,
                _session: &mut dyn NxcSession,
                creds: &Credentials,
            ) -> Result<AuthResult> {
                if creds.password.as_deref() == Some("DUMMY_PASSWORD") {
                    Ok(AuthResult::success(creds.username == "admin"))
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
            verify_ssl: false,
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
            Credentials::password("admin", "DUMMY_PASSWORD", None),
            Credentials::password("user", "DUMMY_PASSWORD", None),
        ];

        // 4 targets * 3 creds = 12 total tasks
        let results = engine.run(smb_proto, targets, creds).await;

        assert_eq!(results.len(), 12);

        // Check the connection failure for .99 matches the mock behavior
        let failures = results.iter().filter(|r| r.target == "192.168.1.99").count();
        assert_eq!(failures, 3);

        // Assert admin auth logic passed correctly for others
        let admins = results.iter().filter(|r| r.success && r.admin).count();
        assert_eq!(admins, 3); // 1 admin win per successful host (10, 11, 12)
    }

    #[tokio::test]
    async fn test_execution_engine_db_persistence() -> Result<()> {
        use anyhow::Result;
        use async_trait::async_trait;
        use nxc_auth::{AuthResult, Credentials};
        use nxc_db::NxcDb;
        use nxc_protocols::{CommandOutput, NxcProtocol, NxcSession};
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
            fn name(&self) -> &'static str {
                "mock"
            }
            fn default_port(&self) -> u16 {
                0
            }
            fn supports_exec(&self) -> bool {
                false
            }
            fn supported_modules(&self) -> &[&str] {
                &[]
            }
            async fn connect(
                &self,
                target: &str,
                _port: u16,
                _proxy: Option<&str>,
            ) -> Result<Box<dyn NxcSession>> {
                struct MockSess {
                    t: String,
                }
                impl NxcSession for MockSess {
                    fn protocol(&self) -> &'static str {
                        "mock"
                    }
                    fn target(&self) -> &str {
                        &self.t
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
                Ok(Box::new(MockSess { t: target.to_string() }))
            }
            async fn authenticate(
                &self,
                _session: &mut dyn NxcSession,
                _creds: &Credentials,
            ) -> Result<AuthResult> {
                Ok(AuthResult::success(true))
            }
            async fn execute(
                &self,
                _session: &dyn NxcSession,
                _cmd: &str,
            ) -> Result<CommandOutput> {
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
