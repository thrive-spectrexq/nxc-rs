//! # nxc-targets — NetExec-RS Target Parsing & Execution Engine
//!
//! Handles target specification (CIDR, ranges, files, hostnames) and
//! drives the concurrent multi-target execution engine.

use anyhow::Result;
use nxc_auth::Credentials;
use nxc_protocols::NxcProtocol;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

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
    pub continue_on_success: bool,
    pub no_bruteforce: bool,
}

impl Default for ExecutionOpts {
    fn default() -> Self {
        Self {
            threads: 256,
            timeout: Duration::from_secs(30),
            jitter_ms: None,
            continue_on_success: false,
            no_bruteforce: false,
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
}

/// The concurrent execution engine.
///
/// Drives multi-target, multi-credential protocol execution
/// with bounded concurrency via Tokio semaphore.
pub struct ExecutionEngine {
    opts: ExecutionOpts,
}

impl ExecutionEngine {
    pub fn new(opts: ExecutionOpts) -> Self {
        Self { opts }
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
        let semaphore = Arc::new(Semaphore::new(self.opts.threads));
        let mut join_handles: Vec<JoinHandle<ExecutionResult>> = Vec::new();

        for target in targets {
            for cred in creds.iter() {
                let permit = semaphore.clone().acquire_owned().await.unwrap();
                let protocol_clone = protocol.clone();
                let target_clone = target.clone();
                let cred_clone = cred.clone();
                let timeout_duration = self.opts.timeout;

                let handle = tokio::spawn(async move {
                    let start_time = std::time::Instant::now();

                    let result = tokio::time::timeout(timeout_duration, async {
                        // Attempt connection
                        let target_str = target_clone.display();
                        let mut session = match protocol_clone
                            .connect(&target_str, protocol_clone.default_port())
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
                                }
                            }
                        };

                        // Attempt auth
                        match protocol_clone
                            .authenticate(session.as_mut(), &cred_clone)
                            .await
                        {
                            Ok(auth_res) => {
                                // Execute modules if requested
                                // (Implementation pending for multi-module execution, 
                                // currently just handling the core auth flow in the engine)
                                ExecutionResult {
                                    target: target_str.clone(),
                                    protocol: protocol_clone.name().to_string(),
                                    username: cred_clone.username.clone(),
                                    success: auth_res.success,
                                    admin: auth_res.admin,
                                    message: auth_res.message,
                                    duration_ms: start_time.elapsed().as_millis() as u64,
                                }
                            },
                            Err(e) => ExecutionResult {
                                target: target_str,
                                protocol: protocol_clone.name().to_string(),
                                username: cred_clone.username.clone(),
                                success: false,
                                admin: false,
                                message: format!("Auth error: {}", e),
                                duration_ms: start_time.elapsed().as_millis() as u64,
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

            async fn connect(&self, target: &str, _port: u16) -> Result<Box<dyn NxcSession>> {
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
            continue_on_success: false,
            no_bruteforce: false,
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
}
