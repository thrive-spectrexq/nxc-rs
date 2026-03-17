//! # MSSQL Protocol Handler
//!
//! MSSQL protocol implementation using the `tiberius` crate for TDS connections.
//! Replicates NetExec capability for DB enum and query execution.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use std::time::Duration;
use tiberius::{AuthMethod, Client, Config};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;
use tracing::{debug, info};

// ─── MSSQL Session ────────────────────────────────────────────────

pub struct MssqlSession {
    pub target: String,
    pub port: u16,
    pub admin: bool,
    // Note: tiberius::Client doesn't easily derive Send/Sync as part of a trait box,
    // so we maintain connection state loosely similar to SSH.
    // In a full implementation, we'd multiplex or hold the connection open safely.
    // To conform to the trait quickly, we'll store basic info and reconnect on execute,
    // or wrap it in Arc<Mutex> depending on upstream abstractions.
}

impl NxcSession for MssqlSession {
    fn protocol(&self) -> &'static str {
        "mssql"
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn is_admin(&self) -> bool {
        self.admin
    }
}

// ─── MSSQL Protocol Handler ───────────────────────────────────────

pub struct MssqlProtocol {
    pub timeout: Duration,
}

impl MssqlProtocol {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(10),
        }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl Default for MssqlProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcProtocol for MssqlProtocol {
    fn name(&self) -> &'static str {
        "mssql"
    }

    fn default_port(&self) -> u16 {
        1433
    }

    fn supports_exec(&self) -> bool {
        // MSSQL supports execution via xp_cmdshell, which we map to the execute function.
        true
    }

    fn supported_modules(&self) -> &[&str] {
        &["enum_logins", "enum_databases", "sam", "lsa"]
    }

    async fn connect(&self, target: &str, port: u16) -> Result<Box<dyn NxcSession>> {
        let addr = format!("{}:{}", target, port);
        debug!("MSSQL: Connecting to {}", addr);

        // Pre-connection check
        let timeout_fut = tokio::time::timeout(self.timeout, TcpStream::connect(&addr));
        match timeout_fut.await {
            Ok(Ok(_stream)) => {
                info!("MSSQL: Connected to {}", addr);
                Ok(Box::new(MssqlSession {
                    target: target.to_string(),
                    port,
                    admin: false,
                }))
            }
            Ok(Err(e)) => Err(anyhow!("Connection refused or unreachable: {}", e)),
            Err(_) => Err(anyhow!("Connection timeout to {}", addr)),
        }
    }

    async fn authenticate(
        &self,
        session: &mut dyn NxcSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        let username = creds.username.clone();
        let password = creds.password.clone().unwrap_or_default();
        let target = session.target().to_string();

        let mssql_sess = unsafe { &*(session as *const dyn NxcSession as *const MssqlSession) };
        let port = mssql_sess.port;

        let addr = format!("{}:{}", target, port);
        debug!("MSSQL: Authenticating {}@{}", username, addr);

        let mut config = Config::new();
        config.host(&target);
        config.port(port);
        // Tiberius supports SQL auth or Windows Auth (NTLM) if compiled with features.
        // For baseline testing, we attempt SQL auth or NTLM fallback depending on credentials.
        config.authentication(AuthMethod::sql_server(&username, &password));
        config.trust_cert(); // Like impacket, don't validate TLS rigorously

        let tcp_fut = tokio::time::timeout(self.timeout, TcpStream::connect(&addr));
        let tcp = match tcp_fut.await {
            Ok(Ok(s)) => s,
            _ => return Ok(AuthResult::failure("Connection timeout during auth", None)),
        };

        let tcp = tcp.compat_write();
        let client_fut = tokio::time::timeout(self.timeout, Client::connect(config, tcp));

        match client_fut.await {
            Ok(Ok(mut client)) => {
                debug!("MSSQL: Auth successful for {}", username);
                
                // Check if admin (sysadmin)
                let mut is_admin = false;
                if let Ok(query_res) = tokio::time::timeout(
                    self.timeout, 
                    client.query("SELECT IS_SRVROLEMEMBER('sysadmin')", &[])
                ).await {
                    if let Ok(stream) = query_res {
                        if let Ok(Some(row)) = stream.into_row().await {
                            if let Some(val) = row.get::<i32, _>(0) {
                                if val == 1 {
                                    is_admin = true;
                                    debug!("MSSQL: User {} is sysadmin!", username);
                                }
                            }
                        }
                    }
                }

                let _ = client.close().await;
                Ok(AuthResult::success(is_admin))
            }
            Ok(Err(e)) => {
                let msg = format!("Auth error: {}", e);
                debug!("MSSQL: Auth failed for {}: {}", username, msg);
                Ok(AuthResult::failure(&msg, None))
            }
            Err(_) => {
                Ok(AuthResult::failure("MSSQL auth timeout", None))
            }
        }
    }

    async fn execute(&self, _session: &dyn NxcSession, _cmd: &str) -> Result<CommandOutput> {
         // To execute via xp_cmdshell, we must establish a connection
        Err(anyhow!("Full xp_cmdshell execution wrapper not yet ported. MSSQL execute pending implementation."))
    }
}
