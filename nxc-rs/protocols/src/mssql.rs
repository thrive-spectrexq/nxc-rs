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
    pub credentials: Option<Credentials>,
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
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
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
        true
    }

    fn supported_modules(&self) -> &[&str] {
        &["enum_logins", "enum_databases", "mssql_enum"]
    }

    async fn connect(&self, target: &str, port: u16) -> Result<Box<dyn NxcSession>> {
        let addr = format!("{}:{}", target, port);
        debug!("MSSQL: Connecting to {}", addr);

        let timeout_fut = tokio::time::timeout(self.timeout, TcpStream::connect(&addr));
        match timeout_fut.await {
            Ok(Ok(_stream)) => {
                info!("MSSQL: Connected to {}", addr);
                Ok(Box::new(MssqlSession {
                    target: target.to_string(),
                    port,
                    admin: false,
                    credentials: None,
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
        let mssql_sess_mut = match session.protocol() {
            "mssql" => unsafe { &mut *(session as *mut dyn NxcSession as *mut MssqlSession) },
            _ => return Err(anyhow!("Invalid session type")),
        };

        let username = creds.username.clone();
        let password = creds.password.clone().unwrap_or_default();
        let target = mssql_sess_mut.target.clone();
        let port = mssql_sess_mut.port;

        let addr = format!("{}:{}", target, port);
        debug!("MSSQL: Authenticating {}@{}", username, addr);

        let mut config = Config::new();
        config.host(&target);
        config.port(port);
        
        // Support NTLM auth if domain is provided or if simple auth fails
        if let Some(ref domain) = creds.domain {
            debug!("MSSQL: Using Windows auth for {}\\{}", domain, username);
            config.authentication(AuthMethod::windows(&format!("{}\\{}", domain, username), &password));
        } else {
            config.authentication(AuthMethod::sql_server(&username, &password));
        }
        
        config.trust_cert();

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
                mssql_sess_mut.credentials = Some(creds.clone());

                let mut is_admin = false;
                if let Ok(Ok(result)) = tokio::time::timeout(
                    self.timeout,
                    client.query("SELECT IS_SRVROLEMEMBER('sysadmin')", &[]),
                )
                .await
                {
                    if let Ok(rows) = result.into_first_result().await {
                        if let Some(row) = rows.first() {
                            if let Some(val) = row.get::<i32, _>(0) {
                                if val == 1 {
                                    is_admin = true;
                                    debug!("MSSQL: User {} is sysadmin!", username);
                                }
                            }
                        }
                    }
                }

                mssql_sess_mut.admin = is_admin;
                let _ = client.close().await;
                Ok(AuthResult::success(is_admin))
            }
            Ok(Err(e)) => {
                let msg = format!("Auth error: {}", e);
                debug!("MSSQL: Auth failed for {}: {}", username, msg);
                Ok(AuthResult::failure(&msg, None))
            }
            Err(_) => Ok(AuthResult::failure("MSSQL auth timeout", None)),
        }
    }

    async fn execute(&self, session: &dyn NxcSession, cmd: &str) -> Result<CommandOutput> {
        let mssql_sess = match session.protocol() {
            "mssql" => unsafe { &*(session as *const dyn NxcSession as *const MssqlSession) },
            _ => return Err(anyhow!("Invalid session type")),
        };

        let creds = mssql_sess
            .credentials
            .as_ref()
            .ok_or_else(|| anyhow!("Session not authenticated"))?;
        let mut config = Config::new();
        config.host(&mssql_sess.target);
        config.port(mssql_sess.port);
        
        let user = &creds.username;
        let pass = creds.password.as_deref().unwrap_or_default();
        
        if let Some(ref domain) = creds.domain {
             config.authentication(AuthMethod::windows(&format!("{}\\{}", domain, user), pass));
        } else {
             config.authentication(AuthMethod::sql_server(user, pass));
        }
        
        config.trust_cert();

        let tcp = TcpStream::connect(format!("{}:{}", mssql_sess.target, mssql_sess.port)).await?;
        let mut client = Client::connect(config, tcp.compat_write()).await?;

        // 1. Ensure xp_cmdshell is enabled
        let _ = client
            .execute(
                "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;",
                &[],
            )
            .await;
        let _ = client
            .execute("EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;", &[])
            .await;

        let sql = format!("EXEC xp_cmdshell '{}'", cmd.replace('\'', "''"));
        let result = client.query(sql, &[]).await?;
        let rows = result.into_first_result().await?;

        let mut stdout = String::new();
        for row in rows {
            if let Some(line) = row.get::<&str, _>(0) {
                stdout.push_str(line);
                stdout.push('\n');
            }
        }

        let _ = client.close().await;
        Ok(CommandOutput {
            stdout,
            stderr: String::new(),
            exit_code: Some(0),
        })
    }
}

impl MssqlProtocol {
    pub async fn query_json(
        &self,
        session: &MssqlSession,
        sql: &str,
    ) -> Result<Vec<serde_json::Value>> {
        let creds = session
            .credentials
            .as_ref()
            .ok_or_else(|| anyhow!("Session not authenticated"))?;
        let mut config = Config::new();
        config.host(&session.target);
        config.port(session.port);

        let user = &creds.username;
        let pass = creds.password.as_deref().unwrap_or_default();

        if let Some(ref domain) = creds.domain {
             config.authentication(AuthMethod::windows(&format!("{}\\{}", domain, user), pass));
        } else {
             config.authentication(AuthMethod::sql_server(user, pass));
        }

        config.trust_cert();

        let tcp = TcpStream::connect(format!("{}:{}", session.target, session.port)).await?;
        let mut client = Client::connect(config, tcp.compat_write()).await?;

        let result = client.query(sql, &[]).await?;
        let rows = result.into_first_result().await?;
        let mut results = Vec::new();

        for row in rows {
            let mut row_map = serde_json::Map::new();
            for (i, column) in row.columns().iter().enumerate() {
                let name = column.name();
                let val = if let Ok(Some(s)) = row.try_get::<&str, _>(i) {
                    serde_json::Value::String(s.to_string())
                } else if let Ok(Some(n)) = row.try_get::<i32, _>(i) {
                    serde_json::Value::Number(n.into())
                } else {
                    serde_json::Value::Null
                };
                row_map.insert(name.to_string(), val);
            }
            results.push(serde_json::Value::Object(row_map));
        }

        let _ = client.close().await;
        Ok(results)
    }
}
