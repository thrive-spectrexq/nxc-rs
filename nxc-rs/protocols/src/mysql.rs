//! # MySQL Protocol Handler
//!
//! MySQL protocol implementation for NetExec-RS.
//! Supports user brute-forcing, database enumeration, and admin checks.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use mysql_async::{prelude::Queryable, OptsBuilder, Pool, Row};
use nxc_auth::{AuthResult, Credentials};
use std::time::Duration;
use tracing::{debug, info};

// ─── MySQL Session ──────────────────────────────────────────────

pub struct MysqlSession {
    pub target: String,
    pub port: u16,
    pub admin: bool,
    pub credentials: Option<Credentials>,
}

impl NxcSession for MysqlSession {
    fn protocol(&self) -> &'static str {
        "mysql"
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

// ─── MySQL Protocol Handler ───────────────────────────────────────

pub struct MysqlProtocol {
    pub timeout: Duration,
}

impl MysqlProtocol {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(5),
        }
    }
}

impl Default for MysqlProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcProtocol for MysqlProtocol {
    fn name(&self) -> &'static str {
        "mysql"
    }

    fn default_port(&self) -> u16 {
        3306
    }

    fn supports_exec(&self) -> bool {
        true // Possible via UDF or FILE privilege, focusing on SQL for now
    }

    fn supported_modules(&self) -> &[&str] {
        &["mysql_enum", "mysql_databases"]
    }

    async fn connect(&self, target: &str, port: u16, _proxy: Option<&str>) -> Result<Box<dyn NxcSession>> {
        let addr = format!("{}:{}", target, port);
        debug!("MySQL: Connecting to {}", addr);

        // Initial TCP check
        let connect_fut = tokio::net::TcpStream::connect(&addr);
        match tokio::time::timeout(self.timeout, connect_fut).await {
            Ok(Ok(_)) => {
                info!("MySQL: Connected to {}", addr);
                Ok(Box::new(MysqlSession {
                    target: target.to_string(),
                    port,
                    admin: false,
                    credentials: None,
                }))
            }
            Ok(Err(e)) => Err(anyhow!("Connection failed: {}", e)),
            Err(_) => Err(anyhow!("Connection timeout to {}", addr)),
        }
    }

    async fn authenticate(
        &self,
        session: &mut dyn NxcSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        let mysql_sess = match session.protocol() {
            "mysql" => unsafe { &mut *(session as *mut dyn NxcSession as *mut MysqlSession) },
            _ => return Err(anyhow!("Invalid session type")),
        };

        let username = &creds.username;
        let password = creds.password.as_deref().unwrap_or_default();
        let target = &mysql_sess.target;
        let port = mysql_sess.port;

        let opts = OptsBuilder::default()
            .ip_or_hostname(target)
            .tcp_port(port)
            .user(Some(username))
            .pass(Some(password))
            .db_name(Some("mysql"));

        let pool = Pool::new(opts);
        debug!("MySQL: Authenticating {}@{}", username, target);

        match tokio::time::timeout(self.timeout, pool.get_conn()).await {
            Ok(Ok(mut conn)) => {
                debug!("MySQL: Auth successful for {}", username);
                mysql_sess.credentials = Some(creds.clone());

                // Check for admin/superuser access
                let mut is_admin = false;
                // In MySQL, check for ALL PRIVILEGES or SUPER privilege
                if let Ok(rows) = conn.query::<Row, _>("SELECT CURRENT_USER()").await {
                    if let Some(row) = rows.first() {
                        let current_user: String = row.get(0).unwrap_or_default();
                        debug!("MySQL: Authenticated as {}", current_user);
                    }
                }
                
                // Check if we can list all users as a proxy for admin
                if conn.query::<Row, _>("SELECT user FROM mysql.user LIMIT 1").await.is_ok() {
                    is_admin = true;
                    debug!("MySQL: User {} has administrative access (can read mysql.user)!", username);
                }

                mysql_sess.admin = is_admin;
                let _ = conn.disconnect().await;
                Ok(AuthResult::success(is_admin))
            }
            Ok(Err(e)) => {
                debug!("MySQL: Auth failed for {}: {}", username, e);
                Ok(AuthResult::failure(&e.to_string(), None))
            }
            Err(_) => Ok(AuthResult::failure("Auth timeout", None)),
        }
    }

    async fn execute(&self, session: &dyn NxcSession, cmd: &str) -> Result<CommandOutput> {
         let mysql_sess = match session.protocol() {
            "mysql" => unsafe { &*(session as *const dyn NxcSession as *const MysqlSession) },
            _ => return Err(anyhow!("Invalid session type")),
        };

        let creds = mysql_sess.credentials.as_ref().ok_or_else(|| anyhow!("Not authenticated"))?;
        let opts = OptsBuilder::default()
            .ip_or_hostname(&mysql_sess.target)
            .tcp_port(mysql_sess.port)
            .user(Some(&creds.username))
            .pass(Some(creds.password.as_deref().unwrap_or_default()))
            .db_name(Some("mysql"));

        let pool = Pool::new(opts);
        let mut conn = pool.get_conn().await?;

        // MySQL execution is typically SQL-based. 
        // For OS command execution, it would involve UDF or FILE privilege (into outfile).
        // For now, we'll implement a simple "SQL execution" wrapper as a placeholder.
        
        let mut stdout = String::new();
        match conn.query::<Row, _>(cmd).await {
            Ok(rows) => {
                for row in rows {
                    let mut line = String::new();
                    for i in 0..row.len() {
                        let val: String = row.get(i).unwrap_or_else(|| "NULL".to_string());
                        line.push_str(&val);
                        line.push_str(" | ");
                    }
                    stdout.push_str(&line);
                    stdout.push('\n');
                }
            }
            Err(e) => {
                return Err(anyhow!("MySQL Query Error: {}", e));
            }
        }

        let _ = conn.disconnect().await;
        Ok(CommandOutput {
            stdout,
            stderr: String::new(),
            exit_code: Some(0),
        })
    }
}

impl MysqlProtocol {
    /// List all databases.
    pub async fn list_databases(&self, session: &MysqlSession) -> Result<Vec<String>> {
         let creds = session.credentials.as_ref().ok_or_else(|| anyhow!("Not authenticated"))?;
        let opts = OptsBuilder::default()
            .ip_or_hostname(&session.target)
            .tcp_port(session.port)
            .user(Some(&creds.username))
            .pass(Some(creds.password.as_deref().unwrap_or_default()));

        let pool = Pool::new(opts);
        let mut conn = pool.get_conn().await?;

        let rows = conn.query::<Row, _>("SHOW DATABASES").await?;
        let dbs = rows.into_iter().map(|row| row.get(0).unwrap_or_default()).collect();
        let _ = conn.disconnect().await;
        Ok(dbs)
    }
}
