//! # Redis Protocol Handler
//!
//! Redis protocol implementation for NetExec-RS.
//! Supports unauthenticated connection, basic authentication, and system enumeration.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use redis::Client;
use std::time::Duration;
use tracing::{debug, info};

// ─── Redis Session ────────────────────────────────────────────────

pub struct RedisSession {
    pub target: String,
    pub port: u16,
    pub admin: bool,
    pub credentials: Option<Credentials>,
}

impl NxcSession for RedisSession {
    fn protocol(&self) -> &'static str {
        "redis"
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

// ─── Redis Protocol Handler ───────────────────────────────────────

pub struct RedisProtocol {
    pub timeout: Duration,
}

impl RedisProtocol {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(5),
        }
    }
}

impl Default for RedisProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcProtocol for RedisProtocol {
    fn name(&self) -> &'static str {
        "redis"
    }

    fn default_port(&self) -> u16 {
        6379
    }

    fn supports_exec(&self) -> bool {
        false // Redis doesn't have a direct "exec shell" command like MSSQL
    }

    fn supported_modules(&self) -> &[&str] {
        &["redis_enum", "redis_info"]
    }

    async fn connect(&self, target: &str, port: u16, _proxy: Option<&str>) -> Result<Box<dyn NxcSession>> {
        let connection_info = format!("redis://{}:{}/", target, port);
        debug!("Redis: Connecting to {}", connection_info);

        let client = Client::open(connection_info)?;
        let connect_fut = tokio::time::timeout(self.timeout, client.get_multiplexed_async_connection());

        match connect_fut.await {
            Ok(Ok(mut conn)) => {
                info!("Redis: Connected to {}:{}", target, port);
                // Check if it's unauthenticated
                let is_unauth: bool = redis::cmd("INFO").query_async::<redis::Value>(&mut conn).await.is_ok();
                
                Ok(Box::new(RedisSession {
                    target: target.to_string(),
                    port,
                    admin: is_unauth, // If unauth, we effectively have full access
                    credentials: None,
                }))
            }
            Ok(Err(e)) => {
                // If it requires auth, we might still be "connected" but unable to run commands
                if e.to_string().contains("Authentication required") || e.to_string().contains("NOAUTH") {
                     debug!("Redis: Connection established, but authentication required.");
                     Ok(Box::new(RedisSession {
                        target: target.to_string(),
                        port,
                        admin: false,
                        credentials: None,
                    }))
                } else {
                    Err(anyhow!("Connection failed: {}", e))
                }
            }
            Err(_) => Err(anyhow!("Connection timeout to {}:{}", target, port)),
        }
    }

    async fn authenticate(
        &self,
        session: &mut dyn NxcSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        let redis_sess = match session.protocol() {
            "redis" => unsafe { &mut *(session as *mut dyn NxcSession as *mut RedisSession) },
            _ => return Err(anyhow!("Invalid session type")),
        };

        if creds.username.is_empty() && creds.password.is_none() {
            // Anonymous check already done in connect, but let's re-verify if needed
            return Ok(AuthResult::success(redis_sess.admin));
        }

        let password = creds.password.as_deref().unwrap_or_default();
        let connection_info = if creds.username.is_empty() {
             format!("redis://:{}@{}:{}/", password, redis_sess.target, redis_sess.port)
        } else {
             format!("redis://{}:{}@{}:{}/", creds.username, password, redis_sess.target, redis_sess.port)
        };

        let client = Client::open(connection_info)?;
        let connect_fut = tokio::time::timeout(self.timeout, client.get_multiplexed_async_connection());

        match connect_fut.await {
            Ok(Ok(mut _conn)) => {
                debug!("Redis: Auth successful for password: {}", password);
                redis_sess.credentials = Some(creds.clone());
                redis_sess.admin = true; // Redis auth usually gives full access
                Ok(AuthResult::success(true))
            }
            Ok(Err(e)) => {
                debug!("Redis: Auth failed: {}", e);
                Ok(AuthResult::failure(&e.to_string(), None))
            }
            Err(_) => Ok(AuthResult::failure("Auth timeout", None)),
        }
    }

    async fn execute(&self, _session: &dyn NxcSession, _cmd: &str) -> Result<CommandOutput> {
        Err(anyhow!("Redis protocol does not support command execution"))
    }
}

impl RedisProtocol {
    /// Get Redis INFO enumeration.
    pub async fn get_info(&self, session: &RedisSession) -> Result<String> {
        let connection_info = if let Some(ref creds) = session.credentials {
            let password = creds.password.as_deref().unwrap_or_default();
            if creds.username.is_empty() {
                format!("redis://:{}@{}:{}/", password, session.target, session.port)
            } else {
                format!("redis://{}:{}@{}:{}/", creds.username, password, session.target, session.port)
            }
        } else {
            format!("redis://{}:{}/", session.target, session.port)
        };

        let client = Client::open(connection_info)?;
        let mut conn = client.get_multiplexed_async_connection().await?;
        let info: String = redis::cmd("INFO").query_async(&mut conn).await?;
        Ok(info)
    }
}
