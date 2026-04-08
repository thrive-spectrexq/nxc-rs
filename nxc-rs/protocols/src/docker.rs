//! # Docker Protocol Handler
//!
//! Docker and Docker Registry protocol implementation for NetExec-RS.
//! Supports unauthenticated API check and image/repository enumeration.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use std::time::Duration;
use tracing::{debug, info};

// ─── Docker Session ──────────────────────────────────────────────

pub struct DockerSession {
    pub target: String,
    pub port: u16,
    pub admin: bool,
    pub is_registry: bool,
    pub credentials: Option<Credentials>,
}

impl NxcSession for DockerSession {
    fn protocol(&self) -> &'static str {
        "docker"
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

// ─── Docker Protocol Handler ───────────────────────────────────────

pub struct DockerProtocol {
    pub timeout: Duration,
}

impl DockerProtocol {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(5),
        }
    }
}

impl Default for DockerProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcProtocol for DockerProtocol {
    fn name(&self) -> &'static str {
        "docker"
    }

    fn default_port(&self) -> u16 {
        2375 // Docker API default
    }

    fn supports_exec(&self) -> bool {
        true // Possible via Docker API (exec)
    }

    fn supported_modules(&self) -> &[&str] {
        &["docker_enum", "registry_enum"]
    }

    async fn connect(
        &self,
        target: &str,
        port: u16,
        _proxy: Option<&str>,
    ) -> Result<Box<dyn NxcSession>> {
        let is_registry = port == 5000;
        let addr = if is_registry {
            format!("http://{}:{}/v2/", target, port)
        } else {
            format!("http://{}:{}/version", target, port)
        };

        debug!("Docker: Checking connection to {}", addr);

        let client = reqwest::Client::builder().timeout(self.timeout).build()?;

        let resp = client.get(&addr).send().await;
        match resp {
            Ok(res) => {
                let status = res.status();
                info!("Docker: Response from {}: {}", addr, status);

                let is_unauth = status.is_success();
                Ok(Box::new(DockerSession {
                    target: target.to_string(),
                    port,
                    admin: is_unauth,
                    is_registry,
                    credentials: None,
                }))
            }
            Err(e) => {
                if e.is_status() && e.status() == Some(reqwest::StatusCode::UNAUTHORIZED) {
                    debug!("Docker: Service found, but authentication required.");
                    Ok(Box::new(DockerSession {
                        target: target.to_string(),
                        port,
                        admin: false,
                        is_registry,
                        credentials: None,
                    }))
                } else {
                    Err(anyhow!("Connection failed: {}", e))
                }
            }
        }
    }

    async fn authenticate(
        &self,
        session: &mut dyn NxcSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        let docker_sess = match session.protocol() {
            "docker" => unsafe { &mut *(session as *mut dyn NxcSession as *mut DockerSession) },
            _ => return Err(anyhow!("Invalid session type")),
        };

        let username = &creds.username;
        let password = creds.password.as_deref().unwrap_or_default();

        let addr = if docker_sess.is_registry {
            format!("http://{}:{}/v2/", docker_sess.target, docker_sess.port)
        } else {
            format!("http://{}:{}/version", docker_sess.target, docker_sess.port)
        };

        debug!("Docker: Authenticating as {} at {}", username, addr);

        let client = reqwest::Client::builder().timeout(self.timeout).build()?;

        let resp = client
            .get(&addr)
            .basic_auth(username, Some(password))
            .send()
            .await;

        match resp {
            Ok(res) if res.status().is_success() => {
                debug!("Docker: Auth successful for {}", username);
                docker_sess.credentials = Some(creds.clone());
                docker_sess.admin = true;
                Ok(AuthResult::success(true))
            }
            Ok(res) => {
                debug!("Docker: Auth failed for {}: {}", username, res.status());
                Ok(AuthResult::failure(&res.status().to_string(), None))
            }
            Err(e) => {
                debug!("Docker: Auth error for {}: {}", username, e);
                Ok(AuthResult::failure(&e.to_string(), None))
            }
        }
    }

    async fn execute(&self, session: &dyn NxcSession, cmd: &str) -> Result<CommandOutput> {
        let docker_sess = match session.protocol() {
            "docker" => unsafe { &*(session as *const dyn NxcSession as *const DockerSession) },
            _ => return Err(anyhow!("Invalid session type")),
        };

        if docker_sess.is_registry {
            return Err(anyhow!(
                "Docker Registry does not support command execution"
            ));
        }

        if !docker_sess.admin {
            return Err(anyhow!(
                "Authentication or admin access required for Docker API execution"
            ));
        }

        // Implementation of Docker API exec would go here.
        // 1. POST /containers/{id}/exec
        // 2. POST /exec/{id}/start
        // For now, return a placeholder as it requires a container ID.

        Ok(CommandOutput {
            stdout: format!("Docker execution of '{}' requires an active container ID. Use docker_enum to find containers.", cmd),
            stderr: String::new(),
            exit_code: Some(0),
        })
    }
}

impl DockerProtocol {
    /// List repositories (Registry) or containers (API).
    pub async fn enumerate(&self, session: &DockerSession) -> Result<String> {
        let client = reqwest::Client::builder().timeout(self.timeout).build()?;

        let mut req = if session.is_registry {
            client.get(format!(
                "http://{}:{}/v2/_catalog",
                session.target, session.port
            ))
        } else {
            client.get(format!(
                "http://{}:{}/containers/json?all=1",
                session.target, session.port
            ))
        };

        if let Some(ref creds) = session.credentials {
            req = req.basic_auth(&creds.username, creds.password.as_deref());
        }

        let resp = req.send().await?;
        if resp.status().is_success() {
            let body = resp.text().await?;
            Ok(body)
        } else {
            Err(anyhow!("Enumeration failed: {}", resp.status()))
        }
    }
}
