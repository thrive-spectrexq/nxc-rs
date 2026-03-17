//! # LDAP Protocol Handler
//!
//! LDAP protocol implementation using the `ldap3` crate.
//! Supports simple bind authentication.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use std::time::Duration;
use tracing::{debug, info};

// ─── LDAP Session ────────────────────────────────────────────────

pub struct LdapSession {
    pub target: String,
    pub port: u16,
    pub admin: bool,
    pub is_ldaps: bool,
}

impl NxcSession for LdapSession {
    fn protocol(&self) -> &'static str {
        "ldap"
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn is_admin(&self) -> bool {
        self.admin
    }
}

// ─── LDAP Protocol Handler ───────────────────────────────────────

pub struct LdapProtocol {
    pub timeout: Duration,
}

impl LdapProtocol {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(10),
        }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }

    fn build_url(&self, target: &str, port: u16) -> String {
        let scheme = if port == 636 { "ldaps" } else { "ldap" };
        format!("{}://{}:{}", scheme, target, port)
    }
}

impl Default for LdapProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcProtocol for LdapProtocol {
    fn name(&self) -> &'static str {
        "ldap"
    }

    fn default_port(&self) -> u16 {
        389
    }

    fn supports_exec(&self) -> bool {
        false
    }

    fn supported_modules(&self) -> &[&str] {
        &["kerberoasting", "asreproasting"] // Based on NetExec modules
    }

    async fn connect(&self, target: &str, port: u16) -> Result<Box<dyn NxcSession>> {
        let url = self.build_url(target, port);
        debug!("LDAP: Connecting to {}", url);

        // Simple connection check (the actual bind happens in authenticate)
        // With ldap3, we establish the connection and bind later, but here we just
        // verify we can connect to the port.

        let timeout = self.timeout;
        let target_owned = target.to_string();

        let session_result = tokio::task::spawn_blocking(move || -> Result<LdapSession> {
            let addr = format!("{}:{}", target_owned, port);
            let _tcp = std::net::TcpStream::connect_timeout(
                &addr.parse().map_err(|e| anyhow!("Invalid address {}: {}", addr, e))?,
                timeout, // Connect timeout
            )?;

            info!("LDAP: Connected to {}", url);

            Ok(LdapSession {
                target: target_owned,
                port,
                admin: false,
                is_ldaps: port == 636,
            })
        })
        .await??;

        Ok(Box::new(session_result))
    }

    async fn authenticate(
        &self,
        session: &mut dyn NxcSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        let username = creds.username.clone();
        let password = creds.password.clone().unwrap_or_default();
        let target = session.target().to_string();
        let ldap_session = unsafe { &*(session as *const dyn NxcSession as *const LdapSession) };
        let port = ldap_session.port;
        let url = self.build_url(&target, port);

        // NTLM/Kerberos auth for LDAP might be more complex, but we fallback to simple bind
        // if password is provided.
        // For basic NXC functionality, we need a simple bind.

        debug!("LDAP: Authenticating {}@{}", username, url);

        // Use ldap3 async API
        let (conn, mut ldap) = match tokio::time::timeout(self.timeout, ldap3::LdapConnAsync::new(&url)).await {
            Ok(Ok(res)) => res,
            Ok(Err(e)) => {
                let msg = format!("LDAP connection failed: {}", e);
                debug!("{}", msg);
                return Ok(AuthResult::failure(&msg, None));
            }
            Err(_) => {
                return Ok(AuthResult::failure("LDAP connection timeout", None));
            }
        };

        ldap3::drive!(conn);

        // Try simple bind
        let bind_result = tokio::time::timeout(self.timeout, ldap.simple_bind(&username, &password)).await;

        match bind_result {
            Ok(Ok(res)) => {
                if res.rc == 0 {
                    debug!("LDAP: Auth successful for {}", username);
                    // Disconnect cleanly
                    let _ = ldap.unbind().await;
                    // For LDAP, "admin" usually requires context, so we default to false or check generic indicators
                    Ok(AuthResult::success(false))
                } else {
                    let msg = format!("Bind failed: {}", res.text);
                    debug!("LDAP: Auth failed for {}: {}", username, msg);
                    let _ = ldap.unbind().await;
                    Ok(AuthResult::failure(&msg, None))
                }
            }
            Ok(Err(e)) => {
                let msg = format!("Bind error: {}", e);
                debug!("LDAP: Auth failed for {}: {}", username, msg);
                let _ = ldap.unbind().await;
                Ok(AuthResult::failure(&msg, None))
            }
            Err(_) => {
                let _ = ldap.unbind().await;
                Ok(AuthResult::failure("LDAP bind timeout", None))
            }
        }
    }

    async fn execute(&self, _session: &dyn NxcSession, _cmd: &str) -> Result<CommandOutput> {
        // LDAP does not support arbitrary command execution like SMB/SSH.
        Err(anyhow!("Command execution is not supported over LDAP."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ldap_protocol_defaults() {
        let proto = LdapProtocol::new();
        assert_eq!(proto.name(), "ldap");
        assert_eq!(proto.default_port(), 389);
        assert!(!proto.supports_exec());
    }
}
