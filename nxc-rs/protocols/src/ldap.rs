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
    pub credentials: Option<Credentials>,
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

    /// Perform an authenticated search against the LDAP server.
    pub async fn search(
        &self,
        session: &LdapSession,
        base_dn: &str,
        scope: ldap3::Scope,
        filter: &str,
        attrs: Vec<&str>,
    ) -> Result<Vec<ldap3::SearchEntry>> {
        let url = self.build_url(&session.target, session.port);
        let creds = session.credentials.as_ref().ok_or_else(|| anyhow!("Session skipped authentication"))?;
        
        let username = creds.username.clone();
        let password = creds.password.clone().unwrap_or_default();

        let (conn, mut ldap) = tokio::time::timeout(self.timeout, ldap3::LdapConnAsync::new(&url))
            .await
            .map_err(|_| anyhow!("LDAP connection timeout"))??;

        ldap3::drive!(conn);

        let res = ldap.simple_bind(&username, &password).await?;
        if res.rc != 0 {
            return Err(anyhow!("LDAP bind failed for search: {}", res.text));
        }

        let rs = ldap.search(base_dn, scope, filter, attrs).await?;
        let mut entries = Vec::new();
        
        for entry in rs.0 {
            let search_entry = ldap3::SearchEntry::construct(entry);
            entries.push(search_entry);
        }

        let _ = ldap.unbind().await;
        Ok(entries)
    }

    /// Resolve naming contexts to find the base DN if not provided.
    pub async fn get_base_dn(&self, session: &LdapSession) -> Result<String> {
        let entries = self.search(
            session,
            "",
            ldap3::Scope::Base,
            "(objectClass=*)",
            vec!["defaultNamingContext"],
        ).await?;

        if let Some(entry) = entries.first() {
            if let Some(dn) = entry.attrs.get("defaultNamingContext").and_then(|v| v.first()) {
                return Ok(dn.clone());
            }
        }
        
        Err(anyhow!("Could not resolve defaultNamingContext"))
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
        &["whoami", "laps", "enum_dns", "kerberoasting", "asreproasting"]
    }

    async fn connect(&self, target: &str, port: u16) -> Result<Box<dyn NxcSession>> {
        let addr = format!("{}:{}", target, port);
        let target_owned = target.to_string();
        let timeout = self.timeout;

        let _ = tokio::task::spawn_blocking(move || -> Result<()> {
            let _tcp = std::net::TcpStream::connect_timeout(
                &addr.parse().map_err(|e| anyhow!("Invalid address {}: {}", addr, e))?,
                timeout,
            )?;
            Ok(())
        })
        .await??;

        info!("LDAP: Connected to {}", self.build_url(target, port));

        Ok(Box::new(LdapSession {
            target: target_owned,
            port,
            admin: false,
            is_ldaps: port == 636,
            credentials: None,
        }))
    }

    async fn authenticate(
        &self,
        session: &mut dyn NxcSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        let ldap_session = match session.protocol() {
            "ldap" => unsafe { &mut *(session as *mut dyn NxcSession as *mut LdapSession) },
            _ => return Err(anyhow!("Invalid session type")),
        };

        let url = self.build_url(&ldap_session.target, ldap_session.port);
        let username = creds.username.clone();
        let password = creds.password.clone().unwrap_or_default();

        debug!("LDAP: Authenticating {}@{}", username, url);

        let (conn, mut ldap) = match tokio::time::timeout(self.timeout, ldap3::LdapConnAsync::new(&url)).await {
            Ok(Ok(res)) => res,
            Ok(Err(e)) => return Ok(AuthResult::failure(&format!("Connection failed: {}", e), None)),
            Err(_) => return Ok(AuthResult::failure("Connection timeout", None)),
        };

        ldap3::drive!(conn);

        let res = ldap.simple_bind(&username, &password).await?;
        if res.rc == 0 {
            debug!("LDAP: Auth successful for {}", username);
            ldap_session.credentials = Some(creds.clone());
            let _ = ldap.unbind().await;
            Ok(AuthResult::success(false))
        } else {
            let _ = ldap.unbind().await;
            Ok(AuthResult::failure(&res.text, None))
        }
    }

    async fn execute(&self, _session: &dyn NxcSession, _cmd: &str) -> Result<CommandOutput> {
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
