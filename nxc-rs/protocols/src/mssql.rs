//! # MSSQL Protocol Handler
//!
//! MSSQL protocol implementation using the `tiberius` crate for TDS connections.
//! Replicates NetExec capability for DB enum and query execution.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::{kerberos::KerberosClient, AuthResult, Credentials};
use std::time::Duration;
use tiberius::{AuthMethod, Client, Config};
use tokio_util::compat::TokioAsyncWriteCompatExt;
use tracing::{debug, info};

// ─── MSSQL Session ────────────────────────────────────────────────

pub struct MssqlSession {
    pub target: String,
    pub port: u16,
    pub admin: bool,
    pub credentials: Option<Credentials>,
    pub proxy: Option<String>,
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
        Self { timeout: Duration::from_secs(10) }
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
        &["enum_logins", "enum_databases", "mssql_enum", "mssql_privesc", "mssql_unc"]
    }

    async fn connect(
        &self,
        target: &str,
        port: u16,
        proxy: Option<&str>,
    ) -> Result<Box<dyn NxcSession>> {
        let addr = format!("{target}:{port}");
        debug!("MSSQL: Connecting to {} (proxy: {:?})", addr, proxy);

        let timeout_fut =
            tokio::time::timeout(self.timeout, crate::connection::connect(target, port, proxy));
        match timeout_fut.await {
            Ok(Ok(_stream)) => {
                info!("MSSQL: Connected to {}", addr);
                Ok(Box::new(MssqlSession {
                    target: target.to_string(),
                    port,
                    admin: false,
                    credentials: None,
                    proxy: proxy.map(std::string::ToString::to_string),
                }))
            }
            Ok(Err(e)) => Err(anyhow!("Connection refused or unreachable: {e}")),
            Err(_) => Err(anyhow!("Connection timeout to {addr}")),
        }
    }

    async fn authenticate(
        &self,
        session: &mut dyn NxcSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        let mssql_sess_mut = session
            .as_any_mut()
            .downcast_mut::<MssqlSession>()
            .ok_or_else(|| anyhow!("Invalid session type"))?;

        if creds.username.is_empty() {
            return Ok(AuthResult::success(false));
        }

        if creds.use_kerberos {
            debug!("MSSQL: Authenticating {} via Kerberos", creds.username);
            return self.authenticate_kerberos(mssql_sess_mut, creds).await;
        }

        let username = creds.username.clone();
        let password = creds.password.clone().unwrap_or_default();
        let target = mssql_sess_mut.target.clone();
        let port = mssql_sess_mut.port;

        let addr = format!("{target}:{port}");
        debug!("MSSQL: Authenticating {}@{}", username, addr);

        let mut config = Config::new();
        config.host(&target);
        config.port(port);

        // Support NTLM auth if domain is provided or if simple auth fails
        if let Some(ref domain) = creds.domain {
            debug!("MSSQL: Using Windows auth for {}\\{}", domain, username);
            #[cfg(any(feature = "winauth", feature = "integrated-auth-gssapi"))]
            config.authentication(AuthMethod::sql_server(
                format!("{domain}\\{username}"),
                &password,
            ));
            #[cfg(not(any(feature = "winauth", feature = "integrated-auth-gssapi")))]
            config
                .authentication(AuthMethod::sql_server(format!("{domain}\\{username}"), &password));
        } else {
            config.authentication(AuthMethod::sql_server(&username, &password));
        }

        config.trust_cert();

        let tcp_fut = tokio::time::timeout(
            self.timeout,
            crate::connection::connect(&target, port, mssql_sess_mut.proxy.as_deref()),
        );
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
                let msg = format!("Auth error: {e}");
                debug!("MSSQL: Auth failed for {}: {}", username, msg);
                Ok(AuthResult::failure(&msg, None))
            }
            Err(_) => Ok(AuthResult::failure("MSSQL auth timeout", None)),
        }
    }

    async fn execute(&self, session: &dyn NxcSession, cmd: &str) -> Result<CommandOutput> {
        let mssql_sess = session
            .as_any()
            .downcast_ref::<MssqlSession>()
            .ok_or_else(|| anyhow!("Invalid session type"))?;

        let creds =
            mssql_sess.credentials.as_ref().ok_or_else(|| anyhow!("Session not authenticated"))?;
        let mut config = Config::new();
        config.host(&mssql_sess.target);
        config.port(mssql_sess.port);

        let user = &creds.username;
        let pass = creds.password.as_deref().unwrap_or_default();

        if let Some(ref domain) = creds.domain {
            config.authentication(AuthMethod::sql_server(format!("{domain}\\{user}"), pass));
        } else {
            config.authentication(AuthMethod::sql_server(user, pass));
        }

        config.trust_cert();

        let tcp = crate::connection::connect(
            &mssql_sess.target,
            mssql_sess.port,
            mssql_sess.proxy.as_deref(),
        )
        .await?;
        let mut client = Client::connect(config, tcp.compat_write()).await?;

        // 1. Ensure xp_cmdshell is enabled
        let _ =
            client.execute("EXEC sp_configure 'show advanced options', 1; RECONFIGURE;", &[]).await;
        let _ = client.execute("EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;", &[]).await;

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
        Ok(CommandOutput { stdout, stderr: String::new(), exit_code: Some(0) })
    }

    async fn read_file(
        &self,
        session: &dyn NxcSession,
        _share: &str,
        path: &str,
    ) -> Result<Vec<u8>> {
        let output = self.execute(session, &format!("type {path}")).await?;
        Ok(output.stdout.into_bytes())
    }

    async fn write_file(
        &self,
        session: &dyn NxcSession,
        _share: &str,
        path: &str,
        data: &[u8],
    ) -> Result<()> {
        let hex_data = hex::encode(data);
        // Using certutil to decode hex in case of binary data
        let cmd = format!("certutil -decodehex temp.hex {path} && del temp.hex");
        self.execute(session, &format!("echo {hex_data} > temp.hex")).await?;
        self.execute(session, &cmd).await?;
        Ok(())
    }
}

impl MssqlProtocol {
    pub async fn query_json(
        &self,
        session: &MssqlSession,
        sql: &str,
    ) -> Result<Vec<serde_json::Value>> {
        let creds =
            session.credentials.as_ref().ok_or_else(|| anyhow!("Session not authenticated"))?;
        let mut config = Config::new();
        config.host(&session.target);
        config.port(session.port);

        let user = &creds.username;
        let pass = creds.password.as_deref().unwrap_or_default();

        if let Some(ref domain) = creds.domain {
            config.authentication(AuthMethod::sql_server(format!("{domain}\\{user}"), pass));
        } else {
            config.authentication(AuthMethod::sql_server(user, pass));
        }

        config.trust_cert();

        let tcp =
            crate::connection::connect(&session.target, session.port, session.proxy.as_deref())
                .await?;
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

    /// Enumerate linked servers.
    pub async fn enumerate_links(&self, session: &MssqlSession) -> Result<Vec<serde_json::Value>> {
        let sql = "SELECT name, product, provider, data_source, is_remote_login_enabled, is_rpc_out_enabled FROM sys.servers WHERE is_linked = 1";
        self.query_json(session, sql).await
    }

    /// Perform Kerberos authentication over MSSQL
    async fn authenticate_kerberos(
        &self,
        mssql_sess: &mut MssqlSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        let domain = creds.domain.as_deref().unwrap_or("DOMAIN");
        let kdc_ip = &mssql_sess.target;

        let krb_client = KerberosClient::new(domain, kdc_ip);

        // 1. Request TGT
        let tgt = krb_client.request_tgt_with_creds(creds).await?;

        // 2. Request TGS for MSSQL service
        let spn = format!("MSSQLSvc/{}:{}", mssql_sess.target, mssql_sess.port);
        let _tgs = krb_client.request_tgs(&tgt, &spn).await?;

        // 3. Initiate Connection with Tiberius
        let mut config = Config::new();
        config.host(&mssql_sess.target);
        config.port(mssql_sess.port);

        #[cfg(any(feature = "winauth", feature = "integrated-auth-gssapi"))]
        config.authentication(AuthMethod::sql_server(
            format!("{}\\{}", domain, creds.username),
            creds.password.as_deref().unwrap_or_default(),
        ));

        config.trust_cert();

        #[cfg(not(any(feature = "winauth", feature = "integrated-auth-gssapi")))]
        {
            Ok(AuthResult::failure("Kerberos/Windows Auth not supported", None))
        }

        #[cfg(any(feature = "winauth", feature = "integrated-auth-gssapi"))]
        {
            let tcp = crate::connection::connect(
                &mssql_sess.target,
                mssql_sess.port,
                mssql_sess.proxy.as_deref(),
            )
            .await?;
            match tokio::time::timeout(self.timeout, Client::connect(config, tcp.compat_write()))
                .await
            {
                Ok(Ok(_client)) => {
                    debug!("MSSQL: Kerberos Auth successful for {}", creds.username);
                    mssql_sess.credentials = Some(creds.clone());
                    Ok(AuthResult::success(false))
                }
                Ok(Err(e)) => Ok(AuthResult::failure(&format!("Auth failed: {e}"), None)),
                Err(_) => Ok(AuthResult::failure("Connection timeout", None)),
            }
        }
    }
}
