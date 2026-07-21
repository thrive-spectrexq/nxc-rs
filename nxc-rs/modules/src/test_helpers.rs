use nxc_protocols::NxcSession;

/// A mock session for testing modules without real network connections.
pub struct MockSession {
    pub protocol_name: &'static str,
    pub target_host: String,
    pub is_admin_flag: bool,
}

impl MockSession {
    pub fn new(protocol: &'static str, target: &str, is_admin: bool) -> Self {
        Self { protocol_name: protocol, target_host: target.to_string(), is_admin_flag: is_admin }
    }
}

impl NxcSession for MockSession {
    fn protocol(&self) -> &'static str {
        self.protocol_name
    }

    fn target(&self) -> &str {
        &self.target_host
    }

    fn is_admin(&self) -> bool {
        self.is_admin_flag
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

// MockDb implementation for testing module database interactions.
#[cfg(test)]
pub mod mock_db {
    use anyhow::Result;
    use async_trait::async_trait;
    use nxc_db::{
        backend::{AttackChain, AttackPath, DatabaseBackend, OperationsLog, Stats, Vulnerability},
        AuthResultEntry, Credential, HostInfo, Loot, ShareInfo,
    };
    use std::sync::Mutex;

    /// In-memory mock implementation of `DatabaseBackend` for unit testing modules.
    #[derive(Debug, Default)]
    pub struct MockDb {
        pub hosts: Mutex<Vec<HostInfo>>,
        pub credentials: Mutex<Vec<Credential>>,
        pub auth_results: Mutex<Vec<AuthResultEntry>>,
        pub loot: Mutex<Vec<Loot>>,
        pub shares: Mutex<Vec<ShareInfo>>,
        pub vulnerabilities: Mutex<Vec<Vulnerability>>,
    }

    impl MockDb {
        pub fn new() -> Self {
            Self::default()
        }
    }

    #[async_trait]
    impl DatabaseBackend for MockDb {
        async fn upsert_host(&self, host: &HostInfo) -> Result<i64> {
            let mut hosts = self.hosts.lock().unwrap();
            hosts.push(host.clone());
            Ok(hosts.len() as i64)
        }

        async fn list_hosts(&self, _workspace: &str) -> Result<Vec<HostInfo>> {
            let hosts = self.hosts.lock().unwrap();
            Ok(hosts.clone())
        }

        async fn delete_host(&self, _host_id: i64) -> Result<usize> {
            Ok(1)
        }

        async fn add_credential(&self, cred: &Credential) -> Result<i64> {
            let mut creds = self.credentials.lock().unwrap();
            creds.push(cred.clone());
            Ok(creds.len() as i64)
        }

        async fn upsert_credential(&self, cred: &Credential) -> Result<i64> {
            self.add_credential(cred).await
        }

        async fn search_credentials(
            &self,
            _workspace: &str,
            _domain: Option<&str>,
            _source: Option<&str>,
            _admin_only: bool,
        ) -> Result<Vec<Credential>> {
            let creds = self.credentials.lock().unwrap();
            Ok(creds.clone())
        }

        async fn delete_credential(&self, _cred_id: i64) -> Result<usize> {
            Ok(1)
        }

        async fn add_auth_result(&self, res: &AuthResultEntry) -> Result<i64> {
            let mut auth = self.auth_results.lock().unwrap();
            auth.push(res.clone());
            Ok(auth.len() as i64)
        }

        async fn add_loot(&self, loot: &Loot) -> Result<i64> {
            let mut l = self.loot.lock().unwrap();
            l.push(loot.clone());
            Ok(l.len() as i64)
        }

        async fn add_share(&self, share: &ShareInfo) -> Result<i64> {
            let mut s = self.shares.lock().unwrap();
            s.push(share.clone());
            Ok(s.len() as i64)
        }

        async fn delete_workspace(&self, _workspace: &str) -> Result<usize> {
            Ok(1)
        }

        async fn export_workspace_json(&self, _workspace: &str) -> Result<String> {
            Ok("{}".to_string())
        }

        async fn get_stats(&self, _workspace: &str) -> Result<Stats> {
            Ok(Stats {
                hosts: self.hosts.lock().unwrap().len() as i64,
                credentials: self.credentials.lock().unwrap().len() as i64,
                dcs: 0,
                admin_accesses: 0,
            })
        }

        async fn add_vulnerability(&self, vuln: &Vulnerability) -> Result<i64> {
            let mut v = self.vulnerabilities.lock().unwrap();
            v.push(vuln.clone());
            Ok(v.len() as i64)
        }

        async fn add_attack_chain(&self, _chain: &AttackChain) -> Result<i64> {
            Ok(1)
        }

        async fn get_attack_paths(&self, _from: i64, _to: i64) -> Result<Vec<AttackPath>> {
            Ok(vec![])
        }

        async fn log_operation(&self, _log: &OperationsLog) -> Result<i64> {
            Ok(1)
        }
    }
}
