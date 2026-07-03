use anyhow::Result;
use async_trait::async_trait;
use tokio::task::spawn_blocking;

use crate::backend::{
    AttackChain, AttackPath, DatabaseBackend, OperationsLog, Stats, Vulnerability,
};
use crate::{AuthResultEntry, Credential, HostInfo, Loot, NxcDb};

#[async_trait]
impl DatabaseBackend for NxcDb {
    async fn upsert_host(&self, host: &HostInfo) -> Result<i64> {
        let db = self.clone();
        let h = host.clone();
        spawn_blocking(move || db.upsert_host(&h)).await?
    }

    async fn list_hosts(&self, workspace: &str) -> Result<Vec<HostInfo>> {
        let db = self.clone();
        let ws = workspace.to_string();
        spawn_blocking(move || db.list_hosts_in(&ws)).await?
    }

    async fn delete_host(&self, host_id: i64) -> Result<usize> {
        let db = self.clone();
        spawn_blocking(move || db.delete_host(host_id).map(|b| if b { 1 } else { 0 })).await?
    }

    async fn add_credential(&self, cred: &Credential) -> Result<i64> {
        let db = self.clone();
        let c = cred.clone();
        spawn_blocking(move || db.add_credential(&c)).await?
    }

    async fn upsert_credential(&self, cred: &Credential) -> Result<i64> {
        let db = self.clone();
        let c = cred.clone();
        spawn_blocking(move || db.upsert_credential(&c).map(|_| 0)).await?
    }

    async fn search_credentials(
        &self,
        workspace: &str,
        domain: Option<&str>,
        source: Option<&str>,
        admin_only: bool,
    ) -> Result<Vec<Credential>> {
        let db = self.clone();
        let ws = workspace.to_string();
        let dom = domain.map(String::from);
        let src = source.map(String::from);
        spawn_blocking(move || {
            let mut db_mut = db.clone();
            db_mut.set_workspace(&ws);
            db_mut.search_credentials(dom.as_deref(), src.as_deref(), admin_only)
        }).await?
    }

    async fn delete_credential(&self, cred_id: i64) -> Result<usize> {
        let db = self.clone();
        spawn_blocking(move || db.delete_credential(cred_id).map(|b| if b { 1 } else { 0 })).await?
    }

    async fn add_auth_result(&self, res: &AuthResultEntry) -> Result<i64> {
        let db = self.clone();
        let r = res.clone();
        spawn_blocking(move || db.add_auth_result(r.host_id, r.credential_id, &r.protocol, &r.status, r.admin)).await?
    }

    async fn add_loot(&self, loot: &Loot) -> Result<i64> {
        let db = self.clone();
        let l = loot.clone();
        spawn_blocking(move || db.add_loot(&l)).await?
    }

    async fn add_share(&self, _share: &crate::ShareInfo) -> Result<i64> {
        // Not currently implemented in NxcDb natively, but we could add it
        Ok(0)
    }

    async fn delete_workspace(&self, workspace: &str) -> Result<usize> {
        let db = self.clone();
        let ws = workspace.to_string();
        spawn_blocking(move || db.delete_workspace(&ws).map(|n| n as usize)).await?
    }

    async fn export_workspace_json(&self, workspace: &str) -> Result<String> {
        let db = self.clone();
        let ws = workspace.to_string();
        spawn_blocking(move || {
            let mut db_mut = db;
            db_mut.set_workspace(&ws);
            db_mut.export_workspace()
        }).await?
    }

    async fn get_stats(&self, workspace: &str) -> Result<Stats> {
        let db = self.clone();
        let ws = workspace.to_string();
        let stats = spawn_blocking(move || db.get_stats_in(&ws)).await??;
        Ok(Stats {
            hosts: stats.host_count,
            credentials: stats.cred_count,
            dcs: stats.dc_count,
            admin_accesses: stats.admin_access_count,
        })
    }

    async fn add_vulnerability(&self, vuln: &Vulnerability) -> Result<i64> {
        let db = self.clone();
        let v = vuln.clone();
        spawn_blocking(move || {
            let conn = db.get_connection()?;
            conn.execute(
                "INSERT INTO nxc_vulnerabilities (host_id, cve_id, title, severity, description, evidence, module_name, detected_at) 
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    v.host_id, v.cve_id, v.title, v.severity, v.description, v.evidence, v.module_name, v.detected_at
                ],
            )?;
            Ok(conn.last_insert_rowid())
        })
        .await?
    }

    async fn add_attack_chain(&self, chain: &AttackChain) -> Result<i64> {
        let db = self.clone();
        let c = chain.clone();
        spawn_blocking(move || {
            let conn = db.get_connection()?;
            conn.execute(
                "INSERT INTO nxc_attack_chains (workspace, name, description, steps, risk_score, created_at) 
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    c.workspace, c.name, c.description, c.steps, c.risk_score, c.created_at
                ],
            )?;
            Ok(conn.last_insert_rowid())
        })
        .await?
    }

    async fn get_attack_paths(&self, _from: i64, _to: i64) -> Result<Vec<AttackPath>> {
        // To be implemented fully with graph search later
        Ok(vec![])
    }

    async fn log_operation(&self, log: &OperationsLog) -> Result<i64> {
        let db = self.clone();
        let l = log.clone();
        spawn_blocking(move || {
            let conn = db.get_connection()?;
            conn.execute(
                "INSERT INTO nxc_operations_log (workspace, operation, target, module, status, details, started_at, completed_at) 
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    l.workspace, l.operation, l.target, l.module, l.status, l.details, l.started_at, l.completed_at
                ],
            )?;
            Ok(conn.last_insert_rowid())
        })
        .await?
    }
}
