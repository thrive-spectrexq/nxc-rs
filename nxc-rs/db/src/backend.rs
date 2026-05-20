use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{AuthResultEntry, Credential, HostInfo, Loot};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: Option<i64>,
    pub host_id: i64,
    pub cve_id: Option<String>,
    pub title: String,
    pub severity: String,
    pub description: Option<String>,
    pub evidence: Option<String>,
    pub module_name: Option<String>,
    pub detected_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackChain {
    pub id: Option<i64>,
    pub workspace: String,
    pub name: String,
    pub description: Option<String>,
    pub steps: String,
    pub risk_score: Option<f64>,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    pub from_host_id: i64,
    pub to_host_id: i64,
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationsLog {
    pub id: Option<i64>,
    pub workspace: String,
    pub operation: String,
    pub target: Option<String>,
    pub module: Option<String>,
    pub status: String,
    pub details: Option<String>,
    pub started_at: u64,
    pub completed_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareInfo {
    pub id: Option<i64>,
    pub host_id: i64,
    pub share: String,
    pub permissions: String,
    pub remark: String,
}

#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub hosts: i64,
    pub credentials: i64,
    pub dcs: i64,
    pub admin_accesses: i64,
}

#[async_trait]
pub trait DatabaseBackend: Send + Sync {
    // Hosts
    async fn upsert_host(&self, host: &HostInfo) -> Result<i64>;
    async fn list_hosts(&self, workspace: &str) -> Result<Vec<HostInfo>>;
    async fn delete_host(&self, host_id: i64) -> Result<usize>;

    // Credentials
    async fn add_credential(&self, cred: &Credential) -> Result<i64>;
    async fn upsert_credential(&self, cred: &Credential) -> Result<i64>;
    async fn search_credentials(&self, workspace: &str, domain: Option<&str>, source: Option<&str>, admin_only: bool) -> Result<Vec<Credential>>;
    async fn delete_credential(&self, cred_id: i64) -> Result<usize>;

    // Auth Results
    async fn add_auth_result(&self, res: &AuthResultEntry) -> Result<i64>;

    // Loot
    async fn add_loot(&self, loot: &Loot) -> Result<i64>;

    // Shares
    async fn add_share(&self, share: &ShareInfo) -> Result<i64>;

    // Workspaces
    async fn delete_workspace(&self, workspace: &str) -> Result<usize>;
    async fn export_workspace_json(&self, workspace: &str) -> Result<String>;
    async fn get_stats(&self, workspace: &str) -> Result<Stats>;

    // Advanced Operations (Phase 1 additions)
    async fn add_vulnerability(&self, vuln: &Vulnerability) -> Result<i64>;
    async fn add_attack_chain(&self, chain: &AttackChain) -> Result<i64>;
    async fn get_attack_paths(&self, from: i64, to: i64) -> Result<Vec<AttackPath>>;
    async fn log_operation(&self, log: &OperationsLog) -> Result<i64>;
}
