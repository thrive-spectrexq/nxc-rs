//! # nxc-db — NetExec-RS Credential Database
//!
//! Extends the netsage-session SQLite store with tables for hosts, credentials,
//! auth results, and shares — the nxcdb equivalent.

use anyhow::Result;
use serde::{Deserialize, Serialize};

// ─── Schema Constants ───────────────────────────────────────────

/// SQL to create nxc tables (backward-compatible migrations).
pub const NXC_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS nxc_hosts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace   TEXT NOT NULL DEFAULT 'default',
    ip          TEXT NOT NULL,
    hostname    TEXT,
    domain      TEXT,
    os          TEXT,
    os_version  TEXT,
    smb_signing INTEGER,
    signing_req INTEGER,
    dc          INTEGER DEFAULT 0,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    UNIQUE(workspace, ip)
);

CREATE TABLE IF NOT EXISTS nxc_credentials (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace  TEXT NOT NULL DEFAULT 'default',
    domain     TEXT,
    username   TEXT NOT NULL,
    password   TEXT,
    nt_hash    TEXT,
    lm_hash    TEXT,
    aes_128    TEXT,
    aes_256    TEXT,
    source     TEXT,
    host_id    INTEGER REFERENCES nxc_hosts(id),
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS nxc_auth_results (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id       INTEGER NOT NULL REFERENCES nxc_hosts(id),
    credential_id INTEGER REFERENCES nxc_credentials(id),
    protocol      TEXT NOT NULL,
    status        TEXT NOT NULL,
    admin         INTEGER DEFAULT 0,
    attempted_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS nxc_shares (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id      INTEGER NOT NULL REFERENCES nxc_hosts(id),
    name         TEXT NOT NULL,
    remark       TEXT,
    read_access  INTEGER DEFAULT 0,
    write_access INTEGER DEFAULT 0
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_nxc_creds_unique ON nxc_credentials(workspace, username, domain);
"#;

// ─── Data Types ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub id: Option<i64>,
    pub workspace: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub domain: Option<String>,
    pub os: Option<String>,
    pub os_version: Option<String>,
    pub smb_signing: Option<bool>,
    pub signing_required: Option<bool>,
    pub is_dc: bool,
    pub first_seen: i64,
    pub last_seen: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: Option<i64>,
    pub workspace: String,
    pub domain: Option<String>,
    pub username: String,
    pub password: Option<String>,
    pub nt_hash: Option<String>,
    pub lm_hash: Option<String>,
    pub aes_128: Option<String>,
    pub aes_256: Option<String>,
    pub source: Option<String>,
    pub host_id: Option<i64>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareInfo {
    pub id: Option<i64>,
    pub host_id: i64,
    pub name: String,
    pub remark: Option<String>,
    pub read_access: bool,
    pub write_access: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceStats {
    pub workspace: String,
    pub host_count: i64,
    pub cred_count: i64,
    pub dc_count: i64,
    pub admin_access_count: i64,
}

// ─── NxcDb Manager ──────────────────────────────────────────────

/// Credential workspace database manager.
pub struct NxcDb {
    pool: r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>,
    workspace: String,
}

impl NxcDb {
    /// Create a new NxcDb, running schema migrations.
    pub fn new(db_path: &std::path::Path, workspace: &str) -> Result<Self> {
        let manager = r2d2_sqlite::SqliteConnectionManager::file(db_path);
        let pool = r2d2::Pool::new(manager)?;

        // Run schema migrations
        let conn = pool.get()?;
        conn.execute_batch(NXC_SCHEMA)?;

        Ok(Self {
            pool,
            workspace: workspace.to_string(),
        })
    }

    // ── Host operations ──

    pub fn upsert_host(&self, host: &HostInfo) -> Result<i64> {
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT INTO nxc_hosts (workspace, ip, hostname, domain, os, os_version, smb_signing, signing_req, dc, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(workspace, ip) DO UPDATE SET
                hostname = COALESCE(excluded.hostname, hostname),
                domain = COALESCE(excluded.domain, domain),
                os = COALESCE(excluded.os, os),
                last_seen = excluded.last_seen",
            rusqlite::params![
                host.workspace, host.ip, host.hostname, host.domain,
                host.os, host.os_version,
                host.smb_signing.map(|b| b as i32),
                host.signing_required.map(|b| b as i32),
                host.is_dc as i32,
                host.first_seen, host.last_seen
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn list_hosts(&self) -> Result<Vec<HostInfo>> {
        self.list_hosts_in(&self.workspace)
    }

    pub fn list_hosts_in(&self, workspace: &str) -> Result<Vec<HostInfo>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT id, workspace, ip, hostname, domain, os, os_version, smb_signing, signing_req, dc, first_seen, last_seen
             FROM nxc_hosts WHERE workspace = ?1"
        )?;
        let rows = stmt.query_map(rusqlite::params![workspace], |row| {
            Ok(HostInfo {
                id: Some(row.get(0)?),
                workspace: row.get(1)?,
                ip: row.get(2)?,
                hostname: row.get(3)?,
                domain: row.get(4)?,
                os: row.get(5)?,
                os_version: row.get(6)?,
                smb_signing: row.get::<_, Option<i32>>(7)?.map(|v| v != 0),
                signing_required: row.get::<_, Option<i32>>(8)?.map(|v| v != 0),
                is_dc: row.get::<_, i32>(9)? != 0,
                first_seen: row.get(10)?,
                last_seen: row.get(11)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    // ── Credential operations ──

    pub fn add_credential(&self, cred: &Credential) -> Result<i64> {
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT INTO nxc_credentials (workspace, domain, username, password, nt_hash, lm_hash, aes_128, aes_256, source, host_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![
                cred.workspace, cred.domain, cred.username, cred.password,
                cred.nt_hash, cred.lm_hash, cred.aes_128, cred.aes_256,
                cred.source, cred.host_id, cred.created_at
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Upsert a credential based on username, domain, and hash.
    pub fn upsert_credential(&self, cred: &Credential) -> Result<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT INTO nxc_credentials (workspace, domain, username, password, nt_hash, lm_hash, aes_128, aes_256, source, host_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(workspace, username, domain) DO UPDATE SET
                password = COALESCE(excluded.password, password),
                nt_hash = COALESCE(excluded.nt_hash, nt_hash),
                lm_hash = COALESCE(excluded.lm_hash, lm_hash),
                aes_128 = COALESCE(excluded.aes_128, aes_128),
                aes_256 = COALESCE(excluded.aes_256, aes_256),
                source = excluded.source,
                created_at = excluded.created_at",
            rusqlite::params![
                cred.workspace, cred.domain, cred.username, cred.password,
                cred.nt_hash, cred.lm_hash, cred.aes_128, cred.aes_256,
                cred.source, cred.host_id, cred.created_at
            ],
        )?;
        Ok(())
    }

    pub fn list_credentials(&self) -> Result<Vec<Credential>> {
        self.list_credentials_in(&self.workspace)
    }

    pub fn list_credentials_in(&self, workspace: &str) -> Result<Vec<Credential>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT id, workspace, domain, username, password, nt_hash, lm_hash, aes_128, aes_256, source, host_id, created_at
             FROM nxc_credentials WHERE workspace = ?1"
        )?;
        let rows = stmt.query_map(rusqlite::params![workspace], |row| {
            Ok(Credential {
                id: Some(row.get(0)?),
                workspace: row.get(1)?,
                domain: row.get(2)?,
                username: row.get(3)?,
                password: row.get(4)?,
                nt_hash: row.get(5)?,
                lm_hash: row.get(6)?,
                aes_128: row.get(7)?,
                aes_256: row.get(8)?,
                source: row.get(9)?,
                host_id: row.get(10)?,
                created_at: row.get(11)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    // ── Workspace management ──

    pub fn set_workspace(&mut self, name: &str) {
        self.workspace = name.to_string();
    }

    pub fn current_workspace(&self) -> &str {
        &self.workspace
    }

    pub fn list_workspaces(&self) -> Result<Vec<String>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT DISTINCT workspace FROM nxc_hosts")?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn get_stats_in(&self, workspace: &str) -> Result<WorkspaceStats> {
        let conn = self.pool.get()?;

        let host_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM nxc_hosts WHERE workspace = ?1",
            rusqlite::params![workspace],
            |row| row.get(0),
        )?;

        let cred_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM nxc_credentials WHERE workspace = ?1",
            rusqlite::params![workspace],
            |row| row.get(0),
        )?;

        let dc_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM nxc_hosts WHERE workspace = ?1 AND dc = 1",
            rusqlite::params![workspace],
            |row| row.get(0),
        )?;

        // Admin access is tracked in auth_results
        let admin_access_count: i64 = conn.query_row(
            "SELECT COUNT(DISTINCT host_id) FROM nxc_auth_results 
             JOIN nxc_hosts ON nxc_auth_results.host_id = nxc_hosts.id
             WHERE nxc_hosts.workspace = ?1 AND nxc_auth_results.admin = 1",
            rusqlite::params![workspace],
            |row| row.get(0),
        )?;

        Ok(WorkspaceStats {
            workspace: workspace.to_string(),
            host_count,
            cred_count,
            dc_count,
            admin_access_count,
        })
    }
}
