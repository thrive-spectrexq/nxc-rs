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

CREATE TABLE IF NOT EXISTS nxc_loot (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace  TEXT NOT NULL DEFAULT 'default',
    host_id    INTEGER REFERENCES nxc_hosts(id),
    name       TEXT NOT NULL,
    loot_type  TEXT NOT NULL,
    path       TEXT,
    content    TEXT,
    created_at INTEGER NOT NULL
);
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
pub struct AuthResultRecord {
    pub id: Option<i64>,
    pub host_id: i64,
    pub credential_id: Option<i64>,
    pub protocol: String,
    pub status: String, // "success", "failed", "locked"
    pub admin: bool,
    pub attempted_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Loot {
    pub id: Option<i64>,
    pub workspace: String,
    pub host_id: Option<i64>,
    pub name: String,
    pub loot_type: String, // e.g., "hash", "file", "registry"
    pub path: Option<String>,
    pub content: Option<String>,
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

// ─── Migration System ───────────────────────────────────────────

/// Ordered list of schema migrations. Each entry is (version, sql).
/// New migrations are appended; existing ones must NEVER be modified.
const MIGRATIONS: &[(i64, &str)] = &[
    (1, NXC_SCHEMA),
    // Future migrations:
    // (2, "ALTER TABLE nxc_hosts ADD COLUMN agent TEXT;"),
];

/// Run pending migrations against the database.
fn run_migrations(conn: &rusqlite::Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS nxc_schema_version (
            version INTEGER PRIMARY KEY,
            applied_at INTEGER NOT NULL
        )",
    )?;

    let current: i64 = conn
        .query_row("SELECT COALESCE(MAX(version), 0) FROM nxc_schema_version", [], |row| row.get(0))
        .unwrap_or(0);

    for (version, sql) in MIGRATIONS {
        if *version > current {
            conn.execute_batch(sql)?;
            conn.execute(
                "INSERT INTO nxc_schema_version (version, applied_at) VALUES (?1, ?2)",
                rusqlite::params![version, chrono::Utc::now().timestamp()],
            )?;
            tracing::info!("Applied database migration v{}", version);
        }
    }
    Ok(())
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

        // Run versioned migrations
        let conn = pool.get()?;
        run_migrations(&conn)?;

        Ok(Self { pool, workspace: workspace.to_string() })
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
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
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
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
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
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
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

    // ── Delete operations ──

    /// Delete a host by ID and cascade-remove its auth results and shares.
    pub fn delete_host(&self, host_id: i64) -> Result<bool> {
        let conn = self.pool.get()?;
        conn.execute(
            "DELETE FROM nxc_auth_results WHERE host_id = ?1",
            rusqlite::params![host_id],
        )?;
        conn.execute("DELETE FROM nxc_shares WHERE host_id = ?1", rusqlite::params![host_id])?;
        let rows =
            conn.execute("DELETE FROM nxc_hosts WHERE id = ?1", rusqlite::params![host_id])?;
        Ok(rows > 0)
    }

    /// Delete a credential by ID and cascade-remove its auth results.
    pub fn delete_credential(&self, cred_id: i64) -> Result<bool> {
        let conn = self.pool.get()?;
        conn.execute(
            "DELETE FROM nxc_auth_results WHERE credential_id = ?1",
            rusqlite::params![cred_id],
        )?;
        let rows =
            conn.execute("DELETE FROM nxc_credentials WHERE id = ?1", rusqlite::params![cred_id])?;
        Ok(rows > 0)
    }

    /// Delete an entire workspace and all associated data.
    pub fn delete_workspace(&self, workspace: &str) -> Result<u64> {
        let conn = self.pool.get()?;

        // Delete auth results for hosts in this workspace
        conn.execute(
            "DELETE FROM nxc_auth_results WHERE host_id IN (SELECT id FROM nxc_hosts WHERE workspace = ?1)",
            rusqlite::params![workspace],
        )?;
        // Delete shares for hosts in this workspace
        conn.execute(
            "DELETE FROM nxc_shares WHERE host_id IN (SELECT id FROM nxc_hosts WHERE workspace = ?1)",
            rusqlite::params![workspace],
        )?;
        let cred_rows = conn.execute(
            "DELETE FROM nxc_credentials WHERE workspace = ?1",
            rusqlite::params![workspace],
        )?;
        let host_rows = conn
            .execute("DELETE FROM nxc_hosts WHERE workspace = ?1", rusqlite::params![workspace])?;

        Ok((cred_rows + host_rows) as u64)
    }

    // ── Loot operations ──

    /// Add a new loot item (e.g., captured hash, downloaded file)
    pub fn add_loot(&self, loot: &Loot) -> Result<i64> {
        let conn = self.pool.get()?;
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO nxc_loot (workspace, host_id, name, loot_type, path, content, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                self.workspace,
                loot.host_id,
                loot.name,
                loot.loot_type,
                loot.path,
                loot.content,
                now,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// List all loot in the current workspace
    pub fn list_loot(&self) -> Result<Vec<Loot>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT id, workspace, host_id, name, loot_type, path, content, created_at
             FROM nxc_loot WHERE workspace = ?1 ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map(rusqlite::params![self.workspace], |row| {
            Ok(Loot {
                id: Some(row.get(0)?),
                workspace: row.get(1)?,
                host_id: row.get(2)?,
                name: row.get(3)?,
                loot_type: row.get(4)?,
                path: row.get(5)?,
                content: row.get(6)?,
                created_at: row.get(7)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Delete a specific loot item
    pub fn delete_loot(&self, loot_id: i64) -> Result<bool> {
        let conn = self.pool.get()?;
        let rows =
            conn.execute("DELETE FROM nxc_loot WHERE id = ?1", rusqlite::params![loot_id])?;
        Ok(rows > 0)
    }

    // ── Search operations ──

    /// Search credentials with optional filters.
    pub fn search_credentials(
        &self,
        domain: Option<&str>,
        source: Option<&str>,
        admin_only: bool,
    ) -> Result<Vec<Credential>> {
        let conn = self.pool.get()?;

        let mut sql = String::from(
            "SELECT c.id, c.workspace, c.domain, c.username, c.password, c.nt_hash, c.lm_hash, c.aes_128, c.aes_256, c.source, c.host_id, c.created_at
             FROM nxc_credentials c WHERE c.workspace = ?1"
        );
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> =
            vec![Box::new(self.workspace.clone())];
        let mut param_idx = 1u32;

        if let Some(dom) = domain {
            param_idx += 1;
            sql.push_str(&format!(" AND c.domain = ?{param_idx}"));
            params.push(Box::new(dom.to_string()));
        }
        if let Some(src) = source {
            param_idx += 1;
            sql.push_str(&format!(" AND c.source LIKE ?{param_idx}"));
            params.push(Box::new(format!("%{src}%")));
        }
        if admin_only {
            sql.push_str(
                " AND c.id IN (SELECT DISTINCT credential_id FROM nxc_auth_results WHERE admin = 1)"
            );
        }

        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(std::convert::AsRef::as_ref).collect();
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(param_refs.as_slice(), |row| {
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
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
    }

    // ── Auth result operations ──

    /// Record an authentication attempt result.
    pub fn add_auth_result(
        &self,
        host_id: i64,
        credential_id: Option<i64>,
        protocol: &str,
        status: &str,
        admin: bool,
    ) -> Result<i64> {
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT INTO nxc_auth_results (host_id, credential_id, protocol, status, admin, attempted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                host_id,
                credential_id,
                protocol,
                status,
                admin as i32,
                chrono::Utc::now().timestamp()
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    // ── Export / Import ──

    /// Export the entire workspace as a JSON string.
    pub fn export_workspace(&self) -> Result<String> {
        let hosts = self.list_hosts()?;
        let creds = self.list_credentials()?;

        #[derive(Serialize)]
        struct WorkspaceDump {
            workspace: String,
            hosts: Vec<HostInfo>,
            credentials: Vec<Credential>,
        }

        let dump = WorkspaceDump { workspace: self.workspace.clone(), hosts, credentials: creds };

        Ok(serde_json::to_string_pretty(&dump)?)
    }

    /// Import a workspace from a JSON dump string.
    pub fn import_workspace(&self, json: &str) -> Result<(usize, usize)> {
        #[derive(Deserialize)]
        struct WorkspaceDump {
            #[allow(dead_code)]
            workspace: String,
            hosts: Vec<HostInfo>,
            credentials: Vec<Credential>,
        }

        let dump: WorkspaceDump = serde_json::from_str(json)?;

        let mut host_count = 0usize;
        for mut host in dump.hosts {
            host.workspace = self.workspace.clone();
            self.upsert_host(&host)?;
            host_count += 1;
        }

        let mut cred_count = 0usize;
        for mut cred in dump.credentials {
            cred.workspace = self.workspace.clone();
            self.upsert_credential(&cred)?;
            cred_count += 1;
        }

        Ok((host_count, cred_count))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_db_migration_and_upsert() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("nxc_test.db");

        let db = NxcDb::new(&db_path, "default").unwrap();

        // Test upserting a host
        let host = HostInfo {
            id: None,
            workspace: "default".to_string(),
            ip: "192.168.1.100".to_string(),
            hostname: Some("win10".to_string()),
            domain: Some("CORP".to_string()),
            os: Some("Windows 10".to_string()),
            os_version: None,
            smb_signing: Some(true),
            signing_required: Some(false),
            is_dc: false,
            first_seen: 0,
            last_seen: 0,
        };

        let host_id = db.upsert_host(&host).unwrap();
        assert!(host_id > 0);

        let hosts = db.list_hosts_in("default").unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].ip, "192.168.1.100");
        assert_eq!(hosts[0].hostname.as_deref(), Some("win10"));
    }

    #[test]
    fn test_delete_host() {
        let dir = tempdir().unwrap();
        let db = NxcDb::new(&dir.path().join("test.db"), "default").unwrap();

        let host_id = db
            .upsert_host(&HostInfo {
                id: None,
                workspace: "default".into(),
                ip: "10.0.0.1".into(),
                hostname: None,
                domain: None,
                os: None,
                os_version: None,
                smb_signing: None,
                signing_required: None,
                is_dc: false,
                first_seen: 0,
                last_seen: 0,
            })
            .unwrap();

        assert!(db.delete_host(host_id).unwrap());
        assert_eq!(db.list_hosts().unwrap().len(), 0);
        // Deleting again returns false
        assert!(!db.delete_host(host_id).unwrap());
    }

    #[test]
    fn test_delete_credential() {
        let dir = tempdir().unwrap();
        let db = NxcDb::new(&dir.path().join("test.db"), "default").unwrap();

        let cred_id = db
            .add_credential(&Credential {
                id: None,
                workspace: "default".into(),
                domain: Some("CORP".into()),
                username: "admin".into(),
                password: Some("pass".into()),
                nt_hash: None,
                lm_hash: None,
                aes_128: None,
                aes_256: None,
                source: Some("smb".into()),
                host_id: None,
                created_at: 0,
            })
            .unwrap();

        assert!(db.delete_credential(cred_id).unwrap());
        assert_eq!(db.list_credentials().unwrap().len(), 0);
    }

    #[test]
    fn test_delete_workspace() {
        let dir = tempdir().unwrap();
        let db = NxcDb::new(&dir.path().join("test.db"), "default").unwrap();

        db.upsert_host(&HostInfo {
            id: None,
            workspace: "default".into(),
            ip: "10.0.0.1".into(),
            hostname: None,
            domain: None,
            os: None,
            os_version: None,
            smb_signing: None,
            signing_required: None,
            is_dc: false,
            first_seen: 0,
            last_seen: 0,
        })
        .unwrap();
        db.add_credential(&Credential {
            id: None,
            workspace: "default".into(),
            domain: None,
            username: "user1".into(),
            password: Some("p".into()),
            nt_hash: None,
            lm_hash: None,
            aes_128: None,
            aes_256: None,
            source: None,
            host_id: None,
            created_at: 0,
        })
        .unwrap();

        let deleted = db.delete_workspace("default").unwrap();
        assert!(deleted >= 2);
        assert_eq!(db.list_hosts().unwrap().len(), 0);
        assert_eq!(db.list_credentials().unwrap().len(), 0);
    }

    #[test]
    fn test_add_auth_result() {
        let dir = tempdir().unwrap();
        let db = NxcDb::new(&dir.path().join("test.db"), "default").unwrap();

        let host_id = db
            .upsert_host(&HostInfo {
                id: None,
                workspace: "default".into(),
                ip: "10.0.0.5".into(),
                hostname: None,
                domain: None,
                os: None,
                os_version: None,
                smb_signing: None,
                signing_required: None,
                is_dc: false,
                first_seen: 0,
                last_seen: 0,
            })
            .unwrap();

        let ar_id = db.add_auth_result(host_id, None, "smb", "success", true).unwrap();
        assert!(ar_id > 0);

        // Verify via stats
        let stats = db.get_stats_in("default").unwrap();
        assert_eq!(stats.admin_access_count, 1);
    }

    #[test]
    fn test_search_credentials_by_domain() {
        let dir = tempdir().unwrap();
        let db = NxcDb::new(&dir.path().join("test.db"), "default").unwrap();

        db.add_credential(&Credential {
            id: None,
            workspace: "default".into(),
            domain: Some("CORP".into()),
            username: "admin".into(),
            password: Some("p".into()),
            nt_hash: None,
            lm_hash: None,
            aes_128: None,
            aes_256: None,
            source: Some("smb".into()),
            host_id: None,
            created_at: 0,
        })
        .unwrap();
        db.add_credential(&Credential {
            id: None,
            workspace: "default".into(),
            domain: Some("OTHER".into()),
            username: "user".into(),
            password: Some("q".into()),
            nt_hash: None,
            lm_hash: None,
            aes_128: None,
            aes_256: None,
            source: Some("ssh".into()),
            host_id: None,
            created_at: 0,
        })
        .unwrap();

        let corp_creds = db.search_credentials(Some("CORP"), None, false).unwrap();
        assert_eq!(corp_creds.len(), 1);
        assert_eq!(corp_creds[0].username, "admin");

        let smb_creds = db.search_credentials(None, Some("smb"), false).unwrap();
        assert_eq!(smb_creds.len(), 1);
    }

    #[test]
    fn test_export_import_workspace() {
        let dir = tempdir().unwrap();
        let db = NxcDb::new(&dir.path().join("test.db"), "default").unwrap();

        db.upsert_host(&HostInfo {
            id: None,
            workspace: "default".into(),
            ip: "10.0.0.1".into(),
            hostname: Some("dc01".into()),
            domain: Some("CORP".into()),
            os: None,
            os_version: None,
            smb_signing: None,
            signing_required: None,
            is_dc: true,
            first_seen: 100,
            last_seen: 200,
        })
        .unwrap();
        db.add_credential(&Credential {
            id: None,
            workspace: "default".into(),
            domain: Some("CORP".into()),
            username: "admin".into(),
            password: Some("pass123".into()),
            nt_hash: None,
            lm_hash: None,
            aes_128: None,
            aes_256: None,
            source: Some("smb".into()),
            host_id: None,
            created_at: 100,
        })
        .unwrap();

        // Export
        let json = db.export_workspace().unwrap();
        assert!(json.contains("dc01"));
        assert!(json.contains("admin"));

        // Import into a new workspace
        let db2 = NxcDb::new(&dir.path().join("test2.db"), "imported").unwrap();
        let (hosts, creds) = db2.import_workspace(&json).unwrap();
        assert_eq!(hosts, 1);
        assert_eq!(creds, 1);

        let imported_hosts = db2.list_hosts().unwrap();
        assert_eq!(imported_hosts[0].ip, "10.0.0.1");
        assert_eq!(imported_hosts[0].workspace, "imported");
    }
}
