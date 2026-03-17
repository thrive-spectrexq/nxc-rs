use anyhow::Result;
use chrono::Utc;
use netsage_common::{AuditRecord, PacketSummary};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use serde_json::Value;
use std::path::Path;
use uuid::Uuid;

#[derive(Clone)]
pub struct SessionManager {
    pool: Pool<SqliteConnectionManager>,
}

impl SessionManager {
    pub fn new(db_path: &Path) -> Result<Self> {
        let manager = SqliteConnectionManager::file(db_path);
        let pool = Pool::new(manager)?;

        let conn = pool.get()?;

        // v1.0.0 Roadmap Schema
        conn.execute(
            "CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                started_at INTEGER NOT NULL,
                ended_at INTEGER,
                provider TEXT NOT NULL,
                model TEXT NOT NULL,
                approval_mode TEXT NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS turns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL REFERENCES sessions(id),
                turn_index INTEGER NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL REFERENCES sessions(id),
                tool_name TEXT NOT NULL,
                tool_input TEXT NOT NULL,
                tool_output TEXT,
                approved INTEGER NOT NULL,
                duration_ms INTEGER,
                created_at INTEGER NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                ts INTEGER NOT NULL,
                proto TEXT NOT NULL,
                src TEXT,
                dst TEXT,
                length INTEGER NOT NULL,
                summary TEXT
            )",
            [],
        )?;

        Ok(Self { pool })
    }

    pub async fn log_turn(&self, session_id: Uuid, role: &str, content: &str) -> Result<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT INTO turns (session_id, turn_index, role, content, created_at)
             VALUES (?1, (SELECT COALESCE(MAX(turn_index), 0) + 1 FROM turns WHERE session_id = ?1), ?2, ?3, ?4)",
            rusqlite::params![session_id.to_string(), role, content, Utc::now().timestamp_millis()],
        )?;
        Ok(())
    }

    pub async fn log_audit(
        &self,
        session_id: Uuid,
        entry: &AuditRecord,
        tool_input: &Value,
        tool_output: Option<&Value>,
    ) -> Result<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT INTO audit_log (session_id, tool_name, tool_input, tool_output, approved, duration_ms, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                session_id.to_string(),
                entry.tool_name,
                tool_input.to_string(),
                tool_output.map(|v| v.to_string()),
                if entry.approved { 1 } else { 0 },
                entry.duration_ms,
                Utc::now().timestamp_millis()
            ],
        )?;
        Ok(())
    }

    pub async fn log_packet(&self, session_id: Uuid, pkt: &PacketSummary) -> Result<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT INTO packets (session_id, ts, proto, src, dst, length)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                session_id.to_string(),
                pkt.timestamp.timestamp_millis(),
                pkt.protocol,
                pkt.src_ip.as_deref(),
                pkt.dst_ip.as_deref(),
                pkt.length
            ],
        )?;
        Ok(())
    }

    pub fn export_markdown(&self, session_id: Uuid) -> Result<String> {
        let conn = self.pool.get()?;
        let mut export = format!(
            "# NetSage Session Report\n**Session ID:** `{}`\n\n",
            session_id
        );

        // Export logic here...
        export.push_str("## Conversation Transcript\n");
        let mut stmt = conn.prepare(
            "SELECT role, content FROM turns WHERE session_id = ? ORDER BY turn_index ASC",
        )?;
        let rows = stmt.query_map([session_id.to_string()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;

        for row in rows {
            let (role, content) = row?;
            export.push_str(&format!("**{}:** {}\n\n", role, content));
        }

        Ok(export)
    }
}
