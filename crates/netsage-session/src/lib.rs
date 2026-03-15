use anyhow::Result;
use chrono::Utc;
use rusqlite::{params, Connection};
use serde_json::Value;
use std::path::Path;

pub struct SessionStore {
    conn: Connection,
}

impl SessionStore {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;

        // Initialize tables
        conn.execute(
            "CREATE TABLE IF NOT EXISTS tool_calls (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                tool TEXT NOT NULL,
                args TEXT NOT NULL,
                status TEXT NOT NULL,
                result TEXT
            )",
            [],
        )?;

        Ok(Self { conn })
    }

    pub fn log_tool_call(&self, id: &str, tool: &str, args: &Value, status: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO tool_calls (id, timestamp, tool, args, status)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, Utc::now().to_rfc3339(), tool, args.to_string(), status],
        )?;
        Ok(())
    }

    pub fn update_tool_result(&self, id: &str, result: &Value) -> Result<()> {
        self.conn.execute(
            "UPDATE tool_calls SET status = 'completed', result = ?1 WHERE id = ?2",
            params![result.to_string(), id],
        )?;
        Ok(())
    }

    pub fn export_as_markdown(&self) -> Result<String> {
        let mut stmt = self.conn.prepare("SELECT id, timestamp, tool, args, status, result FROM tool_calls ORDER BY timestamp ASC")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
            ))
        })?;

        let mut output = String::from("# NetSage Session Report\n\n");
        for row in rows {
            let (id, ts, tool, args, status, result) = row?;
            output.push_str(&format!("## [{}] {}\n", ts, tool));
            output.push_str(&format!("- **ID**: `{}`\n", id));
            output.push_str(&format!("- **Status**: {}\n", status));
            output.push_str(&format!("- **Arguments**: `{}`\n", args));
            if let Some(res) = result {
                output.push_str(&format!("- **Result**:\n```json\n{}\n```\n", res));
            }
            output.push_str("\n---\n\n");
        }
        Ok(output)
    }
}
