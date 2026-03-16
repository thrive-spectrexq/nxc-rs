use anyhow::Result;
use chrono::Utc;
use rusqlite::{params, Connection};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;

enum SessionCommand {
    LogToolCall {
        id: String,
        tool: String,
        args: String,
        status: String,
    },
    UpdateToolResult {
        id: String,
        result: String,
    },
    ExportMarkdown {
        resp_tx: mpsc::Sender<Result<String>>,
    },
    LogSnapshot {
        topology_json: String,
    },
}

#[derive(Clone)]
pub struct SessionStore {
    tx: mpsc::Sender<SessionCommand>,
}

impl SessionStore {
    pub fn open(path: &Path) -> Result<Self> {
        let path = path.to_path_buf();
        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            if let Err(e) = Self::run_db_thread(path, rx) {
                eprintln!("SessionStore database thread error: {}", e);
            }
        });

        Ok(Self { tx })
    }

    fn run_db_thread(path: PathBuf, rx: mpsc::Receiver<SessionCommand>) -> Result<()> {
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

        conn.execute(
            "CREATE TABLE IF NOT EXISTS topology_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                topology_json TEXT NOT NULL
            )",
            [],
        )?;

        while let Ok(cmd) = rx.recv() {
            match cmd {
                SessionCommand::LogToolCall {
                    id,
                    tool,
                    args,
                    status,
                } => {
                    let _ = conn.execute(
                        "INSERT INTO tool_calls (id, timestamp, tool, args, status)
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![id, Utc::now().to_rfc3339(), tool, args, status],
                    );
                }
                SessionCommand::UpdateToolResult { id, result } => {
                    let _ = conn.execute(
                        "UPDATE tool_calls SET status = 'completed', result = ?1 WHERE id = ?2",
                        params![result, id],
                    );
                }
                SessionCommand::ExportMarkdown { resp_tx } => {
                    let result = Self::perform_export(&conn);
                    let _ = resp_tx.send(result);
                }
                SessionCommand::LogSnapshot { topology_json } => {
                    let _ = conn.execute(
                        "INSERT INTO topology_snapshots (timestamp, topology_json) VALUES (?1, ?2)",
                        params![Utc::now().to_rfc3339(), topology_json],
                    );
                }
            }
        }

        Ok(())
    }

    fn perform_export(conn: &Connection) -> Result<String> {
        let mut stmt = conn.prepare("SELECT id, timestamp, tool, args, status, result FROM tool_calls ORDER BY timestamp ASC")?;
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

    pub fn log_tool_call(&self, id: &str, tool: &str, args: &Value, status: &str) -> Result<()> {
        self.tx
            .send(SessionCommand::LogToolCall {
                id: id.to_string(),
                tool: tool.to_string(),
                args: args.to_string(),
                status: status.to_string(),
            })
            .map_err(|e| anyhow::anyhow!("Failed to send log_tool_call: {}", e))
    }

    pub fn update_tool_result(&self, id: &str, result: &Value) -> Result<()> {
        self.tx
            .send(SessionCommand::UpdateToolResult {
                id: id.to_string(),
                result: result.to_string(),
            })
            .map_err(|e| anyhow::anyhow!("Failed to send update_tool_result: {}", e))
    }

    pub fn export_as_markdown(&self) -> Result<String> {
        let (resp_tx, resp_rx) = mpsc::channel();
        self.tx
            .send(SessionCommand::ExportMarkdown { resp_tx })
            .map_err(|e| anyhow::anyhow!("Failed to send export request: {}", e))?;
        resp_rx
            .recv()
            .map_err(|e| anyhow::anyhow!("Failed to receive export result: {}", e))?
    }

    pub fn log_snapshot(&self, topology_json: &Value) -> Result<()> {
        self.tx
            .send(SessionCommand::LogSnapshot {
                topology_json: topology_json.to_string(),
            })
            .map_err(|e| anyhow::anyhow!("Failed to send log_snapshot: {}", e))
    }
}
