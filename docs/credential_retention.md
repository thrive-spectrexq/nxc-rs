# Credential Retention & Secure Erasure Policy

## 1. Overview

NetExec-RS (`nxc-rs`) is designed to capture, validate, and store authentication credentials during authorized security evaluations. Because stored credentials (NTLM hashes, cleartext passwords, Kerberos tickets, and Kerberos keys) are high-value enterprise secrets, this document defines the retention, rotation, and erasure policies for NetExec-RS databases.

---

## 2. Retention Guidelines

### 2.1 Principle of Least Retention
Credentials should be retained **only for the duration of the engagement or authorized audit window**.
- **Ephemeral Engagements**: For one-off security assessments or penetration tests, delete credentials and workspace data immediately upon report generation.
- **Continuous Monitoring**: When used for recurring security monitoring, retain credentials no longer than 30 days, or rotate workspace databases per assessment cycle.

### 2.2 Storage Isolation by Workspace
NetExec-RS partitions targets, credentials, and loot by workspace (`--workspace <name>`).
- Always create a dedicated workspace per assessment (e.g. `--workspace client-2026-q3`).
- Do not mix credentials from different clients or security domains in the `default` workspace.

---

## 3. Secure Erasure Options

### 3.1 Workspace Erasure via API
NetExec-RS provides dedicated programmatic APIs to delete credentials and purge disk storage:
- `NxcDb::erase_credentials(workspace)`:
  1. Executes `DELETE FROM nxc_credentials WHERE workspace = ?1`.
  2. Executes `VACUUM;` to reclaim freed SQLite pages and overwrite residual freelist storage on disk.
- `NxcDb::delete_workspace(workspace)`:
  Removes all associated hosts, credentials, shares, loot, and operations log entries for the specified workspace.

### 3.2 Manual Database Purge
To completely remove all stored credentials across all workspaces:
```bash
# Linux / macOS
rm -rf ~/.nxc/workspaces/
rm -f ~/.nxc/nxc.db

# Windows (PowerShell)
Remove-Item -Recurse -Force "$env:USERPROFILE\.nxc\workspaces"
Remove-Item -Force "$env:USERPROFILE\.nxc\nxc.db" -ErrorAction SilentlyContinue
```

---

## 4. Credential Export & Backup

### 4.1 Exporting Workspace Credentials
To archive credentials for encrypted offline storage before erasure:
```rust
let db = NxcDb::new(db_path, "client_assessment")?;
let json_dump = db.export_workspace()?;
std::fs::write("workspace_archive.json", json_dump)?;
```
Ensure `workspace_archive.json` is encrypted using GPG or Age before long-term archival.

### 4.2 Database Backup
NetExec-RS supports live online backup using SQLite transactional snapshots:
```rust
db.backup(Path::new("backups/nxc_backup_20260902.db"))?;
```
The resulting backup file is validated with `PRAGMA quick_check` to ensure no database corruption occurred during backup.
