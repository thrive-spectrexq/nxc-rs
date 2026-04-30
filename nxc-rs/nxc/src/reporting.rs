use nxc_targets::ExecutionResult;
use serde::Serialize;
use std::fs::File;
use std::io::Write;

use anyhow::Result;

#[derive(Serialize)]
pub struct Report {
    pub timestamp: String,
    pub protocol: String,
    pub results: Vec<ExecutionResult>,
}

pub fn export_json(path: &str, report: &Report) -> Result<()> {
    let file = File::create(path)?;
    serde_json::to_writer_pretty(file, report)?;
    Ok(())
}

pub fn export_csv(path: &str, results: &[ExecutionResult]) -> Result<()> {
    let file = File::create(path)?;
    let mut writer = csv::Writer::from_writer(file);

    // Write header
    writer.write_record([
        "target",
        "protocol",
        "username",
        "success",
        "admin",
        "message",
        "duration_ms",
        "module_data",
    ])?;

    for res in results {
        let module_data_json =
            serde_json::to_string(&res.module_data).unwrap_or_else(|_| "{}".to_string());
        writer.write_record([
            &res.target,
            &res.protocol,
            &res.username,
            &res.success.to_string(),
            &res.admin.to_string(),
            &res.message,
            &res.duration_ms.to_string(),
            &module_data_json,
        ])?;
    }
    writer.flush()?;
    Ok(())
}

/// Export results as newline-delimited JSON (NDJSON) for streaming/log pipelines.
pub fn export_ndjson(path: &str, results: &[ExecutionResult]) -> Result<()> {
    let mut file = File::create(path)?;
    for res in results {
        let line = serde_json::to_string(res)?;
        writeln!(file, "{line}")?;
    }
    file.flush()?;
    Ok(())
}

/// Export results as Metasploit-compatible XML.
pub fn export_xml(path: &str, report: &Report) -> Result<()> {
    let mut file = File::create(path)?;
    writeln!(file, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")?;
    writeln!(file, "<MetasploitV4>")?;
    writeln!(file, "  <hosts>")?;

    // Group by target
    let mut hosts_map: std::collections::HashMap<&str, Vec<&ExecutionResult>> =
        std::collections::HashMap::new();
    for res in &report.results {
        hosts_map.entry(&res.target).or_default().push(res);
    }

    for (target, results) in hosts_map {
        writeln!(file, "    <host>")?;
        writeln!(file, "      <address>{target}</address>")?;
        writeln!(file, "      <services>")?;

        let protocol = report.protocol.to_uppercase();
        let port = match protocol.as_str() {
            "SMB" => 445,
            "SSH" => 22,
            "LDAP" => 389,
            "WINRM" => 5985,
            "MSSQL" => 1433,
            "RDP" => 3389,
            "FTP" => 21,
            "VNC" => 5900,
            _ => 0,
        };

        writeln!(file, "        <service>")?;
        writeln!(file, "          <port>{port}</port>")?;
        writeln!(file, "          <proto>tcp</proto>")?;
        writeln!(file, "          <name>{protocol}</name>")?;
        writeln!(file, "          <state>open</state>")?;
        writeln!(file, "        </service>")?;
        writeln!(file, "      </services>")?;

        writeln!(file, "      <vulns>")?;
        for res in results {
            if res.success {
                writeln!(file, "        <vuln>")?;
                writeln!(file, "          <name>{protocol} Auth bypass/credentials</name>")?;
                writeln!(
                    file,
                    "          <info>Username: {} | Admin: {} | Message: {}</info>",
                    res.username,
                    res.admin,
                    res.message.replace("<", "&lt;").replace(">", "&gt;")
                )?;
                writeln!(file, "        </vuln>")?;
            }
        }
        writeln!(file, "      </vulns>")?;
        writeln!(file, "    </host>")?;
    }

    writeln!(file, "  </hosts>")?;
    writeln!(file, "</MetasploitV4>")?;

    file.flush()?;
    Ok(())
}

/// Export results as a Markdown report with summary and table.
pub fn export_markdown(path: &str, report: &Report) -> Result<()> {
    let mut file = File::create(path)?;

    let total = report.results.len();
    let successes = report.results.iter().filter(|r| r.success).count();
    let admins = report.results.iter().filter(|r| r.admin).count();
    let failures = total - successes;

    writeln!(file, "# NetExec-RS Scan Report")?;
    writeln!(file)?;
    writeln!(file, "- **Timestamp**: {}", report.timestamp)?;
    writeln!(file, "- **Protocol**: {}", report.protocol.to_uppercase())?;
    writeln!(file, "- **Total Results**: {total}")?;
    writeln!(file, "- **Successful**: {successes}")?;
    writeln!(file, "- **Admin Access**: {admins}")?;
    writeln!(file, "- **Failed**: {failures}")?;
    writeln!(file)?;

    writeln!(file, "## Results")?;
    writeln!(file)?;
    writeln!(file, "| Target | Username | Success | Admin | Duration (ms) | Message |")?;
    writeln!(file, "|--------|----------|---------|-------|---------------|---------|")?;

    for res in &report.results {
        let success_icon = if res.success { "✅" } else { "❌" };
        let admin_icon = if res.admin { "👑" } else { "—" };
        // Escape pipe characters in message
        let msg = res.message.replace('|', "\\|");
        writeln!(
            file,
            "| {} | {} | {} | {} | {} | {} |",
            res.target, res.username, success_icon, admin_icon, res.duration_ms, msg
        )?;
    }

    writeln!(file)?;
    writeln!(file, "---")?;
    writeln!(file, "*Generated by NetExec-RS*")?;

    file.flush()?;
    Ok(())
}

/// Export results as a styled HTML report with summary dashboard.
pub fn export_html(path: &str, report: &Report) -> Result<()> {
    let mut file = File::create(path)?;

    let total = report.results.len();
    let successes = report.results.iter().filter(|r| r.success).count();
    let admins = report.results.iter().filter(|r| r.admin).count();
    let failures = total - successes;

    write!(
        file,
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetExec-RS Report — {protocol}</title>
<style>
  :root {{
    --bg: #0d1117; --card: #161b22; --border: #30363d;
    --text: #c9d1d9; --text-dim: #8b949e; --accent: #58a6ff;
    --green: #3fb950; --red: #f85149; --yellow: #d29922; --purple: #bc8cff;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
         background: var(--bg); color: var(--text); padding: 2rem; }}
  .header {{ text-align: center; margin-bottom: 2rem; }}
  .header h1 {{ color: var(--accent); font-size: 1.8rem; }}
  .header .meta {{ color: var(--text-dim); margin-top: 0.5rem; font-size: 0.9rem; }}
  .dashboard {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2rem; }}
  .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px;
           padding: 1.2rem; text-align: center; }}
  .card .value {{ font-size: 2rem; font-weight: 700; }}
  .card .label {{ color: var(--text-dim); font-size: 0.85rem; margin-top: 0.3rem; }}
  .card.total .value {{ color: var(--accent); }}
  .card.success .value {{ color: var(--green); }}
  .card.admin .value {{ color: var(--yellow); }}
  .card.fail .value {{ color: var(--red); }}
  table {{ width: 100%; border-collapse: collapse; background: var(--card);
           border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
  th {{ background: #1c2128; color: var(--accent); padding: 0.75rem 1rem;
       text-align: left; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  td {{ padding: 0.65rem 1rem; border-top: 1px solid var(--border); font-size: 0.9rem; }}
  tr:hover td {{ background: #1c2128; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; font-weight: 600; }}
  .badge-success {{ background: rgba(63,185,80,0.15); color: var(--green); }}
  .badge-fail {{ background: rgba(248,81,73,0.15); color: var(--red); }}
  .badge-admin {{ background: rgba(210,153,34,0.15); color: var(--yellow); }}
  .footer {{ text-align: center; color: var(--text-dim); margin-top: 2rem; font-size: 0.8rem; }}
</style>
</head>
<body>
<div class="header">
  <h1>◈ NetExec-RS Scan Report</h1>
  <div class="meta">{protocol} | {timestamp}</div>
</div>

<div class="dashboard">
  <div class="card total"><div class="value">{total}</div><div class="label">Total</div></div>
  <div class="card success"><div class="value">{successes}</div><div class="label">Successful</div></div>
  <div class="card admin"><div class="value">{admins}</div><div class="label">Admin Access</div></div>
  <div class="card fail"><div class="value">{failures}</div><div class="label">Failed</div></div>
</div>

<table>
<thead>
<tr><th>Target</th><th>Username</th><th>Status</th><th>Admin</th><th>Duration</th><th>Message</th></tr>
</thead>
<tbody>
"#,
        protocol = report.protocol.to_uppercase(),
        timestamp = report.timestamp,
        total = total,
        successes = successes,
        admins = admins,
        failures = failures,
    )?;

    for res in &report.results {
        let status_badge = if res.success {
            r#"<span class="badge badge-success">SUCCESS</span>"#
        } else {
            r#"<span class="badge badge-fail">FAILED</span>"#
        };
        let admin_badge =
            if res.admin { r#"<span class="badge badge-admin">ADMIN</span>"# } else { "—" };
        let msg_escaped =
            res.message.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
        writeln!(
            file,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}ms</td><td>{}</td></tr>",
            res.target, res.username, status_badge, admin_badge, res.duration_ms, msg_escaped
        )?;
    }

    write!(
        file,
        r#"</tbody>
</table>
<div class="footer">Generated by NetExec-RS</div>
</body>
</html>
"#
    )?;

    file.flush()?;
    Ok(())
}
