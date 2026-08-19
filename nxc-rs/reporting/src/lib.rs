use nxc_targets::ExecutionResult;
use serde::Serialize;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

#[derive(Serialize)]
pub struct Report {
    pub timestamp: String,
    pub protocol: String,
    pub results: Vec<ExecutionResult>,
}

/// Atomically writes content to a target file path by writing to a temporary file
/// in the same directory and renaming it.
pub fn atomic_write_file<F>(path: &str, write_fn: F) -> Result<()>
where
    F: FnOnce(&mut File) -> Result<()>,
{
    let target_path = Path::new(path);
    if let Some(parent) = target_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create parent directory for {path}"))?;
        }
    }

    let parent_dir = target_path.parent().unwrap_or_else(|| Path::new("."));
    let temp_name = format!(
        ".{}.tmp.{}",
        target_path.file_name().and_then(|n| n.to_str()).unwrap_or("export"),
        uuid::Uuid::new_v4()
    );
    let tmp_path = parent_dir.join(temp_name);

    {
        let mut file = File::create(&tmp_path)
            .with_context(|| format!("Failed to create temporary file at {tmp_path:?}"))?;
        write_fn(&mut file)?;
        file.flush().with_context(|| format!("Failed to flush temporary file at {tmp_path:?}"))?;
    }

    std::fs::rename(&tmp_path, target_path).with_context(|| {
        format!("Failed to rename temporary file from {tmp_path:?} to {target_path:?}")
    })?;

    Ok(())
}

/// Sanitize a string for safe inclusion in CSV cells to prevent Formula Injection (CSV injection).
/// If a string starts with `=`, `+`, `-`, `@`, tab, or carriage return, prepend `'`.
pub fn sanitize_csv_field(val: &str) -> String {
    if val.starts_with('=')
        || val.starts_with('+')
        || val.starts_with('-')
        || val.starts_with('@')
        || val.starts_with('\t')
        || val.starts_with('\r')
    {
        format!("'{val}")
    } else {
        val.to_string()
    }
}

/// Sanitize workspace names and path segments to prevent directory traversal (`..`, slashes, control chars).
pub fn sanitize_workspace_name(name: &str) -> String {
    let sanitized: String =
        name.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-').collect();
    if sanitized.is_empty() {
        "default".to_string()
    } else {
        sanitized
    }
}

/// Validate export file path to ensure it does not attempt directory traversal out of expected bounds.
pub fn validate_export_path(path: &str) -> Result<PathBuf> {
    let pb = PathBuf::from(path);
    for component in pb.components() {
        if let std::path::Component::ParentDir = component {
            anyhow::bail!("Path traversal ('..') is not permitted in export path: {path}");
        }
    }
    Ok(pb)
}

pub fn export_json(path: &str, report: &Report) -> Result<()> {
    validate_export_path(path)?;
    atomic_write_file(path, |file| {
        serde_json::to_writer_pretty(file, report)?;
        Ok(())
    })
}

pub fn export_csv(path: &str, results: &[ExecutionResult]) -> Result<()> {
    validate_export_path(path)?;
    atomic_write_file(path, |file| {
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
                &sanitize_csv_field(&res.target),
                &sanitize_csv_field(&res.protocol),
                &sanitize_csv_field(&res.username),
                &res.success.to_string(),
                &res.admin.to_string(),
                &sanitize_csv_field(&res.message),
                &res.duration_ms.to_string(),
                &sanitize_csv_field(&module_data_json),
            ])?;
        }
        writer.flush()?;
        Ok(())
    })
}

/// Export results as newline-delimited JSON (NDJSON) for streaming/log pipelines.
pub fn export_ndjson(path: &str, results: &[ExecutionResult]) -> Result<()> {
    validate_export_path(path)?;
    atomic_write_file(path, |file| {
        for res in results {
            let line = serde_json::to_string(res)?;
            writeln!(file, "{line}")?;
        }
        Ok(())
    })
}

/// Escape the five XML special characters in a string.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Export results as Metasploit-compatible XML.
pub fn export_xml(path: &str, report: &Report) -> Result<()> {
    validate_export_path(path)?;
    atomic_write_file(path, |file| {
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
            writeln!(file, "      <address>{}</address>", xml_escape(target))?;
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
                        xml_escape(&res.username),
                        res.admin,
                        xml_escape(&res.message),
                    )?;
                    writeln!(file, "        </vuln>")?;
                }
            }
            writeln!(file, "      </vulns>")?;
            writeln!(file, "    </host>")?;
        }

        writeln!(file, "  </hosts>")?;
        writeln!(file, "</MetasploitV4>")?;
        Ok(())
    })
}

/// Export results as a Markdown report with summary and table.
pub fn export_markdown(path: &str, report: &Report) -> Result<()> {
    validate_export_path(path)?;
    atomic_write_file(path, |file| {
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
        Ok(())
    })
}

/// Export results as a styled HTML report with summary dashboard.
pub fn export_html(path: &str, report: &Report) -> Result<()> {
    validate_export_path(path)?;
    atomic_write_file(path, |file| {
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
            protocol = xml_escape(&report.protocol.to_uppercase()),
            timestamp = xml_escape(&report.timestamp),
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
            let msg_escaped = xml_escape(&res.message);
            let target_escaped = xml_escape(&res.target);
            let user_escaped = xml_escape(&res.username);
            writeln!(
                file,
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}ms</td><td>{}</td></tr>",
                target_escaped,
                user_escaped,
                status_badge,
                admin_badge,
                res.duration_ms,
                msg_escaped
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
        Ok(())
    })
}

// ─── PDF Export (raw PDF 1.4, zero external dependencies) ───────

/// Lightweight PDF 1.4 writer — produces valid documents with text streams.
struct PdfWriter {
    objects: Vec<Vec<u8>>,
}

impl PdfWriter {
    fn new() -> Self {
        Self { objects: Vec::new() }
    }

    /// Add an indirect object and return its 1-based object number.
    fn add_object(&mut self, data: Vec<u8>) -> usize {
        self.objects.push(data);
        self.objects.len() // 1-based
    }

    /// Serialise the entire PDF to bytes.
    fn finish(self, _pages_obj: usize, catalog_obj: usize) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n");

        // Write objects and record byte offsets
        let mut offsets: Vec<usize> = Vec::new();
        for (i, obj) in self.objects.iter().enumerate() {
            offsets.push(buf.len());
            let header = format!("{} 0 obj\n", i + 1);
            buf.extend_from_slice(header.as_bytes());
            buf.extend_from_slice(obj);
            buf.extend_from_slice(b"\nendobj\n");
        }

        // Cross-reference table
        let xref_offset = buf.len();
        buf.extend_from_slice(b"xref\n");
        let line = format!("0 {}\n", self.objects.len() + 1);
        buf.extend_from_slice(line.as_bytes());
        buf.extend_from_slice(b"0000000000 65535 f \n");
        for off in &offsets {
            let entry = format!("{off:010} 00000 n \n");
            buf.extend_from_slice(entry.as_bytes());
        }

        // Trailer
        let trailer = format!(
            "trailer\n<< /Size {} /Root {} 0 R >>\nstartxref\n{}\n%%EOF\n",
            self.objects.len() + 1,
            catalog_obj,
            xref_offset,
        );
        buf.extend_from_slice(trailer.as_bytes());
        buf
    }
}

/// Escape text for a PDF string literal (parenthesised form).
fn pdf_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '(' | ')' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            _ if c.is_ascii() => out.push(c),
            _ => out.push('?'), // non-ASCII → placeholder
        }
    }
    out
}

/// Build a PDF text stream placing each line with `Td` / `Tj`.
fn build_text_stream(lines: &[String], font_size: f32, leading: f32) -> Vec<u8> {
    let mut stream = String::new();
    stream.push_str("BT\n");
    stream.push_str(&format!("/F1 {font_size} Tf\n"));
    stream.push_str(&format!("{leading} TL\n"));
    stream.push_str("36 756 Td\n"); // start near top-left with margins
    for line in lines {
        stream.push_str(&format!("({}) Tj T*\n", pdf_escape(line)));
    }
    stream.push_str("ET\n");

    let length = stream.len();
    let mut obj = format!("<< /Length {length} >>\nstream\n").into_bytes();
    obj.extend_from_slice(stream.as_bytes());
    obj.extend_from_slice(b"\nendstream");
    obj
}

/// Export results as a PDF 1.4 report (no external dependencies).
pub fn export_pdf(path: &str, report: &Report) -> Result<()> {
    validate_export_path(path)?;
    atomic_write_file(path, |file| {
        let total = report.results.len();
        let successes = report.results.iter().filter(|r| r.success).count();
        let admins = report.results.iter().filter(|r| r.admin).count();
        let failures = total - successes;

        // ── Collect lines for the first content page (summary) ──────
        let mut summary_lines: Vec<String> = vec![
            "NetExec-RS Scan Report".to_string(),
            String::new(),
            format!("Timestamp : {}", report.timestamp),
            format!("Protocol  : {}", report.protocol.to_uppercase()),
            format!("Total     : {}", total),
            format!("Successful: {}", successes),
            format!("Admin     : {}", admins),
            format!("Failed    : {}", failures),
            String::new(),
            "--- Results ---".to_string(),
            String::new(),
            format!(
                "{:<18} {:<16} {:<8} {:<6} {:<10} {}",
                "Target", "Username", "Success", "Admin", "Duration", "Message"
            ),
            "-".repeat(90),
        ];

        for res in &report.results {
            let success_str = if res.success { "YES" } else { "NO" };
            let admin_str = if res.admin { "YES" } else { "-" };
            // Truncate message to keep rows legible
            let msg: String = res.message.chars().take(40).collect();
            summary_lines.push(format!(
                "{:<18} {:<16} {:<8} {:<6} {:<10} {}",
                truncate_str(&res.target, 17),
                truncate_str(&res.username, 15),
                success_str,
                admin_str,
                format!("{}ms", res.duration_ms),
                msg,
            ));
        }

        summary_lines.push(String::new());
        summary_lines.push("Generated by NetExec-RS".to_string());

        // ── Build PDF object tree ───────────────────────────────────
        let mut pdf = PdfWriter::new();

        // 1 – Font (Helvetica, a built-in base-14 font)
        let font_obj =
            pdf.add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec());

        // 2 – Content stream
        let stream = build_text_stream(&summary_lines, 9.0, 11.0);
        let content_obj = pdf.add_object(stream);

        // 3 – Page
        let page_dict = format!(
            "<< /Type /Page /Parent {} 0 R /MediaBox [0 0 612 792] /Contents {} 0 R /Resources << /Font << /F1 {} 0 R >> >> >>",
            content_obj + 1,
            content_obj,
            font_obj,
        );
        let page_obj = pdf.add_object(page_dict.into_bytes());

        // 4 – Pages
        let pages_dict = format!("<< /Type /Pages /Kids [{page_obj} 0 R] /Count 1 >>",);
        let pages_obj = pdf.add_object(pages_dict.into_bytes());

        // Fix page /Parent to point to pages_obj
        let fixed_page = format!(
            "<< /Type /Page /Parent {pages_obj} 0 R /MediaBox [0 0 612 792] /Contents {content_obj} 0 R /Resources << /Font << /F1 {font_obj} 0 R >> >> >>",
        );
        pdf.objects[page_obj - 1] = fixed_page.into_bytes();

        // 5 – Catalog
        let catalog_dict = format!("<< /Type /Catalog /Pages {pages_obj} 0 R >>",);
        let catalog_obj = pdf.add_object(catalog_dict.into_bytes());

        let bytes = pdf.finish(pages_obj, catalog_obj);

        file.write_all(&bytes)?;
        Ok(())
    })
}

/// Truncate a string to at most `max` characters.
fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}~", &s[..max - 1])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_csv_field() {
        assert_eq!(sanitize_csv_field("=cmd|'/C calc'!A0"), "'=cmd|'/C calc'!A0");
        assert_eq!(sanitize_csv_field("+12345"), "'+12345");
        assert_eq!(sanitize_csv_field("-12345"), "'-12345");
        assert_eq!(sanitize_csv_field("@SUM(1+1)"), "'@SUM(1+1)");
        assert_eq!(sanitize_csv_field("normal_user"), "normal_user");
    }

    #[test]
    fn test_sanitize_workspace_name() {
        assert_eq!(sanitize_workspace_name("default"), "default");
        assert_eq!(sanitize_workspace_name("../../secret"), "secret");
        assert_eq!(sanitize_workspace_name("corp_internal-2"), "corp_internal-2");
        assert_eq!(sanitize_workspace_name("!@#$%^"), "default");
    }

    #[test]
    fn test_validate_export_path_traversal() {
        assert!(validate_export_path("../escaped.json").is_err());
        assert!(validate_export_path("reports/../../escaped.json").is_err());
        assert!(validate_export_path("reports/sub/report.json").is_ok());
    }
}
