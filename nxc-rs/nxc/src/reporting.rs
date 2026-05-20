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
    let font_obj = pdf.add_object(
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec(),
    );

    // 2 – Content stream
    let stream = build_text_stream(&summary_lines, 9.0, 11.0);
    let content_obj = pdf.add_object(stream);

    // 3 – Page
    // We will fix up /Parent after creating Pages object
    let page_dict = format!(
        "<< /Type /Page /Parent {} 0 R /MediaBox [0 0 612 792] /Contents {} 0 R /Resources << /Font << /F1 {} 0 R >> >> >>",
        content_obj + 1, // pages_obj will be next
        content_obj,
        font_obj,
    );
    let page_obj = pdf.add_object(page_dict.into_bytes());

    // 4 – Pages
    let pages_dict = format!(
        "<< /Type /Pages /Kids [{page_obj} 0 R] /Count 1 >>",
    );
    let pages_obj = pdf.add_object(pages_dict.into_bytes());

    // Fix page /Parent to point to pages_obj
    let fixed_page = format!(
        "<< /Type /Page /Parent {pages_obj} 0 R /MediaBox [0 0 612 792] /Contents {content_obj} 0 R /Resources << /Font << /F1 {font_obj} 0 R >> >> >>",
    );
    pdf.objects[page_obj - 1] = fixed_page.into_bytes();

    // 5 – Catalog
    let catalog_dict = format!(
        "<< /Type /Catalog /Pages {pages_obj} 0 R >>",
    );
    let catalog_obj = pdf.add_object(catalog_dict.into_bytes());

    let bytes = pdf.finish(pages_obj, catalog_obj);

    let mut file = File::create(path)?;
    file.write_all(&bytes)?;
    file.flush()?;
    Ok(())
}

/// Truncate a string to at most `max` characters.
fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}~", &s[..max - 1])
    }
}
