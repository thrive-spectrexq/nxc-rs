//! # WiFi Recon Module
//!
//! Performs host discovery (via ARP) and service fingerprinting on the connected
//! WiFi network.

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;
use serde_json::json;
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::info;

pub struct WifiRecon {}

impl WifiRecon {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for WifiRecon {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for WifiRecon {
    fn name(&self) -> &'static str {
        "wifi_recon"
    }

    fn description(&self) -> &'static str {
        "Discovers hosts on the connected WiFi and identifies active services (SMB, SSH, HTTP, etc.)."
    }

    fn supported_protocols(&self) -> &[&str] {
        &["wifi"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![ModuleOption {
            name: "ports".into(),
            description: "Comma-separated list of ports to scan (e.g. 80,443,445)".into(),
            required: false,
            default: Some("22,80,443,445,135,5900,3389,5555".into()),
        }]
    }

    async fn run(
        &self,
        _session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        info!("WiFi: Starting reconnaissance...");

        let port_str =
            opts.get("ports").cloned().unwrap_or_else(|| "22,80,443,445,135,5900,3389,5555".into());
        let ports: Vec<(u16, &str)> = port_str
            .split(',')
            .filter_map(|s| {
                let p = s.trim().parse::<u16>().ok()?;
                let name = match p {
                    22 => "SSH",
                    80 => "HTTP",
                    443 => "HTTPS",
                    445 => "SMB",
                    135 => "RPC/WMI",
                    5900 => "VNC",
                    3389 => "RDP",
                    5555 => "ADB",
                    _ => "Unknown",
                };
                Some((p, name))
            })
            .collect();

        // 1. Host Discovery using ARP
        let output = tokio::process::Command::new("arp").args(["-a"]).output().await?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut hosts = std::collections::HashSet::new();

        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty()
                || line.starts_with("Interface:")
                || line.starts_with("Internet Address")
            {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if !parts.is_empty() {
                let ip = parts[0].trim();
                // Basic IP validation (v4)
                if ip.chars().all(|c| c.is_ascii_digit() || c == '.')
                    && ip.matches('.').count() == 3
                {
                    // Ignore broadcast/multicast
                    if !ip.ends_with(".255") && !ip.starts_with("224.") && !ip.starts_with("239.") {
                        hosts.insert(ip.to_string());
                    }
                }
            }
        }

        if hosts.is_empty() {
            return Ok(ModuleResult {
                credentials: vec![],
                success: false,
                output: "No hosts discovered on the local network via ARP.".to_string(),
                data: json!({}),
            });
        }

        let mut output_summary = format!(
            "[*] Discovered {} potential hosts. Fingerprinting {} ports...\n",
            hosts.len(),
            ports.len()
        );
        let mut discovered_services = Vec::new();

        for ip in hosts {
            let mut host_services = Vec::new();
            for (port, name) in &ports {
                let addr = format!("{ip}:{port}");
                let timeout = Duration::from_millis(400); // Faster probe

                if let Ok(Ok(_)) = tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
                    host_services.push(json!({ "port": port, "service": name }));
                    output_summary.push_str(&format!("  [+] {ip}:{port} ({name})\n"));
                }
            }
            if !host_services.is_empty() {
                discovered_services.push(json!({
                    "ip": ip,
                    "services": host_services
                }));
            }
        }

        if discovered_services.is_empty() {
            output_summary.push_str("\n[!] No open services found on discovered hosts.");
        }

        Ok(ModuleResult {
            credentials: vec![],
            success: true,
            output: output_summary,
            data: json!({ "hosts": discovered_services }),
        })
    }
}
