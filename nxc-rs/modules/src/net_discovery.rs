//! # Network Discovery Module
//!
//! Performs host discovery (via ARP) and service fingerprinting on the connected
//! network segment.

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;
use serde_json::json;
use tracing::info;
use std::time::Duration;
use tokio::net::TcpStream;

pub struct NetDiscovery {}

impl NetDiscovery {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for NetDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for NetDiscovery {
    fn name(&self) -> &'static str {
        "net_discovery"
    }

    fn description(&self) -> &'static str {
        "Discovers hosts on the connected network and identifies active services (SMB, SSH, HTTP, etc.)."
    }

    fn supported_protocols(&self) -> &[&str] {
        &["network"]
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
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        info!("Network: Starting discovery...");
        
        let network_session = match session.protocol() {
            "network" => session.downcast_mut::<nxc_protocols::network::NetworkSession>().unwrap(),
            _ => return Err(anyhow::anyhow!("Module only supports Network protocol")),
        };

        // We can't easily get the protocol instance here without a factory or passing it,
        // so we'll instantiate a temporary one for discovery actions.
        let protocol = nxc_protocols::network::NetworkProtocol::new(false, None, false, false, false, true, true);

        let port_str = opts.get("ports").cloned().unwrap_or_else(|| "22,80,443,445,135,5900,3389,5555".into());
        let ports: Vec<(u16, &str)> = port_str.split(',')
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

        let mut output_summary = String::new();
        output_summary.push_str("📡 <b>Proactive Network Discovery</b>\n\n");

        // 1. mDNS Discovery
        info!("Network: Discovering mDNS services...");
        match protocol.discover_mdns().await {
            Ok(mdns_out) if !mdns_out.starts_with("No") => {
                output_summary.push_str("[*] Discovered via mDNS:\n");
                output_summary.push_str(&mdns_out);
                output_summary.push_str("\n\n");
            }
            _ => {}
        }

        // 2. LLMNR Discovery
        info!("Network: Discovering LLMNR hosts...");
        match protocol.discover_llmnr().await {
            Ok(llmnr_out) if !llmnr_out.starts_with("No") => {
                output_summary.push_str("[*] Discovered via LLMNR:\n");
                output_summary.push_str(&llmnr_out);
                output_summary.push_str("\n\n");
            }
            _ => {}
        }

        // 3. Host Discovery using ARP
        let output = tokio::process::Command::new("arp")
            .args(["-a"])
            .output()
            .await?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut hosts = std::collections::HashSet::new();

        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("Interface:") || line.starts_with("Internet Address") {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if !parts.is_empty() {
                let ip = parts[0].trim();
                if ip.chars().all(|c| c.is_ascii_digit() || c == '.') && ip.matches('.').count() == 3 {
                    if !ip.ends_with(".255") && !ip.starts_with("224.") && !ip.starts_with("239.") {
                        hosts.insert(ip.to_string());
                    }
                }
            }
        }

        if hosts.is_empty() {
             output_summary.push_str("[!] No additional hosts found via ARP sweep.\n");
        } else {
            output_summary.push_str(&format!("[*] ARP Sweep: {} potential hosts. Fingerprinting {} ports...\n", hosts.len(), ports.len()));
            
            let mut discovered_services = Vec::new();
            for ip in hosts {
                let mut host_services = Vec::new();
                for (port, name) in &ports {
                    let addr = format!("{}:{}", ip, port);
                    let timeout = Duration::from_millis(400);

                    if let Ok(Ok(_)) = tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
                        host_services.push(json!({ "port": port, "service": name }));
                        output_summary.push_str(&format!("  [+] {}:{} ({})\n", ip, port, name));
                    }
                }
                if !host_services.is_empty() {
                    discovered_services.push(json!({
                        "ip": ip,
                        "services": host_services
                    }));
                }
            }
        }

        Ok(ModuleResult {
            success: true,
            output: output_summary,
            data: json!({}),
        })
    }
}
