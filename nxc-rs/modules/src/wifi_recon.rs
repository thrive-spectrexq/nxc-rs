//! # WiFi Recon Module
//!
//! Performs host discovery (via ARP) and service fingerprinting on the connected 
//! WiFi network.

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;
use serde_json::json;
use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use tokio::net::TcpStream;
use std::time::Duration;

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
        vec![]
    }

    async fn run(&self, _session: &mut dyn NxcSession, _opts: &ModuleOptions) -> Result<ModuleResult> {
        println!("[*] Starting WiFi reconnaissance...");

        // 1. Host Discovery using ARP
        let output = tokio::process::Command::new("arp")
            .args(&["-a"])
            .output()
            .await?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut hosts = Vec::new();

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let ip = parts[0].trim();
                // Basic IP validation
                if ip.chars().all(|c| c.is_digit(10) || c == '.') && ip.count_matches('.') == 3 {
                    hosts.push(ip.to_string());
                }
            }
        }

        if hosts.is_empty() {
            return Ok(ModuleResult {
                success: false,
                output: "No hosts discovered on the network.".to_string(),
                data: json!({}),
            });
        }

        println!("[+] Discovered {} potential hosts. Fingerprinting common services...", hosts.len());

        // 2. Service Fingerprinting
        let ports = vec![
            (22, "SSH"),
            (80, "HTTP"),
            (443, "HTTPS"),
            (445, "SMB"),
            (135, "WMI/RPC"),
            (5900, "VNC"),
            (3389, "RDP"),
            (5555, "ADB"),
        ];

        let mut discovered_services = Vec::new();
        let mut output_summary = String::from("Services discovered:\n");

        for ip in hosts {
            let mut host_services = Vec::new();
            for (port, name) in &ports {
                let addr = format!("{}:{}", ip, port);
                let timeout = Duration::from_millis(500); // Fast probe
                
                if let Ok(Ok(_)) = tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
                    host_services.push(json!({ "port": port, "service": name }));
                    output_summary.push_str(&format!("[+] {}:{} ({})\n", ip, port, name));
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
            output_summary.push_str("No open services found on discovered hosts.");
        }

        Ok(ModuleResult {
            success: true,
            output: output_summary,
            data: json!({ "hosts": discovered_services }),
        })
    }
}
