//! # Network Protocol Handler
//!
//! Handles local network enumeration, connection, and host discovery.
//! Relies on native OS utilities like `netsh` and `arp` on Windows.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use tracing::debug;

pub struct NetworkSession {
    pub target: String,
    pub admin: bool,
}

impl NxcSession for NetworkSession {
    fn protocol(&self) -> &'static str {
        "network"
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn is_admin(&self) -> bool {
        self.admin
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

pub struct NetworkProtocol {
    pub scan: bool,
    pub connect: Option<String>,
    pub devices: bool,
    pub profiles: bool,
    pub dump: bool,
    pub mdns: bool,
    pub llmnr: bool,
}

impl Default for NetworkProtocol {
    fn default() -> Self {
        Self::new(false, None, false, false, false, false, false)
    }
}

impl NetworkProtocol {
    pub fn new(
        scan: bool,
        connect: Option<String>,
        devices: bool,
        profiles: bool,
        dump: bool,
        mdns: bool,
        llmnr: bool,
    ) -> Self {
        Self {
            scan,
            connect,
            devices,
            profiles,
            dump,
            mdns,
            llmnr,
        }
    }

    /// Perform a WiFi scan using `netsh wlan show networks mode=bssid` (Windows)
    async fn scan_networks(&self) -> Result<String> {
        let output = tokio::process::Command::new("netsh")
            .args(["wlan", "show", "networks", "mode=bssid"])
            .output()
            .await?;

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

        if !output.status.success() {
            let error_msg = if !stderr.is_empty() { stderr } else { stdout };
            return Err(anyhow!("Scan failed: {}", error_msg));
        }

        Ok(stdout)
    }

    /// Connect to a specific SSID using `netsh wlan connect name="..."`
    async fn connect_ssid(&self, ssid: &str) -> Result<String> {
        let output = tokio::process::Command::new("netsh")
            .args(["wlan", "connect", &format!("name={}", ssid)])
            .output()
            .await?;

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

        if !output.status.success() {
            let error_msg = if !stderr.is_empty() { stderr } else { stdout };
            return Err(anyhow!("Connect failed: {}", error_msg));
        }

        Ok(stdout)
    }

    /// Perform a device sweep using `arp -a`
    async fn sweep_devices(&self) -> Result<String> {
        let output = tokio::process::Command::new("arp")
            .args(["-a"])
            .output()
            .await?;

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

        if !output.status.success() {
            let error_msg = if !stderr.is_empty() { stderr } else { stdout };
            return Err(anyhow!("Device sweep failed: {}", error_msg));
        }

        Ok(stdout)
    }

    /// List saved WiFi profiles
    async fn list_profiles(&self) -> Result<String> {
        let output = tokio::process::Command::new("netsh")
            .args(["wlan", "show", "profiles"])
            .output()
            .await?;

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

        if !output.status.success() {
            let error_msg = if !stderr.is_empty() { stderr } else { stdout };
            return Err(anyhow!("List profiles failed: {}", error_msg));
        }

        Ok(stdout)
    }

    async fn dump_profiles(&self) -> Result<String> {
        // First get the profiles list to extract names
        let profiles_output = self.list_profiles().await?;

        let mut dumped_credentials = String::new();
        dumped_credentials.push_str("[*] Extracting Cleartext Wireless Configurations...\n\n");

        for line in profiles_output.lines() {
            if line.contains("All User Profile") || line.contains("Current User Profile") {
                if let Some(profile_name) = line.split(':').nth(1) {
                    let profile_name = profile_name.trim();
                    if profile_name.is_empty() {
                        continue;
                    }

                    // Dump this specific profile
                    let output = tokio::process::Command::new("netsh")
                        .args([
                            "wlan",
                            "show",
                            "profile",
                            &format!("name={}", profile_name),
                            "key=clear",
                        ])
                        .output()
                        .await?;

                    if output.status.success() {
                        let profile_details = String::from_utf8_lossy(&output.stdout);
                        let mut password = "<None or Not Found>";

                        // Parse the key material
                        for detail_line in profile_details.lines() {
                            if detail_line.contains("Key Content") {
                                if let Some(key) = detail_line.split(':').nth(1) {
                                    password = key.trim();
                                    break;
                                }
                            }
                        }

                        dumped_credentials
                            .push_str(&format!("{:<30} : {}\n", profile_name, password));
                    }
                }
            }
        }

        Ok(dumped_credentials.trim_end().to_string())
    }

    /// Perform mDNS discovery (service discovery)
    pub async fn discover_mdns(&self) -> Result<String> {
        use tokio::net::UdpSocket;
        use std::net::SocketAddr;
        
        debug!("Network: Starting mDNS discovery on 224.0.0.251:5353");
        
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.set_broadcast(true)?;
        
        // DNS Service Discovery (PTR record for _services._dns-sd._udp.local)
        let mut query = vec![
            0x00, 0x00, // Transaction ID
            0x00, 0x00, // Flags
            0x00, 0x01, // Questions
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Answers, Authority, Additional
            0x09, b'_', b's', b'e', b'r', b'v', b'i', b'c', b'e', b's',
            0x07, b'_', b'd', b'n', b's', b'-', b's', b'd',
            0x04, b'_', b'u', b'd', b'p',
            0x05, b'l', b'o', b'c', b'a', b'l',
            0x00, 
            0x00, 0x0c, // Type PTR
            0x00, 0x01, // Class IN
        ];
        
        let mcast_addr: SocketAddr = "224.0.0.251:5353".parse()?;
        socket.send_to(&query, mcast_addr).await?;
        
        let mut buf = [0u8; 1024];
        let mut results = Vec::new();
        
        // Listen for 2 seconds
        let timeout = tokio::time::Duration::from_secs(2);
        let start = tokio::time::Instant::now();
        
        while start.elapsed() < timeout {
            if let Ok(Ok((len, addr))) = tokio::time::timeout(tokio::time::Duration::from_millis(500), socket.recv_from(&mut buf)).await {
                results.push(format!("  {} respondió con {} bytes", addr, len));
            }
        }
        
        if results.is_empty() {
            Ok("No mDNS responders found.".to_string())
        } else {
            Ok(results.join("\n"))
        }
    }

    /// Perform LLMNR discovery (host discovery)
    pub async fn discover_llmnr(&self) -> Result<String> {
        use tokio::net::UdpSocket;
        use std::net::SocketAddr;
        
        debug!("Network: Starting LLMNR discovery on 224.0.0.252:5355");
        
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        
        // LLMNR Query for "*" (any)
        let mut query = vec![
            0xda, 0xda, // Transaction ID
            0x00, 0x00, // Flags
            0x00, 0x01, // Questions
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Answers, Authority, Additional
            0x01, b'*', 0x00,
            0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
        ];
        
        let mcast_addr: SocketAddr = "224.0.0.252:5355".parse()?;
        socket.send_to(&query, mcast_addr).await?;
        
        let mut buf = [0u8; 1024];
        let mut results = Vec::new();
        
        let timeout = tokio::time::Duration::from_secs(2);
        let start = tokio::time::Instant::now();
        
        while start.elapsed() < timeout {
            if let Ok(Ok((len, addr))) = tokio::time::timeout(tokio::time::Duration::from_millis(500), socket.recv_from(&mut buf)).await {
                results.push(format!("  {} respondió con {} bytes", addr, len));
            }
        }
        
        if results.is_empty() {
            Ok("No LLMNR responders found.".to_string())
        } else {
            Ok(results.join("\n"))
        }
    }
}

#[async_trait]
impl NxcProtocol for NetworkProtocol {
    fn name(&self) -> &'static str {
        "network"
    }

    fn default_port(&self) -> u16 {
        0
    }

    fn supports_exec(&self) -> bool {
        false
    }

    fn supported_modules(&self) -> &[&str] {
        &["net_discovery"]
    }

    async fn connect(&self, target: &str, _port: u16) -> Result<Box<dyn NxcSession>> {
        // Since `network` actions generally interact with the host interface rather than
        // a remote TCP port, `connect` merely instantiates the session.
        Ok(Box::new(NetworkSession {
            target: target.to_string(),
            admin: false,
        }))
    }

    async fn authenticate(
        &self,
        _session: &mut dyn NxcSession,
        _creds: &Credentials,
    ) -> Result<AuthResult> {
        let mut final_message = String::new();
        let mut success = true;
        let mut admin_result = false;

        if self.scan {
            match self.scan_networks().await {
                Ok(out) => final_message.push_str(&format!("\n[Network Scan Results]\n{}\n", out)),
                Err(e) => {
                    success = false;
                    final_message.push_str(&format!("\n[Network Scan Error] {}\n", e));
                }
            }
        }

        if let Some(ref ssid) = self.connect {
            match self.connect_ssid(ssid).await {
                Ok(out) => final_message.push_str(&format!("\n[Network Connect Result]\n{}\n", out)),
                Err(e) => {
                    success = false;
                    final_message.push_str(&format!("\n[Network Connect Error] {}\n", e));
                }
            }
        }

        if self.devices {
            match self.sweep_devices().await {
                Ok(out) => final_message.push_str(&format!("\n[ARP Sweep Results]\n{}\n", out)),
                Err(e) => {
                    success = false;
                    final_message.push_str(&format!("\n[ARP Sweep Error] {}\n", e));
                }
            }
        }

        if self.profiles {
            match self.list_profiles().await {
                Ok(out) => final_message.push_str(&format!("\n[Network Profiles]\n{}\n", out)),
                Err(e) => {
                    success = false;
                    final_message.push_str(&format!("\n[Network Profiles Error] {}\n", e));
                }
            }
        }

        if self.dump {
            match self.dump_profiles().await {
                Ok(out) => {
                    final_message.push_str(&format!("\n[Network Configuration Dump]\n{}\n", out));
                    admin_result = true;
                }
                Err(e) => {
                    success = false;
                    final_message.push_str(&format!("\n[Network Dump Error] {}\n", e));
                }
            }
        }

        if self.mdns {
            match self.discover_mdns().await {
                Ok(out) => final_message.push_str(&format!("\n[mDNS Discovery Results]\n{}\n", out)),
                Err(e) => {
                    success = false;
                    final_message.push_str(&format!("\n[mDNS Error] {}\n", e));
                }
            }
        }

        if self.llmnr {
            match self.discover_llmnr().await {
                Ok(out) => final_message.push_str(&format!("\n[LLMNR Discovery Results]\n{}\n", out)),
                Err(e) => {
                    success = false;
                    final_message.push_str(&format!("\n[LLMNR Error] {}\n", e));
                }
            }
        }

        if final_message.is_empty() {
            final_message = "No specific actions requested (use --scan, --connect, --devices, --profiles, or --dump).".to_string();
        }

        if success {
            Ok(AuthResult {
                success: true,
                admin: admin_result,
                message: final_message,
                error_code: None,
            })
        } else {
            Ok(AuthResult::failure(&final_message, None))
        }
    }

    async fn execute(&self, _session: &dyn NxcSession, _cmd: &str) -> Result<CommandOutput> {
        Err(anyhow!("Execute not supported on network protocol. Use --scan, --connect, --devices, --profiles, or --dump instead."))
    }
}
