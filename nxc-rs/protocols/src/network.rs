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
        Self { scan, connect, devices, profiles, dump, mdns, llmnr }
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
            return Err(anyhow!("Scan failed: {error_msg}"));
        }

        Ok(stdout)
    }

    /// Connect to a specific SSID using `netsh wlan connect name="..."`
    async fn connect_ssid(&self, ssid: &str) -> Result<String> {
        let output = tokio::process::Command::new("netsh")
            .args(["wlan", "connect", &format!("name={ssid}")])
            .output()
            .await?;

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

        if !output.status.success() {
            let error_msg = if !stderr.is_empty() { stderr } else { stdout };
            return Err(anyhow!("Connect failed: {error_msg}"));
        }

        Ok(stdout)
    }

    /// Perform a device sweep using `arp -a`
    async fn sweep_devices(&self) -> Result<String> {
        let output = tokio::process::Command::new("arp").args(["-a"]).output().await?;

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

        if !output.status.success() {
            let error_msg = if !stderr.is_empty() { stderr } else { stdout };
            return Err(anyhow!("Device sweep failed: {error_msg}"));
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
            return Err(anyhow!("List profiles failed: {error_msg}"));
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
                            &format!("name={profile_name}"),
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

                        dumped_credentials.push_str(&format!("{profile_name:<30} : {password}\n"));
                    }
                }
            }
        }

        Ok(dumped_credentials.trim_end().to_string())
    }

    /// Perform mDNS discovery (service discovery)
    pub async fn discover_mdns(&self) -> Result<String> {
        use std::net::SocketAddr;
        use tokio::net::UdpSocket;

        debug!("Network: Starting mDNS discovery on 224.0.0.251:5353");

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.set_broadcast(true)?;

        // DNS Service Discovery (PTR record for _services._dns-sd._udp.local)
        let query = vec![
            0x00, 0x00, // Transaction ID
            0x00, 0x00, // Flags
            0x00, 0x01, // Questions
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Answers, Authority, Additional
            0x09, b'_', b's', b'e', b'r', b'v', b'i', b'c', b'e', b's', 0x07, b'_', b'd', b'n',
            b's', b'-', b's', b'd', 0x04, b'_', b'u', b'd', b'p', 0x05, b'l', b'o', b'c', b'a',
            b'l', 0x00, 0x00, 0x0c, // Type PTR
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
            if let Ok(Ok((len, addr))) = tokio::time::timeout(
                tokio::time::Duration::from_millis(500),
                socket.recv_from(&mut buf),
            )
            .await
            {
                let parsed = parse_dns_response(&buf[..len]);
                if !parsed.is_empty() {
                    results.push(format!("  {} -> {}", addr, parsed.join(", ")));
                } else {
                    results.push(format!("  {addr} responded with {len} bytes (unknown format)"));
                }
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
        use std::net::SocketAddr;
        use tokio::net::UdpSocket;

        debug!("Network: Starting LLMNR discovery on 224.0.0.252:5355");

        let socket = UdpSocket::bind("0.0.0.0:0").await?;

        // LLMNR Query for "*" (any)
        let query = vec![
            0xda, 0xda, // Transaction ID
            0x00, 0x00, // Flags
            0x00, 0x01, // Questions
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Answers, Authority, Additional
            0x01, b'*', 0x00, 0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
        ];

        let mcast_addr: SocketAddr = "224.0.0.252:5355".parse()?;
        socket.send_to(&query, mcast_addr).await?;

        let mut buf = [0u8; 1024];
        let mut results = Vec::new();

        let timeout = tokio::time::Duration::from_secs(2);
        let start = tokio::time::Instant::now();

        while start.elapsed() < timeout {
            if let Ok(Ok((len, addr))) = tokio::time::timeout(
                tokio::time::Duration::from_millis(500),
                socket.recv_from(&mut buf),
            )
            .await
            {
                let parsed = parse_dns_response(&buf[..len]);
                if !parsed.is_empty() {
                    results.push(format!("  {} -> {}", addr, parsed.join(", ")));
                } else {
                    results.push(format!("  {addr} responded with {len} bytes (unknown format)"));
                }
            }
        }

        if results.is_empty() {
            Ok("No LLMNR responders found.".to_string())
        } else {
            Ok(results.join("\n"))
        }
    }
}

fn parse_dns_response(buf: &[u8]) -> Vec<String> {
    if buf.len() < 12 {
        return Vec::new();
    }

    let answers_count = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    if answers_count == 0 {
        return Vec::new();
    }

    let mut names = Vec::new();
    let mut offset = 12;

    let questions_count = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    for _ in 0..questions_count {
        offset = skip_name(buf, offset);
        offset += 4;
        if offset >= buf.len() {
            return names;
        }
    }

    for _i in 0..answers_count {
        if offset >= buf.len() {
            break;
        }
        let (name, next_offset) = parse_name(buf, offset);
        offset = next_offset;

        if offset + 10 > buf.len() {
            break;
        }
        let rtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let rdlength = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlength > buf.len() {
            break;
        }

        match rtype {
            0x000c => {
                // PTR
                let (ptr_name, _) = parse_name(buf, offset);
                if !ptr_name.is_empty() {
                    names.push(ptr_name);
                }
            }
            0x0001 => {
                // A
                if !name.is_empty() && name != "*" {
                    names.push(name.clone());
                }
            }
            _ => {}
        }
        offset += rdlength;
    }

    names
}

fn skip_name(buf: &[u8], mut offset: usize) -> usize {
    while offset < buf.len() {
        let len = buf[offset] as usize;
        if len == 0 {
            return offset + 1;
        }
        if (len & 0xc0) == 0xc0 {
            return offset + 2;
        }
        offset += len + 1;
    }
    offset
}

fn parse_name(buf: &[u8], mut offset: usize) -> (String, usize) {
    let mut name = String::new();
    let mut jumped = false;
    let mut final_next_offset = 0;

    let mut safety = 0;
    while offset < buf.len() && safety < 10 {
        safety += 1;
        let len = buf[offset] as usize;
        if len == 0 {
            if !jumped {
                final_next_offset = offset + 1;
            }
            offset += 1;
            break;
        }

        if (len & 0xc0) == 0xc0 {
            if offset + 1 >= buf.len() {
                break;
            }
            let ptr = ((len & 0x3f) << 8) | (buf[offset + 1] as usize);
            if !jumped {
                final_next_offset = offset + 2;
                jumped = true;
            }
            offset = ptr;
            continue;
        }

        offset += 1;
        if offset + len > buf.len() {
            break;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(&buf[offset..offset + len]));
        offset += len;
    }

    let next_offset = if jumped { final_next_offset } else { offset };
    (name, next_offset)
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
        ["net_discovery"].as_slice()
    }

    async fn connect(
        &self,
        target: &str,
        _port: u16,
        _proxy: Option<&str>,
    ) -> Result<Box<dyn NxcSession>> {
        // Since `network` actions generally interact with the host interface rather than
        // a remote TCP port, `connect` merely instantiates the session.
        Ok(Box::new(NetworkSession { target: target.to_string(), admin: false }))
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
                Ok(out) => final_message.push_str(&format!("\n[Network Scan Results]\n{out}\n")),
                Err(e) => {
                    success = false;
                    final_message.push_str(&format!("\n[Network Scan Error] {e}\n"));
                }
            }
        }

        if let Some(ref ssid) = self.connect {
            match self.connect_ssid(ssid).await {
                Ok(out) => final_message.push_str(&format!("\n[Network Connect Result]\n{out}\n")),
                Err(e) => {
                    success = false;
                    final_message.push_str(&format!("\n[Network Connect Error] {e}\n"));
                }
            }
        }

        if self.devices {
            match self.sweep_devices().await {
                Ok(out) => final_message.push_str(&format!("\n[ARP Sweep Results]\n{out}\n")),
                Err(e) => {
                    success = false;
                    final_message.push_str(&format!("\n[ARP Sweep Error] {e}\n"));
                }
            }
        }

        if self.profiles {
            match self.list_profiles().await {
                Ok(out) => final_message.push_str(&format!("\n[Network Profiles]\n{out}\n")),
                Err(e) => {
                    success = false;
                    final_message.push_str(&format!("\n[Network Profiles Error] {e}\n"));
                }
            }
        }

        if self.dump {
            match self.dump_profiles().await {
                Ok(out) => {
                    final_message.push_str(&format!("\n[Network Configuration Dump]\n{out}\n"));
                    admin_result = true;
                }
                Err(e) => {
                    success = false;
                    final_message.push_str(&format!("\n[Network Dump Error] {e}\n"));
                }
            }
        }

        if self.mdns {
            match self.discover_mdns().await {
                Ok(out) => final_message.push_str(&format!("\n[mDNS Discovery Results]\n{out}\n")),
                Err(e) => {
                    success = false;
                    final_message.push_str(&format!("\n[mDNS Error] {e}\n"));
                }
            }
        }

        if self.llmnr {
            match self.discover_llmnr().await {
                Ok(out) => final_message.push_str(&format!("\n[LLMNR Discovery Results]\n{out}\n")),
                Err(e) => {
                    success = false;
                    final_message.push_str(&format!("\n[LLMNR Error] {e}\n"));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns_response_ptr() {
        // PTR response for _services._dns-sd._udp.local -> _printer._tcp.local
        let buf = vec![
            0x00, 0x00, // ID
            0x84, 0x00, // Flags (Standard query response, No error)
            0x00, 0x00, // Questions
            0x00, 0x01, // Answers
            0x00, 0x00, 0x00, 0x00, // Auth, Add
            // Answer: _services._dns-sd._udp.local (PTR) -> _printer._tcp.local
            0x09, b'_', b's', b'e', b'r', b'v', b'i', b'c', b'e', b's', 0x07, b'_', b'd', b'n',
            b's', b'-', b's', b'd', 0x04, b'_', b'u', b'd', b'p', 0x05, b'l', b'o', b'c', b'a',
            b'l', 0x00, 0x00, 0x0c, // Type PTR
            0x00, 0x01, // Class IN
            0x00, 0x00, 0x00, 0x3c, // TTL
            0x00, 0x10, // Data Length (16)
            0x08, b'_', b'p', b'r', b'i', b'n', b't', b'e', b'r', 0x04, b'_', b't', b'c', b'p',
            0xc0, 0x23, // Pointer to "local" at offset 35
        ];

        let result = parse_dns_response(&buf);
        assert!(!result.is_empty());
        assert!(result.contains(&"_printer._tcp.local".to_string()));
    }
}
