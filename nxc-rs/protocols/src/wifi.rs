//! # WiFi Protocol Handler
//!
//! Handles local WiFi network enumeration, connection, and LAN device sweeping.
//! Relies on native OS utilities like `netsh` and `arp` on Windows.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};

pub struct WifiSession {
    pub target: String,
    pub admin: bool,
}

impl NxcSession for WifiSession {
    fn protocol(&self) -> &'static str {
        "wifi"
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn is_admin(&self) -> bool {
        self.admin
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

pub struct WifiProtocol {
    pub scan: bool,
    pub connect: Option<String>,
    pub devices: bool,
    pub profiles: bool,
    pub dump: bool,
}

impl Default for WifiProtocol {
    fn default() -> Self {
        Self::new(false, None, false, false, false)
    }
}

impl WifiProtocol {
    pub fn new(
        scan: bool,
        connect: Option<String>,
        devices: bool,
        profiles: bool,
        dump: bool,
    ) -> Self {
        Self {
            scan,
            connect,
            devices,
            profiles,
            dump,
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

    /// Dump cleartext passwords for all saved profiles
    async fn dump_profiles(&self) -> Result<String> {
        // First get the profiles list to extract names
        let profiles_output = self.list_profiles().await?;

        let mut dumped_credentials = String::new();
        dumped_credentials.push_str("[*] Extracting Cleartext WiFi Configurations...\n\n");

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
}

#[async_trait]
impl NxcProtocol for WifiProtocol {
    fn name(&self) -> &'static str {
        "wifi"
    }

    fn default_port(&self) -> u16 {
        0
    }

    fn supports_exec(&self) -> bool {
        false
    }

    fn supported_modules(&self) -> &[&str] {
        &["wifi_recon"]
    }

    async fn connect(&self, target: &str, _port: u16) -> Result<Box<dyn NxcSession>> {
        // Since `wifi` actions generally interact with the host interface rather than
        // a remote TCP port, `connect` merely instantiates the session.
        Ok(Box::new(WifiSession {
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
                Ok(out) => final_message.push_str(&format!("\n[WiFi Scan Results]\n{}\n", out)),
                Err(e) => {
                    success = false;
                    final_message.push_str(&format!("\n[WiFi Scan Error] {}\n", e));
                }
            }
        }

        if let Some(ref ssid) = self.connect {
            match self.connect_ssid(ssid).await {
                Ok(out) => final_message.push_str(&format!("\n[WiFi Connect Result]\n{}\n", out)),
                Err(e) => {
                    success = false;
                    final_message.push_str(&format!("\n[WiFi Connect Error] {}\n", e));
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
                Ok(out) => final_message.push_str(&format!("\n[WiFi Profiles]\n{}\n", out)),
                Err(e) => {
                    success = false;
                    final_message.push_str(&format!("\n[WiFi Profiles Error] {}\n", e));
                }
            }
        }

        if self.dump {
            match self.dump_profiles().await {
                Ok(out) => {
                    final_message.push_str(&format!("\n[WiFi Profile Dump]\n{}\n", out));
                    // Because a dump is typically an administrative win context in offensive tooling,
                    // we'll flag it as admin if we successfully dumped any keys (though netsh wlan doesn't
                    // strictly require SYSTEM, just local user access for their own profiles)
                    admin_result = true;
                }
                Err(e) => {
                    success = false;
                    final_message.push_str(&format!("\n[WiFi Dump Error] {}\n", e));
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
        Err(anyhow!("Execute not supported on wifi protocol. Use --scan, --connect, --devices, --profiles, or --dump instead."))
    }
}
