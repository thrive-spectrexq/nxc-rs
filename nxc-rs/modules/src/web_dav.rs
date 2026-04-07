use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{http::HttpSession, NxcSession};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

pub struct WebDav {}

impl WebDav {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for WebDav {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for WebDav {
    fn name(&self) -> &'static str {
        "web_dav"
    }

    fn description(&self) -> &'static str {
        "Enumerates WebDAV configurations and attempts benign file uploads."
    }

    fn supported_protocols(&self) -> &[&str] {
        &["http"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        _opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let http_sess = session
            .as_any_mut()
            .downcast_mut::<HttpSession>()
            .ok_or_else(|| anyhow!("Module requires an HTTP session"))?;

        let scheme = if http_sess.use_ssl { "https" } else { "http" };
        let base_url = format!("{}://{}:{}", scheme, http_sess.target, http_sess.port);
        
        info!("Starting WebDAV Enumeration against {}", base_url);

        let mut output = String::from("WebDAV Enumeration Results:\n");
        let mut dav_enabled = false;
        let mut can_upload = false;

        // 1. Send OPTIONS request
        let mut req_options = http_sess.client.request(reqwest::Method::OPTIONS, &base_url);
        if let Some(creds) = &http_sess.credentials {
            if let Some(pw) = &creds.password {
                req_options = req_options.basic_auth(&creds.username, Some(pw));
            } else {
                req_options = req_options.basic_auth(&creds.username, None::<&str>);
            }
        }

        if let Ok(res) = req_options.send().await {
            let allow_header = res.headers().get("Allow").and_then(|v| v.to_str().ok()).unwrap_or("");
            let dav_header = res.headers().get("DAV").and_then(|v| v.to_str().ok()).unwrap_or("");

            if !dav_header.is_empty() || allow_header.contains("PROPFIND") {
                dav_enabled = true;
                output.push_str(&format!("  [!] WebDAV appears ENABLED.\n      DAV Header: {}\n      Allow Header: {}\n", dav_header, allow_header));
            } else {
                output.push_str("  [-] WebDAV does not appear to be natively advertised at the root.\n");
            }
        }

        // 2. Regardless of OPTIONS result, forcibly attempt a PUT to check for write access.
        let epoch = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let filename = format!("test_{}.txt", epoch);
        let upload_url = format!("{}/{}", base_url, filename);
        let payload = "NetExec-RS WebDAV Test File\n";

        let mut req_put = http_sess.client.put(&upload_url).body(payload.to_string());
        if let Some(creds) = &http_sess.credentials {
            if let Some(pw) = &creds.password {
                req_put = req_put.basic_auth(&creds.username, Some(pw));
            } else {
                req_put = req_put.basic_auth(&creds.username, None::<&str>);
            }
        }

        if let Ok(res) = req_put.send().await {
            let status = res.status();
            if status.is_success() || status.as_u16() == 201 { // 201 Created
               can_upload = true;
               output.push_str(&format!("  [!] CRITICAL: Arbitrary file upload successful via PUT!\n      File created at: {}\n", upload_url));
               
               // Attempt cleanup
               let _ = http_sess.client.request(reqwest::Method::DELETE, &upload_url).send().await;
            } else {
                output.push_str(&format!("  [-] File upload failed via PUT (Status: {}).\n", status));
            }
        }

        Ok(ModuleResult {
            success: can_upload || dav_enabled,
            output,
            data: json!({
                "webdav_enabled": dav_enabled,
                "upload_vulnerable": can_upload
            }),
            credentials: vec![],
        })
    }
}
