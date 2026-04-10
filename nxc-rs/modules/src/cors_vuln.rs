use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{http::HttpSession, NxcSession};
use serde_json::json;
use tracing::info;

pub struct CorsVuln {}

impl CorsVuln {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for CorsVuln {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for CorsVuln {
    fn name(&self) -> &'static str {
        "cors_vuln"
    }

    fn description(&self) -> &'static str {
        "Audits Cross-Origin Resource Sharing (CORS) configurations for dangerous reflections."
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

        info!("Starting CORS configuration audit against {}", base_url);

        let suffix = format!("{scheme}evil.com");
        let test_origins = vec!["https://evil.com".to_string(), "null".to_string(), suffix];

        let mut output = String::from("CORS Audit Results:\n");
        let mut vulnerabilities = Vec::new();

        for origin in &test_origins {
            let mut req = http_sess.client.get(&base_url).header("Origin", origin);

            if let Some(creds) = &http_sess.credentials {
                if let Some(pw) = &creds.password {
                    req = req.basic_auth(&creds.username, Some(pw));
                } else {
                    req = req.basic_auth(&creds.username, None::<&str>);
                }
            }

            if let Ok(res) = req.send().await {
                let allow_origin = res
                    .headers()
                    .get("Access-Control-Allow-Origin")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let allow_creds = res
                    .headers()
                    .get("Access-Control-Allow-Credentials")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("false");

                if allow_origin == origin {
                    output.push_str(&format!(
                        "  [!] VULNERABLE: Origin '{origin}' reflected in Access-Control-Allow-Origin.\n"
                    ));
                    if allow_creds == "true" {
                        output.push_str("      -> CRITICAL: Access-Control-Allow-Credentials is true! Auth hijacking possible.\n");
                    }
                    vulnerabilities.push(json!({
                        "tested_origin": origin,
                        "reflected": true,
                        "allow_credentials": allow_creds == "true"
                    }));
                }
            }
        }

        if vulnerabilities.is_empty() {
            output.push_str("  [+] No CORS misconfigurations detected.\n");
        }

        Ok(ModuleResult {
            success: !vulnerabilities.is_empty(),
            output,
            data: json!({ "cors_vulnerabilities": vulnerabilities }),
            credentials: vec![],
        })
    }
}
