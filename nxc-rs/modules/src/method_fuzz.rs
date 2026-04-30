use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{http::HttpSession, NxcSession};
use serde_json::json;
use tracing::info;

pub struct MethodFuzz {}

impl MethodFuzz {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for MethodFuzz {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for MethodFuzz {
    fn name(&self) -> &'static str {
        "method_fuzz"
    }

    fn description(&self) -> &'static str {
        "Fuzzes standard and non-standard HTTP methods to find dangerous allowed verbs."
    }

    fn supported_protocols(&self) -> &[&str] {
        &["http"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![ModuleOption {
            name: "PATH".to_string(),
            description: "Endpoint path to fuzz (default /)".to_string(),
            required: false,
            default: Some("/".to_string()),
        }]
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

        let path = opts.get("PATH").map(std::string::String::as_str).unwrap_or("/");
        let scheme = if http_sess.use_ssl { "https" } else { "http" };
        let url = format!("{}://{}:{}{}", scheme, http_sess.target, http_sess.port, path);

        info!("Starting HTTP Method Fuzzing against {}", url);

        let test_methods = vec![
            ("GET", reqwest::Method::GET),
            ("POST", reqwest::Method::POST),
            ("PUT", reqwest::Method::PUT),
            ("DELETE", reqwest::Method::DELETE),
            ("OPTIONS", reqwest::Method::OPTIONS),
            ("HEAD", reqwest::Method::HEAD),
            ("TRACE", reqwest::Method::TRACE),
            ("PATCH", reqwest::Method::PATCH),
            ("CONNECT", reqwest::Method::CONNECT),
        ];

        let mut output = String::from("Method Fuzzing Results:\n");
        let mut allowed_methods = Vec::new();

        for (name, method) in test_methods {
            let mut req = http_sess.client.request(method.clone(), &url);

            if let Some(creds) = &http_sess.credentials {
                if let Some(pw) = &creds.password {
                    req = req.basic_auth(&creds.username, Some(pw));
                } else {
                    req = req.basic_auth(&creds.username, None::<&str>);
                }
            }

            if let Ok(res) = req.send().await {
                let status = res.status();

                // HTTP 405 Method Not Allowed naturally implies rejection
                // HTTP 501 Not Implemented implies rejection
                // If it isn't rejected, it is allowed or gracefully falls back
                if status != reqwest::StatusCode::METHOD_NOT_ALLOWED
                    && status != reqwest::StatusCode::NOT_IMPLEMENTED
                {
                    allowed_methods.push(json!({
                        "method": name,
                        "status_code": status.as_u16(),
                    }));
                    output.push_str(&format!(
                        "  [+] {} allowed! (Status: {})\n",
                        name,
                        status.as_str()
                    ));

                    if name == "TRACE" && status.is_success() {
                        output.push_str(
                            "      -> CRITICAL: TRACE is enabled (Potential XST Vulnerability!)\n",
                        );
                    }
                    if (name == "PUT" || name == "DELETE") && status.is_success() {
                        output.push_str(&format!("      -> HIGH: {name} is functionally allowed! File modification may be possible.\n"));
                    }
                } else {
                    output.push_str(&format!(
                        "  [-] {} cleanly rejected (Status: {}).\n",
                        name,
                        status.as_str()
                    ));
                }
            }
        }

        Ok(ModuleResult {
            success: !allowed_methods.is_empty(),
            output,
            data: json!({ "allowed_methods": allowed_methods }),
            credentials: vec![],
        })
    }
}
