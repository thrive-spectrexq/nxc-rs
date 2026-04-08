use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{http::HttpSession, NxcSession};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::info;

pub struct WebVuln {}

impl WebVuln {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for WebVuln {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for WebVuln {
    fn name(&self) -> &'static str {
        "web_vuln"
    }

    fn description(&self) -> &'static str {
        "Scans for rapid, high-impact web misconfigurations and CVE exposures."
    }

    fn supported_protocols(&self) -> &[&str] {
        &["http"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![] // Future options could include specific CVE toggles
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

        info!("Starting rapid vulnerability scan against {}", base_url);

        let checks = vec![
            (
                "/.git/config",
                "repositoryformatversion",
                "Exposed .git directory",
            ),
            ("/.env", "APP_ENV", "Exposed .env file"),
            ("/.env", "DB_PASSWORD", "Exposed .env file"),
            (
                "/server-status",
                "Apache Status",
                "Exposed Apache server-status",
            ),
            (
                "/actuator/env",
                "java.version",
                "Spring Boot Actuator exposed",
            ),
            ("/WEB-INF/web.xml", "<web-app", "Exposed WEB-INF"),
            (
                "/backup.zip",
                "",
                "Possible Backup file exposed (Check size)",
            ),
            (
                "/etc/passwd",
                "root:x:0:0",
                "LFI / Path Traversal successful",
            ),
            (
                "/../../../../etc/passwd",
                "root:x:0:0",
                "Path Traversal successful",
            ),
            ("/phpinfo.php", "PHP Version", "Exposed phpinfo"),
        ];

        let threads = 10;
        let sem = Arc::new(Semaphore::new(threads));
        let mut tasks = Vec::new();

        for (path, signature, desc) in checks {
            let permit = sem.clone().acquire_owned().await.unwrap();
            let url = format!("{}{}", base_url, path);
            let client = http_sess.client.clone();
            let creds = http_sess.credentials.clone();
            let signature = signature.to_string();
            let desc = desc.to_string();

            tasks.push(tokio::spawn(async move {
                let mut req = client.get(&url);
                if let Some(c) = creds {
                    if let Some(pw) = &c.password {
                        req = req.basic_auth(&c.username, Some(pw));
                    } else {
                        req = req.basic_auth(&c.username, None::<&str>);
                    }
                }

                let res = req.send().await;
                drop(permit);

                match res {
                    Ok(response) => {
                        let status = response.status();
                        if status.is_success() {
                            if signature.is_empty() {
                                return Some((path, desc));
                            } else {
                                // Try to body match
                                if let Ok(body) = response.text().await {
                                    if body.contains(&signature) {
                                        return Some((path, desc));
                                    }
                                }
                            }
                        }
                        None
                    }
                    Err(_) => None,
                }
            }));
        }

        let mut output = String::from("Vulnerability Scan Results:\n");
        let mut found = Vec::new();

        for task in tasks {
            if let Ok(Some((path, desc))) = task.await {
                output.push_str(&format!("  [!] VULN FOUND: {} at {}\n", desc, path));
                found.push(json!({"path": path, "vuln": desc}));
            }
        }

        if found.is_empty() {
            output.push_str("  [✓] No trivial web exposures detected.\n");
        }

        Ok(ModuleResult {
            success: true,
            output,
            data: json!({ "vulnerabilities": found }),
            credentials: vec![],
        })
    }
}
