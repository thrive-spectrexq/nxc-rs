use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{http::HttpSession, NxcSession};
use reqwest::header::HOST;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::info;

pub struct VhostEnum {}

impl VhostEnum {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for VhostEnum {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for VhostEnum {
    fn name(&self) -> &'static str {
        "vhost_enum"
    }

    fn description(&self) -> &'static str {
        "Enumerates virtual hosts on the target IP using the Host header."
    }

    fn supported_protocols(&self) -> &[&str] {
        &["http"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption {
                name: "DOMAIN".to_string(),
                description: "Base domain to append (e.g., example.com)".to_string(),
                required: true,
                default: None,
            },
            ModuleOption {
                name: "WORDLIST".to_string(),
                description: "Path to subdomains wordlist, or 'common' for default".to_string(),
                required: false,
                default: Some("common".to_string()),
            },
            ModuleOption {
                name: "THREADS".to_string(),
                description: "Number of concurrent requests".to_string(),
                required: false,
                default: Some("50".to_string()),
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
        let base_url = format!("{}://{}:{}", scheme, http_sess.target, http_sess.port);

        let domain =
            opts.get("DOMAIN").ok_or_else(|| anyhow!("DOMAIN is required for vhost enum"))?;
        let wordlist = opts.get("WORDLIST").map(std::string::String::as_str).unwrap_or("common");
        let threads = opts.get("THREADS").and_then(|s| s.parse::<usize>().ok()).unwrap_or(50);

        let basic_words = vec![
            "www",
            "dev",
            "staging",
            "test",
            "api",
            "admin",
            "mail",
            "portal",
            "vpn",
            "secure",
            "internal",
            "intranet",
            "auth",
            "sso",
            "blog",
            "shop",
            "app",
            "beta",
            "jira",
            "confluence",
            "git",
            "gitlab",
            "jenkins",
            "docker",
        ];

        let subdomains: Vec<String> = if wordlist == "common" {
            basic_words.into_iter().map(std::string::ToString::to_string).collect()
        } else {
            match std::fs::read_to_string(wordlist) {
                Ok(content) => content
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty())
                    .collect(),
                Err(_) => {
                    return Ok(ModuleResult {
                        success: false,
                        output: format!("Failed to read wordlist at {wordlist}"),
                        data: json!({}),
                        credentials: vec![],
                    });
                }
            }
        };

        info!(
            "Starting vHost enumeration against {} for domain {} with {} words",
            base_url,
            domain,
            subdomains.len()
        );

        // First establish baseline response size for an invalid vHost
        let baseline_host = format!("nonexistent123randomizerxyz.{domain}");
        let mut baseline_len = 0;
        let mut baseline_status = 0;

        if let Ok(res) = http_sess.client.get(&base_url).header(HOST, baseline_host).send().await {
            baseline_status = res.status().as_u16();
            baseline_len = res.content_length().unwrap_or(0);
        }

        let sem = Arc::new(Semaphore::new(threads));
        let mut tasks = Vec::new();

        for sub in subdomains {
            let permit = sem.clone().acquire_owned().await.unwrap_or_else(|_| panic!("Failed to acquire semaphore"));
            let url = base_url.clone();
            let client = http_sess.client.clone();
            let vhost = format!("{sub}.{domain}");
            let creds = http_sess.credentials.clone();

            tasks.push(tokio::spawn(async move {
                let mut req = client.get(&url).header(HOST, &vhost);
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
                        let status = response.status().as_u16();
                        let mut len = response.content_length().unwrap_or(0);

                        if len == 0 {
                            if let Ok(b) = response.text().await {
                                len = b.len() as u64;
                            }
                        }

                        // Compare with baseline
                        if status != baseline_status || len != baseline_len {
                            Some((vhost, status, len))
                        } else {
                            None
                        }
                    }
                    Err(_) => None,
                }
            }));
        }

        let mut output = String::from("vHost Discovery Results:\n");
        let mut found_list = Vec::new();

        for task in tasks {
            if let Ok(Some((vhost, status, len))) = task.await {
                output.push_str(&format!(
                    "  [+] {vhost:<30} [Status: {status}, Size: {len} bytes]\n"
                ));
                found_list.push(json!({ "vhost": vhost, "status": status, "size": len }));
            }
        }

        if found_list.is_empty() {
            output.push_str("  [!] No hidden vHosts discovered.\n");
        }

        Ok(ModuleResult {
            success: true,
            output,
            data: json!({ "found": found_list }),
            credentials: vec![],
        })
    }
}
