use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{http::HttpSession, NxcSession};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::info;

pub struct WebFuzzer {}

impl WebFuzzer {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for WebFuzzer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for WebFuzzer {
    fn name(&self) -> &'static str {
        "web_fuzzer"
    }

    fn description(&self) -> &'static str {
        "High-performance asynchronous directory and file brute-forcer."
    }

    fn supported_protocols(&self) -> &[&str] {
        &["http"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption {
                name: "WORDLIST".to_string(),
                description: "Path to wordlist, or 'common' for default".to_string(),
                required: false,
                default: Some("common".to_string()),
            },
            ModuleOption {
                name: "THREADS".to_string(),
                description: "Number of concurrent requests".to_string(),
                required: false,
                default: Some("50".to_string()),
            },
            ModuleOption {
                name: "EXT".to_string(),
                description: "Comma-separated extensions to append (e.g. php,txt)".to_string(),
                required: false,
                default: Some("".to_string()),
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
        let wordlist = opts.get("WORDLIST").map(|s| s.as_str()).unwrap_or("common");
        let threads = opts.get("THREADS").and_then(|s| s.parse::<usize>().ok()).unwrap_or(50);
        
        let extensions: Vec<&str> = opts.get("EXT")
            .map(|s| s.as_str())
            .unwrap_or("")
            .split(',')
            .filter(|s| !s.is_empty())
            .collect();

        let basic_words = vec![
            "admin", "login", "api", "test", "backup", "db", "config", "dev", "staging",
            "dashboard", "manager", "robots.txt", ".git/config", ".env", "server-status",
            "phpmyadmin", "wp-login.php", "wp-admin", "old", "new", "v1", "v2"
        ];

        let words: Vec<String> = if wordlist == "common" {
            basic_words.into_iter().map(|s| s.to_string()).collect()
        } else {
            match std::fs::read_to_string(wordlist) {
                Ok(content) => content.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect(),
                Err(_) => {
                    return Ok(ModuleResult {
                        success: false,
                        output: format!("Failed to read wordlist at {}", wordlist),
                        data: json!({}),
                        credentials: vec![],
                    });
                }
            }
        };

        // Build the target paths incorporating extensions
        let mut target_paths = Vec::new();
        for word in &words {
            target_paths.push(format!("/{}", word));
            for ext in &extensions {
                target_paths.push(format!("/{}.{}", word, ext));
            }
        }

        info!("Starting web fuzzing against {} with {} words across {} threads...", base_url, target_paths.len(), threads);

        let sem = Arc::new(Semaphore::new(threads));
        let mut tasks = Vec::new();

        for path in target_paths {
            let permit = sem.clone().acquire_owned().await.unwrap();
            let url = format!("{}{}", base_url, path);
            let client = http_sess.client.clone();
            let creds = http_sess.credentials.clone();
            
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
                        if status.is_success() || status.is_redirection() || status.as_u16() == 401 || status.as_u16() == 403 {
                            let len = response.content_length().unwrap_or(0);
                            Some((path, status.as_u16(), len))
                        } else {
                            None
                        }
                    },
                    Err(_) => None
                }
            }));
        }

        let mut output = String::from("Discovery Results:\n");
        let mut found_list = Vec::new();
        
        for task in tasks {
            if let Ok(Some((path, status, len))) = task.await {
                output.push_str(&format!("  [+] {:<20} [Status: {}, Size: {} bytes]\n", path, status, len));
                found_list.push(json!({ "path": path, "status": status, "size": len }));
            }
        }

        if found_list.is_empty() {
            output.push_str("  [!] No hidden paths discovered.\n");
        }

        Ok(ModuleResult {
            success: true,
            output,
            data: json!({ "found": found_list }),
            credentials: vec![],
        })
    }
}
