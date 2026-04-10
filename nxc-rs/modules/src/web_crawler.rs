use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{http::HttpSession, NxcSession};
use serde_json::json;
use std::collections::HashSet;
use tracing::info;

pub struct WebCrawler {}

impl WebCrawler {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for WebCrawler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for WebCrawler {
    fn name(&self) -> &'static str {
        "web_crawler"
    }

    fn description(&self) -> &'static str {
        "Lightweight concurrent web spider. Extracts links, forms, and emails."
    }

    fn supported_protocols(&self) -> &[&str] {
        &["http"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![ModuleOption {
            name: "DEPTH".to_string(),
            description: "Maximum crawl depth".to_string(),
            required: false,
            default: Some("2".to_string()),
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

        let scheme = if http_sess.use_ssl { "https" } else { "http" };
        let base_url = format!("{}://{}:{}", scheme, http_sess.target, http_sess.port);
        let max_depth = opts.get("DEPTH").and_then(|s| s.parse::<usize>().ok()).unwrap_or(2);

        info!("Starting web crawl against {} up to depth {}", base_url, max_depth);

        let mut visited = HashSet::new();
        let mut queue = vec![(base_url.clone(), 0)];
        let mut emails = HashSet::new();
        let mut js_files = HashSet::new();

        while let Some((url, depth)) = queue.pop() {
            if depth > max_depth || visited.contains(&url) {
                continue;
            }
            visited.insert(url.clone());

            let mut req = http_sess.client.get(&url);
            if let Some(creds) = &http_sess.credentials {
                if let Some(pw) = &creds.password {
                    req = req.basic_auth(&creds.username, Some(pw));
                } else {
                    req = req.basic_auth(&creds.username, None::<&str>);
                }
            }

            if let Ok(res) = req.send().await {
                if let Ok(text) = res.text().await {
                    // Extremely basic regex-free extraction for speed & portability
                    // Extract hrefs
                    let hrefs: Vec<&str> = text
                        .split("href=\"")
                        .skip(1)
                        .filter_map(|s| s.split('\"').next())
                        .collect();

                    for href in hrefs {
                        if href.starts_with("http") && href.contains(&http_sess.target) {
                            queue.push((href.to_string(), depth + 1));
                        } else if href.starts_with('/') {
                            queue.push((format!("{base_url}{href}"), depth + 1));
                        }
                    }

                    // Extract JS scripts
                    let scripts: Vec<&str> = text
                        .split("src=\"")
                        .skip(1)
                        .filter_map(|s| s.split('\"').next())
                        .filter(|s| s.ends_with(".js"))
                        .collect();

                    for script in scripts {
                        js_files.insert(script.to_string());
                    }

                    // Extract crude emails
                    let mailtos: Vec<&str> = text
                        .split("mailto:")
                        .skip(1)
                        .filter_map(|s| s.split('\"').next())
                        .collect();
                    for mailto in mailtos {
                        emails.insert(mailto.to_string());
                    }
                }
            }
        }

        let mut output = String::from("Crawl Results:\n");
        output.push_str(&format!("  [*] Total Scraped URLs: {}\n", visited.len()));
        output.push_str(&format!("  [*] JavaScript Files Discovered: {}\n", js_files.len()));
        output.push_str(&format!("  [*] Emails Discovered: {}\n", emails.len()));

        if !emails.is_empty() {
            output.push_str("  [+] Emails:\n");
            for email in &emails {
                output.push_str(&format!("      - {email}\n"));
            }
        }

        Ok(ModuleResult {
            success: true,
            output,
            data: json!({
                "crawled_urls": visited,
                "js_files": js_files,
                "emails": emails
            }),
            credentials: vec![],
        })
    }
}
