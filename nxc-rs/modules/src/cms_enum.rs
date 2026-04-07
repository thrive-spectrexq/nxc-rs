use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{http::HttpSession, NxcSession};
use serde_json::json;
use tracing::info;

pub struct CmsEnum {}

impl CmsEnum {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for CmsEnum {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for CmsEnum {
    fn name(&self) -> &'static str {
        "cms_enum"
    }

    fn description(&self) -> &'static str {
        "Detects Content Management Systems (WordPress, Joomla, Drupal, etc.)"
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
        
        info!("Starting CMS enumeration against {}", base_url);

        let mut req = http_sess.client.get(&base_url);
        if let Some(creds) = &http_sess.credentials {
            if let Some(pw) = &creds.password {
                req = req.basic_auth(&creds.username, Some(pw));
            } else {
                req = req.basic_auth(&creds.username, None::<&str>);
            }
        }

        let mut found_cms = Vec::new();
        let mut output = String::from("CMS Detection Results:\n");

        if let Ok(res) = req.send().await {
            // Check headers
            for (key, value) in res.headers() {
                if let Ok(val) = value.to_str() {
                    let k = key.as_str().to_lowercase();
                    if k == "x-generator" {
                        found_cms.push(format!("Header X-Generator: {}", val));
                    }
                    if k == "x-powered-by" {
                        found_cms.push(format!("Header X-Powered-By: {}", val));
                    }
                }
            }

            if let Ok(body) = res.text().await {
                // Check body for common signatures
                if body.contains("wp-content") || body.contains("wp-includes") {
                    found_cms.push("WordPress (Detected via paths)".to_string());
                }
                if body.contains("Joomla!") {
                    found_cms.push("Joomla (Detected via meta generator)".to_string());
                }
                if body.contains("Drupal") {
                    found_cms.push("Drupal (Detected via meta generator or headers)".to_string());
                }
                if body.contains("magento") || body.contains("Mage.Cookies") {
                    found_cms.push("Magento (Detected via paths/js)".to_string());
                }
                if body.contains("Shopify") {
                    found_cms.push("Shopify (Detected via js object)".to_string());
                }
                if body.contains("ghost.org") {
                    found_cms.push("Ghost (Detected via meta generator)".to_string());
                }
            }
        }

        if found_cms.is_empty() {
            output.push_str("  [!] No common CMS detected.\n");
        } else {
            for cms in &found_cms {
                output.push_str(&format!("  [+] Found: {}\n", cms));
            }
        }

        Ok(ModuleResult {
            success: true,
            output,
            data: json!({ "detected": found_cms }),
            credentials: vec![],
        })
    }
}
