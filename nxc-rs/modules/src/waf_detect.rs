use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{http::HttpSession, NxcSession};
use serde_json::json;
use tracing::info;

pub struct WafDetect {}

impl WafDetect {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for WafDetect {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for WafDetect {
    fn name(&self) -> &'static str {
        "waf_detect"
    }

    fn description(&self) -> &'static str {
        "Detects and fingerprints Web Application Firewalls (WAF) using HTTP responses."
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
        // Malicious payload to trigger WAF blocking behavior: a standard benign SQLi
        let base_url =
            format!("{}://{}:{}/?id=1'+OR+'1'='1'--", scheme, http_sess.target, http_sess.port);

        info!("Starting WAF Detection against {}", base_url);

        let mut req = http_sess.client.get(&base_url);
        if let Some(creds) = &http_sess.credentials {
            if let Some(pw) = &creds.password {
                req = req.basic_auth(&creds.username, Some(pw));
            } else {
                req = req.basic_auth(&creds.username, None::<&str>);
            }
        }

        let mut output = String::from("WAF Detection Results:\n");
        let mut detected_waf = None;

        if let Ok(res) = req.send().await {
            let status = res.status().as_u16();

            for (key, value) in res.headers() {
                if let Ok(val) = value.to_str() {
                    let k = key.as_str().to_lowercase();
                    let v = val.to_lowercase();

                    // Cloudflare
                    if k == "server" && v.contains("cloudflare") {
                        detected_waf = Some("Cloudflare");
                    }
                    if k == "cf-ray" {
                        detected_waf = Some("Cloudflare");
                    }
                    // AWS CloudFront / WAF
                    if k == "x-amz-cf-id" || k == "x-cache" && v.contains("cloudfront") {
                        detected_waf = Some("AWS CloudFront/WAF");
                    }
                    // Imperva / Incapsula
                    if k == "x-iinfo" || k == "x-cdn" && v.contains("incapsula") {
                        detected_waf = Some("Imperva Incapsula");
                    }
                    // Akamai
                    if k == "x-akamai-transformed" || k == "server" && v.contains("akamai") {
                        detected_waf = Some("Akamai");
                    }
                    // F5 BIG-IP
                    if k == "server" && v.contains("big-ip")
                        || k == "x-cnection" && v.contains("close")
                    {
                        detected_waf = Some("F5 BIG-IP");
                    }
                    // Sucuri
                    if k == "x-sucuri-id" || k == "server" && v.contains("sucuri") {
                        detected_waf = Some("Sucuri");
                    }
                }
            }

            if let Ok(body) = res.text().await {
                if detected_waf.is_none() {
                    // Check standard WAF block pages if headers are ambiguous
                    if body.contains("Attention Required! | Cloudflare") {
                        detected_waf = Some("Cloudflare");
                    } else if body.contains("Incapsula incident ID") {
                        detected_waf = Some("Imperva Incapsula");
                    } else if body
                        .contains("The Amazon CloudFront distribution is configured to block")
                    {
                        detected_waf = Some("AWS WAF");
                    } else if body.contains("Access Denied") && body.contains("Reference #") {
                        detected_waf = Some("Akamai");
                    } else if body.contains("Not Acceptable") && body.contains("mod_security") {
                        detected_waf = Some("ModSecurity");
                    } else if status == 403 || status == 406 {
                        detected_waf = Some("Generic WAF (Blocked via 403/406)");
                    }
                }
            }
        }

        match &detected_waf {
            Some(waf) => {
                output.push_str(&format!("  [!] WAF Detected: {waf}\n"));
            }
            None => {
                output
                    .push_str("  [+] No standard WAF detected (or WAF didn't block signature).\n");
            }
        }

        Ok(ModuleResult {
            success: true,
            output,
            data: json!({ "waf": detected_waf }),
            credentials: vec![],
        })
    }
}
