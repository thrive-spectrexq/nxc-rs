use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::{http::HttpSession, NxcSession};
use serde_json::json;
use tracing::info;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

pub struct JwtAudit {}

impl JwtAudit {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for JwtAudit {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for JwtAudit {
    fn name(&self) -> &'static str {
        "jwt_audit"
    }

    fn description(&self) -> &'static str {
        "Detects and audits JSON Web Tokens (JWT) for algorithms and sensitive data."
    }

    fn supported_protocols(&self) -> &[&str] {
        &["http"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption {
                name: "PATH".to_string(),
                description: "Endpoint to query for JWTs (e.g. /api/auth)".to_string(),
                required: false,
                default: Some("/".to_string()),
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
        let base_path = opts.get("PATH").map(|s| s.as_str()).unwrap_or("/");
        let url = format!("{}://{}:{}{}", scheme, http_sess.target, http_sess.port, base_path);
        
        info!("Starting JWT Audit against {}", url);

        let mut output = String::from("JWT Audit Results:\n");
        let mut jwts_found = Vec::new();

        let mut req = http_sess.client.get(&url);
        
        if let Some(creds) = &http_sess.credentials {
            if let Some(pw) = &creds.password {
                req = req.basic_auth(&creds.username, Some(pw));
            } else {
                req = req.basic_auth(&creds.username, None::<&str>);
            }
        }

        if let Ok(res) = req.send().await {
            // Check headers for JWTs
            for (_key, value) in res.headers() {
                if let Ok(val) = value.to_str() {
                    extract_jwts(val, &mut jwts_found);
                }
            }

            // Check body for JWTs
            if let Ok(body) = res.text().await {
                extract_jwts(&body, &mut jwts_found);
            }
        }

        if jwts_found.is_empty() {
            output.push_str("  [-] No JSON Web Tokens (JWT) found in response.\n");
        } else {
            // Deduplicate
            jwts_found.sort();
            jwts_found.dedup();

            output.push_str(&format!("  [!] Found {} distinct JWT(s):\n", jwts_found.len()));

            for jwt in &jwts_found {
                let parts: Vec<&str> = jwt.split('.').collect();
                if parts.len() == 3 {
                    let header = decode_jwt_part(parts[0]);
                    let payload = decode_jwt_part(parts[1]);

                    output.push_str("      ---------------------------\n");
                    output.push_str(&format!("      Token  : {}...\n", &jwt[0..15.min(jwt.len())]));
                    output.push_str(&format!("      Header : {}\n", header));
                    output.push_str(&format!("      Payload: {}\n", payload));

                    if header.contains("\"none\"") || header.contains("\"NONE\"") {
                        output.push_str("      [!] CRITICAL: JWT Algorithm is set to 'none'!\n");
                    }
                }
            }
        }

        Ok(ModuleResult {
            success: !jwts_found.is_empty(),
            output,
            data: json!({ "jwts_detected": jwts_found, "count": jwts_found.len() }),
            credentials: vec![],
        })
    }
}

// Very basic JWT regex-like extraction (eyJh... string)
fn extract_jwts(text: &str, found: &mut Vec<String>) {
    let parts: Vec<&str> = text.split(&[' ', '"', '\'', '\n', '\r', ',', '\\'][..]).collect();
    for part in parts {
        if part.starts_with("eyJ") && part.chars().filter(|&c| c == '.').count() == 2 {
            found.push(part.to_string());
        }
    }
}

fn decode_jwt_part(part: &str) -> String {
    // Standard Base64 requires padding; URL-safe Base64 drops it. 
    // We try to decode as URL_SAFE_NO_PAD first, then fallback to robust bytes.
    let clean_part = part.trim_end_matches('='); // manual strip padding if any
    
    match URL_SAFE_NO_PAD.decode(clean_part) {
        Ok(bytes) => String::from_utf8(bytes).unwrap_or_else(|_| "[Invalid UTF-8 json]".to_string()),
        Err(_) => "[Base64 decoding failed]".to_string()
    }
}
