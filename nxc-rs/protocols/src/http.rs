//! # HTTP Protocol Handler
//!
//! Basic HTTP authentication brute force and web request protocol handler.
//! Supports Basic Authentication for generic IoT endpoint testing.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{Context, Result};
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use reqwest::{Client, StatusCode};

pub struct HttpSession {
    pub target: String,
    pub port: u16,
    pub admin: bool,
    pub use_ssl: bool,
    pub client: Client,
    pub credentials: Option<Credentials>,
}

impl NxcSession for HttpSession {
    fn protocol(&self) -> &'static str {
        "http"
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn is_admin(&self) -> bool {
        self.admin
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

pub struct HttpProtocol {
    pub use_ssl: bool,
    pub verify_ssl: bool,
}

impl Default for HttpProtocol {
    fn default() -> Self {
        Self::new(false, false)
    }
}

impl HttpProtocol {
    pub fn new(use_ssl: bool, verify_ssl: bool) -> Self {
        Self {
            use_ssl,
            verify_ssl,
        }
    }
}

#[async_trait]
impl NxcProtocol for HttpProtocol {
    fn name(&self) -> &'static str {
        "http"
    }

    fn default_port(&self) -> u16 {
        if self.use_ssl {
            443
        } else {
            80
        }
    }

    fn supports_exec(&self) -> bool {
        false
    }

    fn supported_modules(&self) -> &[&str] {
        &["iot_cam", "http_paths", "web_crawler", "web_fuzzer", "web_vuln", "vhost_enum", "cms_enum", "graphql_enum", "waf_detect", "web_auth_brute", "cors_vuln", "web_dav", "method_fuzz", "lfi_fuzzer", "ssrf_fuzzer", "jwt_audit"] 
    }

    async fn connect(&self, target: &str, port: u16, proxy: Option<&str>) -> Result<Box<dyn NxcSession>> {
        let mut builder = Client::builder()
            .danger_accept_invalid_certs(!self.verify_ssl) // Option to bypass cert warnings common on IoT
            .user_agent(Self::get_random_user_agent())
            .timeout(std::time::Duration::from_secs(10));

        if let Some(proxy_url) = proxy {
            let proxy_obj = reqwest::Proxy::all(proxy_url)?;
            builder = builder.proxy(proxy_obj);
        }

        let client = builder.build()
            .context("Failed to build HTTP client")?;

        Ok(Box::new(HttpSession {
            target: target.to_string(),
            port,
            admin: false,
            use_ssl: self.use_ssl,
            client,
            credentials: None,
        }))
    }

    async fn authenticate(
        &self,
        session: &mut dyn NxcSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        let http_sess = session
            .as_any_mut()
            .downcast_mut::<HttpSession>()
            .ok_or_else(|| anyhow::anyhow!("Invalid session type downcast for http"))?;

        let scheme = if self.use_ssl { "https" } else { "http" };
        let url = format!("{}://{}:{}", scheme, http_sess.target, http_sess.port);

        // Cache the credentials for post-auth modules
        http_sess.credentials = Some(creds.clone());

        // Perform HTTP GET with Basic Auth
        let mut req = http_sess.client.get(&url);

        if let Some(password) = &creds.password {
            req = req.basic_auth(&creds.username, Some(password));
        } else {
            req = req.basic_auth(&creds.username, None::<&str>);
        }

        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => return Ok(AuthResult::failure(&format!("HTTP Error: {}", e), None)),
        };

        let status = resp.status();
        let server_header = resp
            .headers()
            .get("Server")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("Unknown Server");

        let msg = format!("HTTP {} - Server: {}", status, server_header);

        if status.is_success() || status == StatusCode::NOT_FOUND {
            // Unauthenticated public servers might return 404 on the root, but it means
            // we connected and the creds (if any) didn't cause a 401.
            // Truly valid authentication to a protected route will typically return 200.
            Ok(AuthResult {
                success: true,
                admin: false,
                message: msg,
                error_code: None,
            })
        } else if status == StatusCode::UNAUTHORIZED {
            // 401 Unauthorized means the credentials failed
            Ok(AuthResult::failure(&msg, Some("HTTP_401")))
        } else {
            // Other errors (500, etc) usually mean we didn't firmly authenticate
            Ok(AuthResult::failure(
                &msg,
                Some(&status.as_u16().to_string()),
            ))
        }
    }

    async fn execute(&self, _session: &dyn NxcSession, _cmd: &str) -> Result<CommandOutput> {
        Err(anyhow::anyhow!(
            "Command execution not supported on HTTP protocol natively."
        ))
    }
}

impl HttpProtocol {
    /// Enumerate a list of common paths on the target.
    pub async fn enumerate_paths(&self, session: &HttpSession, paths: &[&str]) -> Result<Vec<(String, StatusCode)>> {
        let mut results = Vec::new();
        let scheme = if self.use_ssl { "https" } else { "http" };

        for path in paths {
            let url = format!("{}://{}:{}/{}", scheme, session.target, session.port, path.trim_start_matches('/'));
            let resp = session.client.get(&url).send().await;

            if let Ok(r) = resp {
                results.push((path.to_string(), r.status()));
            }
        }
        Ok(results)
    }

    fn get_random_user_agent() -> &'static str {
        const USER_AGENTS: &[&str] = &[
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1.2 Mobile/15E148 Safari/604.1",
        ];
        use rand::seq::SliceRandom;
        USER_AGENTS.choose(&mut rand::thread_rng()).unwrap_or(&USER_AGENTS[0])
    }
}
