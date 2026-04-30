//! # Kubernetes API Protocol Handler
//!
//! Kubernetes API server authentication testing and enumeration.
//! Supports bearer token, certificate, and anonymous access testing.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use futures_util::StreamExt;
use nxc_auth::{AuthResult, Credentials};
use tracing::info;

// ─── Kubernetes Session ─────────────────────────────────────────

pub struct KubeSession {
    pub target: String,
    pub port: u16,
    pub admin: bool,
    pub namespace: Option<String>,
    pub server_version: Option<String>,
    pub token: Option<String>,
}

impl NxcSession for KubeSession {
    fn protocol(&self) -> &'static str {
        "kube"
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

// ─── Kubernetes Protocol ────────────────────────────────────────

pub struct KubeProtocol;

impl KubeProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for KubeProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcProtocol for KubeProtocol {
    fn name(&self) -> &'static str {
        "kube"
    }
    fn default_port(&self) -> u16 {
        6443
    }
    fn supports_exec(&self) -> bool {
        true
    }

    async fn connect(
        &self,
        target: &str,
        port: u16,
        _proxy: Option<&str>,
    ) -> Result<Box<dyn NxcSession>> {
        info!("Kube: Probing API server at {}:{}", target, port);

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        let mut server_version = None;

        // Check /version endpoint (usually accessible without auth)
        let version_url = format!("https://{target}:{port}/version");
        if let Ok(resp) = client.get(&version_url).send().await {
            if resp.status().is_success() {
                if let Ok(body) = resp.text().await {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                        let major = v.get("major").and_then(|m| m.as_str()).unwrap_or("?");
                        let minor = v.get("minor").and_then(|m| m.as_str()).unwrap_or("?");
                        server_version = Some(format!("v{major}.{minor}"));
                    }
                }
            }
        }

        // Also try HTTP (port 8080/8443)
        if server_version.is_none() {
            let http_url = format!("http://{target}:{port}/version");
            if let Ok(resp) = client.get(&http_url).send().await {
                if let Ok(body) = resp.text().await {
                    if body.contains("gitVersion") {
                        server_version = Some("Kubernetes (HTTP)".to_string());
                    }
                }
            }
        }

        Ok(Box::new(KubeSession {
            target: target.to_string(),
            port,
            admin: false,
            namespace: None,
            server_version,
            token: None,
        }))
    }

    async fn authenticate(
        &self,
        session: &mut dyn NxcSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        let kube_sess = session
            .as_any_mut()
            .downcast_mut::<KubeSession>()
            .ok_or_else(|| anyhow!("Invalid session type"))?;

        info!("Kube: Authenticating on {}", kube_sess.target);

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        let api_url = format!("https://{}:{}/api/v1/namespaces", kube_sess.target, kube_sess.port);

        // Use password as bearer token if provided
        let req = if let Some(ref token) = creds.password {
            client.get(&api_url).bearer_auth(token)
        } else {
            // Try anonymous access
            client.get(&api_url)
        };

        match req.send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    kube_sess.admin = true;
                    kube_sess.namespace = Some("default".to_string());
                    kube_sess.token = creds.password.clone();
                    Ok(AuthResult::success(true))
                } else if status.as_u16() == 403 {
                    // Authenticated but not authorized for this resource
                    Ok(AuthResult::success(false))
                } else {
                    Ok(AuthResult::failure(
                        "Kubernetes authentication failed",
                        Some(&status.to_string()),
                    ))
                }
            }
            Err(e) => Ok(AuthResult::failure(&format!("Connection error: {e}"), None)),
        }
    }

    async fn execute(&self, session: &dyn NxcSession, cmd: &str) -> Result<CommandOutput> {
        let kube_sess = session
            .as_any()
            .downcast_ref::<KubeSession>()
            .ok_or_else(|| anyhow!("Invalid session type"))?;

        info!("Kube: Executing '{}' on {}", cmd, kube_sess.target);

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let ns = kube_sess.namespace.as_deref().unwrap_or("default");

        // Try to find a pod to execute on
        let pods_url = format!("https://{}:{}/api/v1/namespaces/{}/pods", kube_sess.target, kube_sess.port, ns);
        let mut req = client.get(&pods_url);
        if let Some(ref token) = kube_sess.token {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await?;
        let pods_json: serde_json::Value = resp.json().await?;

        let pod_name = pods_json["items"].as_array().and_then(|items| {
            items.iter().find_map(|item| {
                let status = item["status"]["phase"].as_str().unwrap_or("");
                if status == "Running" {
                    item["metadata"]["name"].as_str().map(std::string::ToString::to_string)
                } else {
                    None
                }
            })
        }).ok_or_else(|| anyhow!("No running pods found in namespace {ns}"))?;

        info!("Kube: Selected pod {} for execution", pod_name);

        let exec_url = format!(
            "wss://{}:{}/api/v1/namespaces/{}/pods/{}/exec?command=sh&command=-c&command={}&stdin=false&stdout=true&stderr=true&tty=false",
            kube_sess.target, kube_sess.port, ns, pod_name, urlencoding::encode(cmd)
        );

        let mut req = tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(exec_url.clone())?;
        if let Some(ref token) = kube_sess.token {
            req.headers_mut().insert(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))?
            );
        }
        req.headers_mut().insert(reqwest::header::SEC_WEBSOCKET_PROTOCOL, reqwest::header::HeaderValue::from_static("v4.channel.k8s.io"));

        let connector = tokio_tungstenite::Connector::NativeTls(
            native_tls::TlsConnector::builder().danger_accept_invalid_certs(true).build()?
        );

        let (mut ws_stream, _) = tokio_tungstenite::connect_async_tls_with_config(
            req,
            None,
            false,
            Some(connector),
        ).await?;

        let mut stdout_buf = String::new();
        let mut stderr_buf = String::new();

        while let Some(msg) = ws_stream.next().await {
            let msg = msg?;
            match msg {
                tokio_tungstenite::tungstenite::Message::Binary(data) => {
                    if data.is_empty() { continue; }
                    let channel = data[0];
                    let content = String::from_utf8_lossy(&data[1..]);
                    if channel == 1 {
                        stdout_buf.push_str(&content);
                    } else if channel == 2 {
                        stderr_buf.push_str(&content);
                    }
                }
                tokio_tungstenite::tungstenite::Message::Text(text) => {
                    stdout_buf.push_str(&text);
                }
                tokio_tungstenite::tungstenite::Message::Close(_) => break,
                _ => {}
            }
        }

        Ok(CommandOutput {
            stdout: stdout_buf,
            stderr: stderr_buf,
            exit_code: Some(0),
        })
    }
}

impl KubeProtocol {
    /// Enumerate service accounts and secrets.
    pub async fn list_secrets(&self, session: &KubeSession) -> Result<Vec<serde_json::Value>> {
        let client = reqwest::Client::builder().danger_accept_invalid_certs(true).build()?;

        let ns = session.namespace.as_deref().unwrap_or("default");
        let url =
            format!("https://{}:{}/api/v1/namespaces/{}/secrets", session.target, session.port, ns);

        let resp = client.get(&url).send().await?;
        if resp.status().is_success() {
            let body: serde_json::Value = resp.json().await?;
            if let Some(items) = body.get("items").and_then(|i| i.as_array()) {
                return Ok(items.clone());
            }
        }
        Ok(Vec::new())
    }

    /// List pods in a namespace.
    pub async fn list_pods(&self, session: &KubeSession) -> Result<Vec<serde_json::Value>> {
        let client = reqwest::Client::builder().danger_accept_invalid_certs(true).build()?;

        let ns = session.namespace.as_deref().unwrap_or("default");
        let url =
            format!("https://{}:{}/api/v1/namespaces/{}/pods", session.target, session.port, ns);

        let resp = client.get(&url).send().await?;
        if resp.status().is_success() {
            let body: serde_json::Value = resp.json().await?;
            if let Some(items) = body.get("items").and_then(|i| i.as_array()) {
                return Ok(items.clone());
            }
        }
        Ok(Vec::new())
    }
}
