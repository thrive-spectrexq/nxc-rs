use crate::{ModuleResult, NxcModule, ModuleOptions, ModuleOption};
use nxc_protocols::NxcSession;
use anyhow::Result;
use async_trait::async_trait;
use tracing::info;

pub struct HttpPathsModule;

impl HttpPathsModule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl NxcModule for HttpPathsModule {
    fn name(&self) -> &'static str {
        "http_paths"
    }

    fn description(&self) -> &'static str {
        "Enumerate common sensitive web paths on the target"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["http"]
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![ModuleOption {
            name: "PATHS".to_string(),
            description: "Comma-separated list of paths to check".to_string(),
            required: false,
            default: Some("/.git,/.env,/backup,/phpmyadmin,/admin,/config".to_string()),
        }]
    }

    async fn run(&self, session: &mut dyn NxcSession, opts: &ModuleOptions) -> Result<ModuleResult> {
        info!("HTTP: Starting Path Discovery on {}...", session.target());

        if let Some(http_sess) = session.as_any().downcast_ref::<nxc_protocols::http::HttpSession>() {
            let protocol = nxc_protocols::http::HttpProtocol { use_ssl: false, verify_ssl: false }; // Defaults
            
            let default_paths = "/.git,/.env,/backup,/phpmyadmin,/admin,/config";
            let paths_str = opts.get("PATHS").map(|s| s.as_str()).unwrap_or(default_paths);
            let paths_vec: Vec<&str> = paths_str.split(',').collect();

            match protocol.enumerate_paths(http_sess, &paths_vec).await {
                Ok(results) => {
                    let mut output = String::from("Discovery Results:\n");
                    let mut found = Vec::new();
                    for (path, status) in results {
                        if status.is_success() {
                            output.push_str(&format!("  [+] {} - {}\n", path, status));
                            found.push(path);
                        }
                    }
                    if found.is_empty() {
                        output.push_str("  [!] No sensitive paths discovered.");
                    }
                    return Ok(ModuleResult {
                        success: true,
                        output,
                        data: serde_json::json!({ "found": found }),
                    });
                }
                Err(e) => return Err(e),
            }
        }

        Ok(ModuleResult {
            success: false,
            output: "Invalid session type for http_paths".to_string(),
            data: serde_json::json!({}),
        })
    }
}
