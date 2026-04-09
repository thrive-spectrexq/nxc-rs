//! # spider_plus — SMB Share Spider & Extractor
//!
//! Enumerates shares, spiders paths natively capturing metadata, and downloads matching files.
//! Replicates the highly-used `spider_plus` module from NetExec.

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use tracing::{error, info, warn};

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};

pub struct SpiderPlus;

impl SpiderPlus {
    pub fn new() -> Self {
        Self
    }

    async fn spider_directory(
        &self,
        smb: &nxc_protocols::smb::SmbProtocol,
        session: &nxc_protocols::smb::SmbSession,
        share: &str,
        path: &str,
        depth: usize,
        max_size: u64,
        exclude_exts: &HashSet<String>,
        exclude_filter: &HashSet<String>,
        download: bool,
        output_dir: &str,
        results: &mut HashMap<String, serde_json::Value>,
    ) -> Result<()> {
        if depth == 0 {
            return Ok(());
        }

        let entries = match smb.list_directory_detailed(session, share, path).await {
            Ok(e) => e,
            Err(_) => return Ok(()),
        };

        for entry in entries {
            let entry_name_lower = entry.name.to_lowercase();

            // Check exclusion filter for folder/file names
            if exclude_filter.iter().any(|f| entry_name_lower.contains(f)) {
                continue;
            }

            let current_path = if path.is_empty() {
                entry.name.clone()
            } else {
                format!("{}\\{}", path, entry.name)
            };

            if entry.is_dir {
                // Recursive call for directories
                let _ = Box::pin(self.spider_directory(
                    smb,
                    session,
                    share,
                    &current_path,
                    depth - 1,
                    max_size,
                    exclude_exts,
                    exclude_filter,
                    download,
                    output_dir,
                    results,
                ))
                .await;
            } else {
                // Process file
                results.insert(
                    current_path.clone(),
                    serde_json::json!({
                        "size": entry.size,
                        "ctime": entry.ctime,
                        "mtime": entry.mtime,
                        "atime": entry.atime,
                    }),
                );

                if download && entry.size <= max_size {
                    let ext = Path::new(&entry.name)
                        .extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or("")
                        .to_lowercase();

                    if !ext.is_empty() && exclude_exts.contains(&ext) {
                        continue;
                    }

                    // Attempt download
                    info!("Downloading file: {}\\{}", share, current_path);
                    match smb.download_file(session, share, &current_path).await {
                        Ok(data) => {
                            let mut save_path = PathBuf::from(output_dir);
                            save_path.push(session.target.clone());
                            save_path.push(share);
                            save_path.push(current_path.replace("\\", "/"));

                            if let Some(parent) = save_path.parent() {
                                let _ = std::fs::create_dir_all(parent);
                            }

                            if let Err(e) = std::fs::write(&save_path, data) {
                                error!("Failed to write downloaded file {:?}: {}", save_path, e);
                            }
                        }
                        Err(e) => warn!("Failed to download {}: {}", current_path, e),
                    }
                }
            }
        }

        Ok(())
    }
}

impl Default for SpiderPlus {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for SpiderPlus {
    fn name(&self) -> &'static str {
        "spider_plus"
    }

    fn description(&self) -> &'static str {
        "List files recursively and save a JSON share-file metadata. Downloads files if configured."
    }

    fn supported_protocols(&self) -> &[&str] {
        &["smb"].as_slice()
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption {
                name: "DOWNLOAD_FLAG".to_string(),
                description: "Download discovered files (Default: false)".to_string(),
                required: false,
                default: Some("false".to_string()),
            },
            ModuleOption {
                name: "EXCLUDE_EXTS".to_string(),
                description: "Comma-separated extensions to exclude (Default: ico,lnk)".to_string(),
                required: false,
                default: Some("ico,lnk".to_string()),
            },
            ModuleOption {
                name: "EXCLUDE_FILTER".to_string(),
                description:
                    "Comma-separated strings to exclude folders/files (Default: print$,ipc$)"
                        .to_string(),
                required: false,
                default: Some("print$,ipc$".to_string()),
            },
            ModuleOption {
                name: "MAX_FILE_SIZE".to_string(),
                description: "Max file size to download in bytes (Default: 51200)".to_string(),
                required: false,
                default: Some("51200".to_string()),
            },
            ModuleOption {
                name: "OUTPUT_FOLDER".to_string(),
                description: "Path to save files and JSON metadata (Default: ./nxc_spider_plus)"
                    .to_string(),
                required: false,
                default: Some("./nxc_spider_plus".to_string()),
            },
        ]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let smb_session = match session.as_any().downcast_ref::<nxc_protocols::smb::SmbSession>() {
            Some(s) => s,
            None => return Err(anyhow::anyhow!("Module only supports SMB")),
        };

        let download = opts
            .get("DOWNLOAD_FLAG")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false);
        let max_size: u64 = opts
            .get("MAX_FILE_SIZE")
            .and_then(|v| v.parse().ok())
            .unwrap_or(51200);
        let output_folder = opts
            .get("OUTPUT_FOLDER")
            .cloned()
            .unwrap_or_else(|| "./nxc_spider_plus".to_string());

        let exclude_exts: HashSet<String> = opts
            .get("EXCLUDE_EXTS")
            .unwrap_or(&"ico,lnk".to_string())
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();

        let exclude_filter: HashSet<String> = opts
            .get("EXCLUDE_FILTER")
            .unwrap_or(&"print$,ipc$".to_string())
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();

        let protocol = nxc_protocols::smb::SmbProtocol::new();
        let shares = protocol.list_shares(smb_session).await?;

        std::fs::create_dir_all(&output_folder).unwrap_or_default();

        let mut all_results = HashMap::new();
        let depth = 10; // Max depth to spider

        for share in shares {
            if share.read_access {
                let share_name_lower = share.name.to_lowercase();
                if exclude_filter.iter().any(|f| share_name_lower.contains(f)) {
                    continue; // Skip excluded shares
                }

                info!("Spidering share: {}", share.name);
                let mut share_results = HashMap::new();
                let _ = self
                    .spider_directory(
                        &protocol,
                        smb_session,
                        &share.name,
                        "",
                        depth,
                        max_size,
                        &exclude_exts,
                        &exclude_filter,
                        download,
                        &output_folder,
                        &mut share_results,
                    )
                    .await;

                all_results.insert(share.name.clone(), serde_json::json!(share_results));
            }
        }

        let host_json_path =
            PathBuf::from(&output_folder).join(format!("{}.json", smb_session.target));
        let json_output = serde_json::json!(all_results);
        let _ = std::fs::write(&host_json_path, serde_json::to_string_pretty(&json_output)?);

        Ok(ModuleResult {
            success: true,
            output: format!(
                "Spidering completed. Metadata saved to {:?}",
                host_json_path
            ),
            data: json_output,
            credentials: vec![],
        })
    }
}
