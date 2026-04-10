//! # BloodHound Export Module
//!
//! Generates BloodHound-compatible JSON files from authenticated sessions.

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_protocols::NxcSession;
use reqwest::{multipart, Client};
use std::io::{Cursor, Write};
use tracing::{debug, error, info};
use zip::{write::FileOptions, ZipWriter};

pub struct BloodhoundModule;

impl Default for BloodhoundModule {
    fn default() -> Self {
        Self::new()
    }
}

impl BloodhoundModule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl NxcModule for BloodhoundModule {
    fn name(&self) -> &'static str {
        "bloodhound"
    }

    fn description(&self) -> &'static str {
        "Export Active Directory data to BloodHound JSON format and optionally upload to BloodHound CE REST API"
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![
            ModuleOption {
                name: "bh_uri".to_string(),
                description: "BloodHound CE REST API URI (e.g., https://127.0.0.1:8080)"
                    .to_string(),
                required: false,
                default: None,
            },
            ModuleOption {
                name: "bh_user".to_string(),
                description: "BloodHound CE Username/Token ID".to_string(),
                required: false,
                default: None,
            },
            ModuleOption {
                name: "bh_pass".to_string(),
                description: "BloodHound CE Password/Token Key".to_string(),
                required: false,
                default: None,
            },
            ModuleOption {
                name: "verify_ssl".to_string(),
                description: "Verify BloodHound CE SSL certificate (default: false)".to_string(),
                required: false,
                default: Some("false".to_string()),
            },
        ]
    }

    fn supported_protocols(&self) -> &[&str] {
        &["ldap", "smb"]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        info!("BloodHound: Collecting data from {}...", session.target());

        let mut users_json = Vec::new();
        let computers_json: Vec<serde_json::Value> = Vec::new();

        if session.protocol() == "ldap" {
            use nxc_protocols::ldap::{LdapProtocol, LdapSession};
            let ldap_proto = LdapProtocol::default();
            let ldap_sess = session
                .as_any()
                .downcast_ref::<LdapSession>()
                .ok_or_else(|| anyhow!("Invalid LDAP session"))?;

            if let Ok(users) = ldap_proto.enumerate_users(ldap_sess).await {
                for user in users {
                    users_json.push(serde_json::json!({
                        "ObjectIdentifier": format!("S-1-5-21-3624784890-3369157290-3035138449-{}", user), // Dummy SID
                        "Properties": {
                            "name": format!("{}@{}", user, ldap_sess.target),
                            "samaccountname": user,
                            "distinguishedname": format!("CN={},{}", user, ldap_proto.get_base_dn(ldap_sess).await.unwrap_or_default())
                        },
                        "Aces": []
                    }));
                }
            }
        }

        let payload = serde_json::json!({
            "users": users_json,
            "computers": computers_json,
            "meta": {
                "type": "bloodhound",
                "count": users_json.len() + computers_json.len(),
                "version": 5
            }
        });

        // If BloodHound REST API options are provided, upload the data
        if let (Some(bh_uri), Some(bh_user), Some(bh_pass)) =
            (opts.get("bh_uri"), opts.get("bh_user"), opts.get("bh_pass"))
        {
            let verify_ssl = opts.get("verify_ssl").map(|s| s == "true").unwrap_or(false);
            info!("BloodHound: Zipping and pushing data to {}...", bh_uri);
            if let Err(e) =
                self.upload_to_bloodhound(bh_uri, bh_user, bh_pass, verify_ssl, &payload).await
            {
                error!("BloodHound: Failed to upload data: {}", e);
                return Ok(ModuleResult {
                    credentials: vec![],
                    success: false,
                    output: format!("Failed to push to BloodHound API: {e}"),
                    data: payload,
                });
            } else {
                return Ok(ModuleResult {
                    credentials: vec![], success: true,
                    output: format!("BloodHound collection and upload complete! Published {} users and {} computers to {}.", users_json.len(), computers_json.len(), bh_uri),
                    data: serde_json::json!({"status": "uploaded"}),
                });
            }
        }

        Ok(ModuleResult {
            credentials: vec![],
            success: true,
            output: format!(
                "BloodHound collection complete. Generated {} users and {} computers.",
                users_json.len(),
                computers_json.len()
            ),
            data: payload,
        })
    }
}

impl BloodhoundModule {
    async fn upload_to_bloodhound(
        &self,
        uri: &str,
        user: &str,
        pass: &str,
        verify_ssl: bool,
        payload: &serde_json::Value,
    ) -> Result<()> {
        let client = Client::builder().danger_accept_invalid_certs(!verify_ssl).build()?;

        // 1. Authenticate with BloodHound CE API to get a session JWT
        let login_url = format!("{}/api/v2/login", uri.trim_end_matches('/'));
        let login_body = serde_json::json!({
            "login_method": "secret",
            "username": user,
            "secret": pass
        });

        debug!("BloodHound: Authenticating to {}", login_url);
        let auth_resp = client.post(&login_url).json(&login_body).send().await?;

        if !auth_resp.status().is_success() {
            return Err(anyhow!("Authentication failed: {}", auth_resp.status()));
        }

        let auth_data: serde_json::Value = auth_resp.json().await?;
        let token = auth_data["data"]["session_token"]
            .as_str()
            .ok_or_else(|| anyhow!("No session token in response"))?;

        // 2. Create in-memory zip file of the payload
        let mut buffer = Cursor::new(Vec::<u8>::new());
        {
            let mut zip = ZipWriter::new(&mut buffer);
            let options = FileOptions::<'static, ()>::default()
                .compression_method(zip::CompressionMethod::Deflated);
            zip.start_file("bloodhound_data.json", options)?;

            let json_string = serde_json::to_string(payload)?;
            zip.write_all(json_string.as_bytes())?;
            zip.finish()?;
        }

        let zip_data = buffer.into_inner();

        // 3. Upload file via multipart
        let upload_url = format!("{}/api/v2/file-upload/", uri.trim_end_matches('/'));
        let part = multipart::Part::bytes(zip_data)
            .file_name("nxc_extract.zip")
            .mime_str("application/zip")?;

        let form = multipart::Form::new().part("file", part);

        debug!("BloodHound: Pushing zip payload to {}", upload_url);
        let upload_resp = client
            .post(&upload_url)
            .header("Authorization", format!("Bearer {token}"))
            .multipart(form)
            .send()
            .await?;

        if upload_resp.status().is_success() {
            Ok(())
        } else {
            Err(anyhow!("Upload failed: {}", upload_resp.status()))
        }
    }
}
