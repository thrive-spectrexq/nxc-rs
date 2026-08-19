//! # MQTT Protocol Handler
//!
//! MQTT protocol implementation for NetExec-RS.
//! Supports unauthenticated connection and basic authentication.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use rand;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info};

// ─── MQTT Session ────────────────────────────────────────────────

pub struct MqttSession {
    pub target: String,
    pub port: u16,
    pub authenticated: bool,
    pub credentials: Option<Credentials>,
}

impl NxcSession for MqttSession {
    fn protocol(&self) -> &'static str {
        "mqtt"
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn is_admin(&self) -> bool {
        self.authenticated
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

// ─── MQTT Protocol Handler ───────────────────────────────────────

pub struct MqttProtocol {
    pub timeout: Duration,
}

impl MqttProtocol {
    pub fn new() -> Self {
        Self { timeout: Duration::from_secs(5) }
    }
}

impl Default for MqttProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcProtocol for MqttProtocol {
    fn name(&self) -> &'static str {
        "mqtt"
    }

    fn default_port(&self) -> u16 {
        1883
    }

    fn supports_exec(&self) -> bool {
        false
    }

    fn supported_modules(&self) -> &[&str] {
        &["mqtt_enum", "mqtt_publish"]
    }

    async fn connect(
        &self,
        target: &str,
        port: u16,
        _proxy: Option<&str>,
    ) -> Result<Box<dyn NxcSession>> {
        debug!("MQTT: Connecting to {}:{}", target, port);

        match timeout(self.timeout, TcpStream::connect((target, port))).await {
            Ok(Ok(_conn)) => {
                info!("MQTT: Connected to {}:{}", target, port);
                Ok(Box::new(MqttSession {
                    target: target.to_string(),
                    port,
                    authenticated: false,
                    credentials: None,
                }))
            }
            Ok(Err(e)) => Err(anyhow!("Connection failed: {e}")),
            Err(_) => Err(anyhow!("Connection timeout to {target}:{port}")),
        }
    }

    async fn authenticate(
        &self,
        session: &mut dyn NxcSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        let mqtt_sess = session
            .as_any_mut()
            .downcast_mut::<MqttSession>()
            .ok_or_else(|| anyhow!("Invalid session type"))?;

        // Build MQTT 3.1.1 CONNECT packet
        let connect_packet = build_connect_packet(
            &format!("nxc-{}", rand::random::<u16>()),
            if creds.username.is_empty() { None } else { Some(&creds.username) },
            creds.password.as_deref(),
        );

        // Send CONNECT and receive CONNACK
        let addr = format!("{}:{}", mqtt_sess.target, mqtt_sess.port);
        let mut stream = match timeout(self.timeout, TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(anyhow!("MQTT reconnect failed: {e}")),
            Err(_) => return Err(anyhow!("MQTT reconnect timeout")),
        };

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream.write_all(&connect_packet).await
            .map_err(|e| anyhow!("MQTT CONNECT send failed: {e}"))?;

        let mut buf = [0u8; 4];
        match timeout(self.timeout, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n >= 4 => {
                let (session_present, return_code) = parse_connack(&buf)?;
                debug!("MQTT: CONNACK received — session_present={session_present}, return_code={return_code}");
                match return_code {
                    0 => {
                        mqtt_sess.authenticated = true;
                        mqtt_sess.credentials = Some(creds.clone());
                        Ok(AuthResult::success(false))
                    }
                    4 => Ok(AuthResult::failure("Bad username or password", Some("CONNACK_BAD_CREDENTIALS"))),
                    5 => Ok(AuthResult::failure("Not authorized", Some("CONNACK_NOT_AUTHORIZED"))),
                    _ => Ok(AuthResult::failure(&format!("CONNACK return code: {return_code}"), None)),
                }
            }
            Ok(Ok(_)) => Ok(AuthResult::failure("CONNACK too short", None)),
            Ok(Err(e)) => Err(anyhow!("MQTT CONNACK read error: {e}")),
            Err(_) => Err(anyhow!("MQTT CONNACK timeout")),
        }
    }

    async fn execute(&self, _session: &dyn NxcSession, _cmd: &str) -> Result<CommandOutput> {
        Err(anyhow!("MQTT protocol does not support direct command execution"))
    }
}

/// Build an MQTT 3.1.1 CONNECT packet.
fn build_connect_packet(client_id: &str, username: Option<&str>, password: Option<&str>) -> Vec<u8> {
    let mut variable_header = Vec::new();
    // Protocol Name: "MQTT"
    variable_header.extend_from_slice(&[0x00, 0x04]); // Length
    variable_header.extend_from_slice(b"MQTT");
    // Protocol Level: 4 (MQTT 3.1.1)
    variable_header.push(0x04);
    // Connect Flags
    let mut flags: u8 = 0x02; // Clean Session
    if username.is_some() {
        flags |= 0x80; // Username flag
    }
    if password.is_some() {
        flags |= 0x40; // Password flag
    }
    variable_header.push(flags);
    // Keep Alive: 60 seconds
    variable_header.extend_from_slice(&60u16.to_be_bytes());

    // Payload
    let mut payload = Vec::new();
    // Client Identifier
    let client_id_bytes = client_id.as_bytes();
    payload.extend_from_slice(&(client_id_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(client_id_bytes);
    // Username
    if let Some(user) = username {
        let user_bytes = user.as_bytes();
        payload.extend_from_slice(&(user_bytes.len() as u16).to_be_bytes());
        payload.extend_from_slice(user_bytes);
    }
    // Password
    if let Some(pass) = password {
        let pass_bytes = pass.as_bytes();
        payload.extend_from_slice(&(pass_bytes.len() as u16).to_be_bytes());
        payload.extend_from_slice(pass_bytes);
    }

    // Fixed Header
    let remaining_len = variable_header.len() + payload.len();
    let mut packet = Vec::new();
    packet.push(0x10); // CONNECT packet type
    // Encode remaining length (simplified: assumes < 128 bytes for typical CONNECT)
    encode_remaining_length(&mut packet, remaining_len);
    packet.extend_from_slice(&variable_header);
    packet.extend_from_slice(&payload);
    packet
}

/// Encode MQTT remaining length field.
fn encode_remaining_length(packet: &mut Vec<u8>, mut length: usize) {
    loop {
        let mut byte = (length % 128) as u8;
        length /= 128;
        if length > 0 {
            byte |= 0x80;
        }
        packet.push(byte);
        if length == 0 {
            break;
        }
    }
}

/// Parse an MQTT CONNACK packet. Returns (session_present, return_code).
fn parse_connack(data: &[u8]) -> Result<(bool, u8)> {
    if data.len() < 4 {
        return Err(anyhow!("CONNACK packet too short"));
    }
    if data[0] != 0x20 {
        return Err(anyhow!("Not a CONNACK packet (type: 0x{:02x})", data[0]));
    }
    let session_present = (data[2] & 0x01) != 0;
    let return_code = data[3];
    Ok((session_present, return_code))
}

