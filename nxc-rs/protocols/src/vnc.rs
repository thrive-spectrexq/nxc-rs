//! # VNC Protocol Handler
//!
//! VNC protocol implementation focusing on port 5900 connections,
//! RFB protocol probing, and security type enumeration.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

pub struct VncSession {
    pub target: String,
    pub port: u16,
    pub rfb_version: String,
    pub security_types: Vec<u8>,
    pub no_auth_supported: bool,
    pub width: u16,
    pub height: u16,
    pub name: String,
    pub admin: bool,
    pub stream: Option<TcpStream>,
}

impl NxcSession for VncSession {
    fn protocol(&self) -> &'static str {
        "vnc"
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

pub struct VncProtocol {
    pub timeout: Duration,
}

impl VncProtocol {
    pub fn new() -> Self {
        Self { timeout: Duration::from_secs(10) }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl Default for VncProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcProtocol for VncProtocol {
    fn name(&self) -> &'static str {
        "vnc"
    }

    fn default_port(&self) -> u16 {
        5900
    }

    fn supports_exec(&self) -> bool {
        true // Exec via VNC mouse/keyboard macros
    }

    fn supported_modules(&self) -> &[&str] {
        &["screenshot"]
    }

    async fn connect(
        &self,
        target: &str,
        port: u16,
        _proxy: Option<&str>,
    ) -> Result<Box<dyn NxcSession>> {
        let addr = format!("{target}:{port}");
        debug!("VNC: Connecting to {}", addr);

        let timeout_fut = tokio::time::timeout(self.timeout, TcpStream::connect(&addr));
        let mut stream = match timeout_fut.await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(anyhow!("Connection refused or unreachable: {e}")),
            Err(_) => return Err(anyhow!("Connection timeout to {addr}")),
        };

        // 1. Probe RFB (Remote Frame Buffer) version
        let mut banner = vec![0; 12];
        stream.read_exact(&mut banner).await?;
        if !banner.starts_with(b"RFB") {
            return Err(anyhow!("Invalid VNC RFB banner received."));
        }
        let rfb_version = String::from_utf8_lossy(&banner).trim().to_string();
        stream.write_all(&banner).await?;

        // 2. Security Handshake
        let mut security_types = Vec::new();
        let mut no_auth_supported = false;

        let mut n_types = [0u8; 1];
        stream.read_exact(&mut n_types).await?;
        let n = n_types[0];
        if n > 0 {
            let mut types = vec![0; n as usize];
            stream.read_exact(&mut types).await?;
            security_types = types.clone();
            no_auth_supported = types.contains(&1);
        }

        info!(
            "VNC: Connected to {} (Version: {}, SecTypes: {:?}, NoAuth: {})",
            addr, rfb_version, security_types, no_auth_supported
        );

        Ok(Box::new(VncSession {
            target: target.to_string(),
            port,
            rfb_version,
            security_types,
            no_auth_supported,
            width: 0,
            height: 0,
            name: String::new(),
            admin: false,
            stream: Some(stream),
        }))
    }

    async fn authenticate(
        &self,
        session: &mut dyn NxcSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        let vnc_sess = match session.downcast_mut::<VncSession>() {
            Some(s) => s,
            None => return Err(anyhow!("Invalid session type for VNC")),
        };

        let stream = match vnc_sess.stream.as_mut() {
            Some(s) => s,
            None => return Err(anyhow!("VNC stream not open")),
        };

        // Decide security type
        if vnc_sess.security_types.contains(&2) {
            // VNC Authentication (DES)
            stream.write_all(&[2]).await?;

            let mut challenge = [0u8; 16];
            stream.read_exact(&mut challenge).await?;

            let password = creds.password.as_deref().unwrap_or_default();
            let response = vnc_encrypt(password, &challenge);
            stream.write_all(&response).await?;

            let mut auth_result = [0u8; 4];
            stream.read_exact(&mut auth_result).await?;

            if u32::from_be_bytes(auth_result) == 0 {
                // 3. ClientInit
                stream.write_all(&[1]).await?; // Default: Shared=1

                // 4. ServerInit
                let mut server_init = [0u8; 20];
                stream.read_exact(&mut server_init).await?;

                vnc_sess.width = u16::from_be_bytes([server_init[0], server_init[1]]);
                vnc_sess.height = u16::from_be_bytes([server_init[2], server_init[3]]);

                let name_len = u32::from_be_bytes([
                    server_init[16],
                    server_init[17],
                    server_init[18],
                    server_init[19],
                ]);
                let mut name_buf = vec![0u8; name_len as usize];
                stream.read_exact(&mut name_buf).await?;
                vnc_sess.name = String::from_utf8_lossy(&name_buf).to_string();

                info!(
                    "VNC: Authenticated to {} ({}x{}, Name: {})",
                    vnc_sess.target, vnc_sess.width, vnc_sess.height, vnc_sess.name
                );
                return Ok(AuthResult::success(false));
            } else {
                return Ok(AuthResult::failure("VNC Invalid Credentials", None));
            }
        } else if vnc_sess.no_auth_supported {
            stream.write_all(&[1]).await?;
            return Ok(AuthResult::success(false));
        }

        Ok(AuthResult::failure("VNC: Unsupported security types", None))
    }

    async fn execute(&self, _session: &dyn NxcSession, _cmd: &str) -> Result<CommandOutput> {
        Err(anyhow!("VNC explicit command execution requires macro injection (not yet ported)."))
    }
}

impl VncProtocol {
    pub async fn capture_screenshot(&self, session: &mut dyn NxcSession) -> Result<String> {
        let vnc_sess = match session.downcast_mut::<VncSession>() {
            Some(s) => s,
            None => return Err(anyhow!("Invalid session type for VNC")),
        };

        let width = vnc_sess.width;
        let height = vnc_sess.height;

        if width == 0 || height == 0 {
            return Err(anyhow!("VNC Display not initialized. Authentication required?"));
        }

        let stream = match vnc_sess.stream.as_mut() {
            Some(s) => s,
            None => return Err(anyhow!("VNC stream not open")),
        };

        // 1. Send FramebufferUpdateRequest
        let mut req = vec![3, 0]; // MsgType=3, Incremental=0
        req.extend_from_slice(&0u16.to_be_bytes()); // X
        req.extend_from_slice(&0u16.to_be_bytes()); // Y
        req.extend_from_slice(&width.to_be_bytes());
        req.extend_from_slice(&height.to_be_bytes());

        stream.write_all(&req).await?;

        // 2. Read FramebufferUpdate
        // MsgType (1) + Padding (1) + Number of Rectangles (2)
        let mut msg_header = [0u8; 4];
        stream.read_exact(&mut msg_header).await?;

        if msg_header[0] != 0 {
            return Err(anyhow!("Expected FramebufferUpdate (0), got {}", msg_header[0]));
        }

        let n_rects = u16::from_be_bytes([msg_header[2], msg_header[3]]);
        info!("VNC: Receiving {} rectangles for {}x{} screenshot", n_rects, width, height);

        let mut fb_data = vec![0u8; (width as usize) * (height as usize) * 4];
        for _ in 0..n_rects {
            let mut rect_header = [0u8; 12];
            stream.read_exact(&mut rect_header).await?;

            let x = u16::from_be_bytes([rect_header[0], rect_header[1]]);
            let y = u16::from_be_bytes([rect_header[2], rect_header[3]]);
            let w = u16::from_be_bytes([rect_header[4], rect_header[5]]);
            let h = u16::from_be_bytes([rect_header[6], rect_header[7]]);
            let encoding = i32::from_be_bytes([
                rect_header[8],
                rect_header[9],
                rect_header[10],
                rect_header[11],
            ]);

            if encoding == 0 {
                // Raw encoding
                let pixel_data_len = (w as usize) * (h as usize) * 4;
                let mut pixels = vec![0u8; pixel_data_len];
                stream.read_exact(&mut pixels).await?;

                // Copy into fb_data at correct offset
                for row in 0..(h as usize) {
                    let src_start = row * (w as usize) * 4;
                    let dst_start = ((y as usize + row) * (width as usize) + (x as usize)) * 4;
                    let copy_len = (w as usize) * 4;
                    if dst_start + copy_len <= fb_data.len() && src_start + copy_len <= pixels.len()
                    {
                        fb_data[dst_start..dst_start + copy_len]
                            .copy_from_slice(&pixels[src_start..src_start + copy_len]);
                    }
                }
            }
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)?
            .as_secs();
        let path = format!("screenshots/vnc_{}_{}.png", vnc_sess.target, timestamp);

        std::fs::create_dir_all("screenshots")?;

        // VNC usually sends BGRA, convert to RGBA for PNG
        let mut rgba_data = fb_data.clone();
        for i in (0..rgba_data.len()).step_by(4) {
            let b = rgba_data[i];
            let r = rgba_data[i + 2];
            rgba_data[i] = r;
            rgba_data[i + 2] = b;
        }

        image::save_buffer(&path, &rgba_data, width as u32, height as u32, image::ColorType::Rgba8)
            .map_err(|e| anyhow!("Failed to save PNG: {e}"))?;

        info!("VNC: Screenshot saved to {}", path);
        Ok(path)
    }
}

fn vnc_encrypt(password: &str, challenge: &[u8; 16]) -> [u8; 16] {
    let mut key = [0u8; 8];
    let pwd_bytes = password.as_bytes();
    for i in 0..8 {
        if i < pwd_bytes.len() {
            key[i] = reverse_bits(pwd_bytes[i]);
        }
    }

    // SECURITY: VNC authentication MANDATES the use of the legacy DES algorithm
    // for its standard challenge-response handshake. This is insecure but
    // required for compatibility with standard VNC servers.
    use des::cipher::{BlockCipherEncrypt, KeyInit};
    use des::Des;

    let key_arr: &des::cipher::Key<Des> = (&key).into();
    let cipher = Des::new(key_arr);

    let mut out = [0u8; 16];
    let challenge_block1: &des::cipher::Block<Des> = (&challenge[0..8]).try_into().unwrap();
    let out_block1: &mut des::cipher::Block<Des> = (&mut out[0..8]).try_into().unwrap();
    cipher.encrypt_block_b2b(challenge_block1, out_block1);
    let challenge_block2: &des::cipher::Block<Des> = (&challenge[8..16]).try_into().unwrap();
    let out_block2: &mut des::cipher::Block<Des> = (&mut out[8..16]).try_into().unwrap();
    cipher.encrypt_block_b2b(challenge_block2, out_block2);
    out
}

fn reverse_bits(mut b: u8) -> u8 {
    let mut res = 0;
    for _ in 0..8 {
        res <<= 1;
        res |= b & 1;
        b >>= 1;
    }
    res
}
