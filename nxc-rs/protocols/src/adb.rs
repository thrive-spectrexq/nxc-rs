//! # ADB Protocol Handler
//!
//! Android Debug Bridge protocol implementation over TCP (port 5555).
//! Understands the ADB handshake (`CNXN`) and basic shell command execution (`OPEN shell:`).

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

// ─── ADB Packet Constants ───────────────────────────────────────
const _A_SYNC: u32 = 0x434e5953;
const A_CNXN: u32 = 0x4e584e43;
const A_OPEN: u32 = 0x4e45504f;
const A_OKAY: u32 = 0x59414b4f;
const A_CLSE: u32 = 0x45534c43;
const A_WRTE: u32 = 0x45545257;

const A_VERSION: u32 = 0x01000000; // ADB Protocol Version
const MAX_PAYLOAD: u32 = 4096;

// ─── Helper Functions ───────────────────────────────────────────

/// Generate the magic value (bitwise NOT of command) for an ADB packet.
fn magic(command: u32) -> u32 {
    command ^ 0xFFFFFFFF
}

/// Calculate the sum of all bytes in a payload.
fn checksum(payload: &[u8]) -> u32 {
    payload.iter().fold(0u32, |acc, &b| acc.wrapping_add(b as u32))
}

/// Helper to serialize a standard 24-byte ADB message header.
fn build_header(command: u32, arg0: u32, arg1: u32, payload: &[u8]) -> [u8; 24] {
    let mut header = [0u8; 24];
    header[0..4].copy_from_slice(&command.to_le_bytes());
    header[4..8].copy_from_slice(&arg0.to_le_bytes());
    header[8..12].copy_from_slice(&arg1.to_le_bytes());
    header[12..16].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    header[16..20].copy_from_slice(&checksum(payload).to_le_bytes());
    header[20..24].copy_from_slice(&magic(command).to_le_bytes());
    header
}

// ─── ADB Session ────────────────────────────────────────────────

pub struct AdbSession {
    pub target: String,
    pub port: u16,
    pub admin: bool,
    pub connection_string: String,
}

impl NxcSession for AdbSession {
    fn protocol(&self) -> &'static str {
        "adb"
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

// ─── ADB Protocol Handler ───────────────────────────────────────

pub struct AdbProtocol {
    pub timeout: Duration,
}

impl AdbProtocol {
    pub fn new() -> Self {
        Self { timeout: Duration::from_secs(10) }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Read a standard 24-byte ADB header from the stream.
    async fn read_packet_header(stream: &mut TcpStream) -> Result<(u32, u32, u32, u32, u32, u32)> {
        let mut header = [0u8; 24];
        stream.read_exact(&mut header).await?;

        let cmd = u32::from_le_bytes(
            header[0..4].try_into().unwrap_or_else(|_| panic!("Invalid bytes length")),
        );
        let arg0 = u32::from_le_bytes(
            header[4..8].try_into().unwrap_or_else(|_| panic!("Invalid bytes length")),
        );
        let arg1 = u32::from_le_bytes(
            header[8..12].try_into().unwrap_or_else(|_| panic!("Invalid bytes length")),
        );
        let len = u32::from_le_bytes(
            header[12..16].try_into().unwrap_or_else(|_| panic!("Invalid bytes length")),
        );
        let crc = u32::from_le_bytes(
            header[16..20].try_into().unwrap_or_else(|_| panic!("Invalid bytes length")),
        );
        let magic_val = u32::from_le_bytes(
            header[20..24].try_into().unwrap_or_else(|_| panic!("Invalid bytes length")),
        );

        if magic_val != magic(cmd) {
            return Err(anyhow!("Invalid ADB packet magic number"));
        }

        Ok((cmd, arg0, arg1, len, crc, magic_val))
    }

    /// Helper to do the initial CNXN exchange manually if we aren't saving the stream.
    async fn perform_handshake(stream: &mut TcpStream) -> Result<String> {
        let system_identity = b"host::nxc-rs\0";
        let cnxn_header = build_header(A_CNXN, A_VERSION, MAX_PAYLOAD, system_identity);

        stream.write_all(&cnxn_header).await?;
        stream.write_all(system_identity).await?;

        // Wait for CNXN or AUTH response
        let (cmd, _arg0, _arg1, payload_len, _crc, _magic) =
            Self::read_packet_header(stream).await?;

        if cmd == 0x48545541 {
            // AUTH
            return Err(anyhow!("ADB requested AUTH (RSA key). NXC-RS currently only supports open ADB debug bridges."));
        }

        if cmd != A_CNXN {
            return Err(anyhow!("Expected ADB CNXN response, got 0x{cmd:08x}"));
        }

        // Read the host connection string
        let mut string_buf = vec![0u8; payload_len as usize];
        stream.read_exact(&mut string_buf).await?;

        let conn_str = String::from_utf8_lossy(&string_buf).trim_end_matches('\0').to_string();
        Ok(conn_str)
    }
}

impl Default for AdbProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcProtocol for AdbProtocol {
    fn name(&self) -> &'static str {
        "adb"
    }

    fn default_port(&self) -> u16 {
        5555
    }

    fn supports_exec(&self) -> bool {
        true
    }

    fn supported_modules(&self) -> &[&str] {
        &[]
    }

    async fn connect(
        &self,
        target: &str,
        port: u16,
        _proxy: Option<&str>,
    ) -> Result<Box<dyn NxcSession>> {
        let addr = format!("{target}:{port}");
        debug!("ADB: Connecting to {}", addr);

        let timeout_fut = tokio::time::timeout(self.timeout, TcpStream::connect(&addr));
        let mut stream = match timeout_fut.await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(anyhow!("Connection refused or unreachable: {e}")),
            Err(_) => return Err(anyhow!("Connection timeout to {addr}")),
        };

        // Try standard handshake
        let conn_string =
            match tokio::time::timeout(self.timeout, Self::perform_handshake(&mut stream)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return Err(anyhow!("ADB Handshake Error: {e}")),
                Err(_) => return Err(anyhow!("Timeout waiting for ADB handshake response")),
            };

        info!("ADB: Connected to {} ({})", target, conn_string);

        // Let's assume root if it's open ADB (or we could execute `id` to check).
        let admin = conn_string.contains("ro.secure=0") || conn_string.contains("root");

        Ok(Box::new(AdbSession {
            target: target.to_string(),
            port,
            admin,
            connection_string: conn_string,
        }))
    }

    async fn authenticate(
        &self,
        _session: &mut dyn NxcSession,
        _creds: &Credentials,
    ) -> Result<AuthResult> {
        // ADB over TCP is usually root access without credentials, unless RSA key auth is requested
        // Handshake already handles Open ADB verification
        Ok(AuthResult::success(true))
    }

    async fn execute(&self, session: &dyn NxcSession, command: &str) -> Result<CommandOutput> {
        let target = session.target().to_string();

        // In nxc, we can only safely downcast by mutating through `as_any_mut`,
        // but `execute` only provides an immutable `&dyn NxcSession`.
        // Standard ADB port is 5555, so we use it directly as there's no easy immutable downcasting.
        let port = 5555;
        let addr = format!("{target}:{port}");

        let mut stream = TcpStream::connect(&addr).await?;

        // 1. Handshake again for the new TCP connection
        Self::perform_handshake(&mut stream).await?;

        // 2. Open `shell:` stream
        let shell_req = format!("shell:{command}\0");
        let shell_bytes = shell_req.as_bytes();
        let local_id = 1; // Arbitrary local stream identifier

        let open_hdr = build_header(A_OPEN, local_id, 0, shell_bytes);
        stream.write_all(&open_hdr).await?;
        stream.write_all(shell_bytes).await?;

        // 3. Wait for OKAY to confirm stream opened
        let (cmd, remote_id, _, _, _, _) = Self::read_packet_header(&mut stream).await?;
        if cmd != A_OKAY {
            return Err(anyhow!("ADB did not return OKAY for shell request. Got: 0x{cmd:08x}"));
        }

        // 4. Read WRTE packets until CLSE, gathering stdout
        let mut stdout = String::new();
        loop {
            let (cmd, _id0, _id1, payload_len, _, _) =
                match Self::read_packet_header(&mut stream).await {
                    Ok(hdr) => hdr,
                    Err(e) => {
                        warn!("ADB Stream read error: {}", e);
                        break;
                    }
                };

            if cmd == A_WRTE {
                let mut data = vec![0u8; payload_len as usize];
                stream.read_exact(&mut data).await?;

                stdout.push_str(&String::from_utf8_lossy(&data));

                // Acknowledge the WRTE with our OKAY
                let okay_hdr = build_header(A_OKAY, local_id, remote_id, &[]);
                stream.write_all(&okay_hdr).await?;
            } else if cmd == A_CLSE {
                // The remote side closed the channel.
                // Acknowledge and break
                let clse_hdr = build_header(A_CLSE, local_id, remote_id, &[]);
                let _ = stream.write_all(&clse_hdr).await;
                break;
            } else {
                // Discard payloads for other unknown packets to avoid losing sync
                if payload_len > 0 {
                    let mut tmp = vec![0u8; payload_len as usize];
                    let _ = stream.read_exact(&mut tmp).await;
                }
            }
        }

        Ok(CommandOutput {
            stdout,
            stderr: String::new(), // ADB merges stdio
            exit_code: Some(0),    // Not natively reported via ADB `WRTE` in basic implementations
        })
    }
}

impl AdbProtocol {
    /// Capture a screenshot from the Android device using `screencap -p`.
    pub async fn capture_screenshot(&self, session: &dyn NxcSession) -> Result<String> {
        let target = session.target().to_string();
        info!("ADB: Capturing screenshot from {}", target);

        // Execute `screencap -p` to get binary PNG data
        let output = self.execute(session, "screencap -p").await?;

        if output.stdout.is_empty() {
            return Err(anyhow!("ADB: screencap returned no data. Is the device screen off?"));
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)?
            .as_secs();
        let path = format!("screenshots/adb_{target}_{timestamp}.png");

        std::fs::create_dir_all("screenshots")?;
        std::fs::write(&path, output.stdout.as_bytes())?;

        info!("ADB: Screenshot saved to {}", path);
        Ok(path)
    }
}
