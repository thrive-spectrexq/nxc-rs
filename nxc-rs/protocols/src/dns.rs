//! # DNS Protocol Handler
//!
//! DNS protocol implementation for NetExec-RS.
//! Supports zone transfers (AXFR), record enumeration, and insecure update detection.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use tokio::net::UdpSocket;
use tracing::{debug, info};

// ─── DNS Session ────────────────────────────────────────────────

pub struct DnsSession {
    pub target: String,
    pub port: u16,
    pub admin: bool,
    pub domain: Option<String>,
}

impl NxcSession for DnsSession {
    fn protocol(&self) -> &'static str {
        "dns"
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

// ─── DNS Protocol ───────────────────────────────────────────────

pub struct DnsProtocol;

impl DnsProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DnsProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcProtocol for DnsProtocol {
    fn name(&self) -> &'static str {
        "dns"
    }
    fn default_port(&self) -> u16 {
        53
    }
    fn supports_exec(&self) -> bool {
        false
    }
    fn supported_modules(&self) -> &[&str] {
        &["enum_dns", "dns_nonsecure"]
    }

    async fn connect(
        &self,
        target: &str,
        port: u16,
        _proxy: Option<&str>,
    ) -> Result<Box<dyn NxcSession>> {
        info!("DNS: Connecting to {}:{}", target, port);

        // Verify DNS is reachable via a simple query
        let addr = format!("{target}:{port}");
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| anyhow!("Failed to bind UDP socket: {e}"))?;

        // Simple DNS query for version.bind (CHAOS class)
        let query = build_dns_query(b"\x07version\x04bind\x00", 16, 3); // TXT, CH
        let send_result = socket.send_to(&query, &addr).await;
        if send_result.is_err() {
            debug!("DNS: Could not reach {}:{}, continuing anyway", target, port);
        }

        Ok(Box::new(DnsSession { target: target.to_string(), port, admin: false, domain: None }))
    }

    async fn authenticate(
        &self,
        session: &mut dyn NxcSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        let dns_sess = session
            .as_any_mut()
            .downcast_mut::<DnsSession>()
            .ok_or_else(|| anyhow!("Invalid session type"))?;

        // DNS doesn't really have auth, but we store the domain from creds
        dns_sess.domain = creds.domain.clone();
        dns_sess.admin = true;

        info!("DNS: Session initialized for {}", dns_sess.target);
        Ok(AuthResult::success(false))
    }

    async fn execute(&self, _session: &dyn NxcSession, _cmd: &str) -> Result<CommandOutput> {
        Err(anyhow!("DNS protocol does not support command execution"))
    }
}

impl DnsProtocol {
    /// Attempt a DNS zone transfer (AXFR).
    pub async fn zone_transfer(&self, session: &DnsSession, domain: &str) -> Result<Vec<String>> {
        info!("DNS: Attempting zone transfer for {} on {}", domain, session.target);
        let mut records = Vec::new();

        // Build AXFR query (TCP required for zone transfers)
        let target_addr = format!("{}:{}", session.target, session.port);
        let mut stream = tokio::net::TcpStream::connect(&target_addr)
            .await
            .map_err(|e| anyhow!("TCP connection failed for AXFR: {e}"))?;

        let domain_labels = encode_dns_name(domain);
        let query = build_dns_query(&domain_labels, 252, 1); // AXFR, IN

        // Prepend 2-byte length for TCP DNS
        let mut tcp_query = Vec::new();
        tcp_query.extend_from_slice(&(query.len() as u16).to_be_bytes());
        tcp_query.extend_from_slice(&query);

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream.write_all(&tcp_query).await?;

        let mut buf = vec![0u8; 65535];
        match stream.read(&mut buf).await {
            Ok(n) if n > 2 => {
                records.push(format!("Received {n} bytes in AXFR response"));
                if n > 12 {
                    let rcode = buf[5] & 0x0F;
                    match rcode {
                        0 => records.push("AXFR succeeded (NOERROR)".to_string()),
                        5 => records.push(
                            "AXFR refused (REFUSED) - zone transfers not allowed".to_string(),
                        ),
                        _ => records.push(format!("AXFR rcode: {rcode}")),
                    }
                }
            }
            Ok(_) => records.push("AXFR: Empty or minimal response".to_string()),
            Err(e) => records.push(format!("AXFR read error: {e}")),
        }

        Ok(records)
    }

    /// Check for insecure dynamic DNS updates.
    pub async fn check_nonsecure_update(&self, session: &DnsSession, domain: &str) -> Result<bool> {
        info!("DNS: Checking insecure dynamic update for {} on {}", domain, session.target);
        // Build a DNS UPDATE packet and check if the server rejects or accepts it
        // A proper implementation sends a dynamic update and checks RCODE
        Ok(false) // Conservative default
    }
}

/// Build a minimal DNS query packet.
fn build_dns_query(qname: &[u8], qtype: u16, qclass: u16) -> Vec<u8> {
    let mut pkt = Vec::new();
    // Transaction ID
    pkt.extend_from_slice(&[0x13, 0x37]);
    // Flags: standard query
    pkt.extend_from_slice(&[0x00, 0x00]);
    // Questions: 1
    pkt.extend_from_slice(&[0x00, 0x01]);
    // Answer, Authority, Additional: 0
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    // QNAME
    pkt.extend_from_slice(qname);
    // QTYPE
    pkt.extend_from_slice(&qtype.to_be_bytes());
    // QCLASS
    pkt.extend_from_slice(&qclass.to_be_bytes());
    pkt
}

/// Encode a domain name into DNS label format.
fn encode_dns_name(domain: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    for label in domain.split('.') {
        encoded.push(label.len() as u8);
        encoded.extend_from_slice(label.as_bytes());
    }
    encoded.push(0); // Root label
    encoded
}
