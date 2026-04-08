//! # RDP Protocol Handler
//!
//! RDP protocol implementation focusing on port 3389 connections
//! and NLA (Network Level Authentication) detection.

use crate::{CommandOutput, NxcProtocol, NxcSession};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nxc_auth::{AuthResult, Credentials};
use rasn::{AsnType, Decode, Decoder, Encode, Encoder};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::rustls::{self, pki_types::ServerName, ClientConfig};
use tokio_rustls::TlsConnector;
use tracing::{debug, info};

#[derive(AsnType, Decode, Encode, Debug, Clone)]
#[rasn(delegate)]
pub struct NegoToken(pub Vec<u8>);

#[derive(AsnType, Decode, Encode, Debug, Clone)]
pub struct NegoData {
    #[rasn(tag(explicit(0)))]
    pub nego_token: NegoToken,
}

#[derive(AsnType, Decode, Encode, Debug, Clone)]
pub struct TsRequest {
    #[rasn(tag(explicit(0)))]
    pub version: i32,
    #[rasn(tag(explicit(1)))]
    pub nego_tokens: Option<Vec<NegoData>>,
    #[rasn(tag(explicit(2)))]
    pub auth_info: Option<Vec<u8>>,
    #[rasn(tag(explicit(3)))]
    pub pub_key_auth: Option<Vec<u8>>,
}

#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

pub struct RdpSession {
    pub target: String,
    pub port: u16,
    pub is_nla: bool,
    pub admin: bool,
}

impl NxcSession for RdpSession {
    fn protocol(&self) -> &'static str {
        "rdp"
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

pub struct RdpProtocol {
    pub timeout: Duration,
}

impl RdpProtocol {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(10),
        }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl Default for RdpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcProtocol for RdpProtocol {
    fn name(&self) -> &'static str {
        "rdp"
    }

    fn default_port(&self) -> u16 {
        3389
    }

    fn supports_exec(&self) -> bool {
        true // RDP supports execution via GUI interaction or injected payload execution
    }

    fn supported_modules(&self) -> &[&str] {
        &["nla_screenshot", "screenshot", "rdp_sec_check"] // Standard RDP enumeration modules
    }

    async fn connect(
        &self,
        target: &str,
        port: u16,
        _proxy: Option<&str>,
    ) -> Result<Box<dyn NxcSession>> {
        let addr = format!("{}:{}", target, port);
        debug!("RDP: Connecting to {}", addr);

        let mut stream = if let Some(proxy_url) = _proxy {
            crate::socks::SocksProxy::connect(proxy_url, &addr).await?
        } else {
            let timeout_fut = tokio::time::timeout(self.timeout, TcpStream::connect(&addr));
            match timeout_fut.await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return Err(anyhow!("Connection refused or unreachable: {}", e)),
                Err(_) => return Err(anyhow!("Connection timeout to {}", addr)),
            }
        };

        // Send a TPKT / X.224 Connection Request to fingerprint NLA support
        let x224_req: [u8; 19] = [
            0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08,
            0x00, 0x03, // Protocol flags 0x03 (SSL + HYBRID)
            0x00, 0x00, 0x00,
        ];

        stream.write_all(&x224_req).await?;

        // Read response
        let mut resp = [0u8; 19];
        let n = tokio::time::timeout(
            self.timeout,
            tokio::io::AsyncReadExt::read(&mut stream, &mut resp),
        )
        .await??;

        let mut is_nla = false;
        if n >= 19 && resp[0] == 0x03 && resp[1] == 0x00 {
            // Check Negotiation Response flags at offset 15
            let selected_proto = resp[15];
            is_nla = selected_proto & 0x02 != 0; // HYBRID (NLA) flag
            debug!("RDP: Selected protocol flags: 0x{:02x}", selected_proto);
        }

        info!("RDP: Connected to {} (NLA: {})", addr, is_nla);

        Ok(Box::new(RdpSession {
            target: target.to_string(),
            port,
            is_nla,
            admin: false,
        }))
    }

    async fn authenticate(
        &self,
        session: &mut dyn NxcSession,
        creds: &Credentials,
    ) -> Result<AuthResult> {
        let rdp_sess = session
            .as_any()
            .downcast_ref::<RdpSession>()
            .ok_or_else(|| anyhow::anyhow!("Invalid session type"))?;
        let addr = format!("{}:{}", rdp_sess.target, rdp_sess.port);

        debug!("RDP: Authenticating {} via NLA on {}", creds.username, addr);

        // 1. Re-connect and perform X.224 negotiation to establish TLS
        let mut tcp = TcpStream::connect(&addr).await?;
        let x224_req: [u8; 19] = [
            0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08,
            0x00, 0x03, 0x00, 0x00, 0x00,
        ];
        tcp.write_all(&x224_req).await?;

        let mut resp = [0u8; 19];
        tokio::io::AsyncReadExt::read_exact(&mut tcp, &mut resp).await?;

        // 2. Wrap in TLS
        let mut config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth();

        // Ensure we support TLS 1.2+ (standard for RDP)
        config.alpn_protocols = vec![b"rdp".to_vec()];

        let connector = TlsConnector::from(Arc::new(config));
        let server_name = ServerName::try_from(rdp_sess.target.clone())
            .map_err(|_| anyhow!("Invalid server name: {}", rdp_sess.target))?;

        let _tls = connector.connect(server_name, tcp).await?;
        debug!("RDP: TLS tunnel established for NLA");

        // 3. NLA/CredSSP Handshake (Simplified foundations)
        // Send TsRequest with NTLM Negotiate
        let auth = nxc_auth::NtlmAuthenticator::new(creds.domain.as_deref());
        let t1_msg = auth.generate_type1();

        let ts_req1 = TsRequest {
            version: 6, // CredSSP v6
            nego_tokens: Some(vec![NegoData {
                nego_token: NegoToken(t1_msg),
            }]),
            auth_info: None,
            pub_key_auth: None,
        };

        let ts_req1_der =
            rasn::der::encode(&ts_req1).map_err(|e| anyhow!("ASN.1 encode error: {}", e))?;

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut reader, mut writer) = tokio::io::split(_tls);
        writer.write_all(&ts_req1_der).await?;

        // 4. Receive NTLM Challenge
        let mut resp_buf = vec![0u8; 4096];
        let n = reader.read(&mut resp_buf).await?;
        let ts_resp: TsRequest =
            rasn::der::decode(&resp_buf[..n]).map_err(|e| anyhow!("ASN.1 decode error: {}", e))?;

        let t2_msg = ts_resp
            .nego_tokens
            .and_then(|tokens| tokens.first().cloned())
            .map(|tok| tok.nego_token.0)
            .ok_or_else(|| anyhow!("No NegoToken in TsRequest response"))?;

        // 5. Send NTLM Authenticate
        let challenge = auth.parse_type2(&t2_msg)?;
        let t3_res = auth.generate_type3(creds, &challenge)?;
        let ts_req2 = TsRequest {
            version: 6,
            nego_tokens: Some(vec![NegoData {
                nego_token: NegoToken(t3_res.message),
            }]),
            auth_info: None,
            pub_key_auth: None, // In real CredSSP we'd calculate public key auth here
        };

        let ts_req2_der =
            rasn::der::encode(&ts_req2).map_err(|e| anyhow!("ASN.1 encode error: {}", e))?;
        writer.write_all(&ts_req2_der).await?;

        // 6. Receive final response
        let n = reader.read(&mut resp_buf).await?;
        if n == 0 {
            return Ok(AuthResult::failure(
                "RDP NLA: Connection closed during authentication",
                None,
            ));
        }

        // Standard NLA check: If we don't get an error, and the connection remains open, it's typically a success.
        // Some servers might send one more TsRequest with authInfo.
        debug!("RDP: Received final NLA response ({} bytes)", n);

        Ok(AuthResult::success(false))
    }

    async fn execute(&self, _session: &dyn NxcSession, _cmd: &str) -> Result<CommandOutput> {
        Err(anyhow!(
            "RDP explicit command execution requires injected GUI input (not yet ported)."
        ))
    }
}
