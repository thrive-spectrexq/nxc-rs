use crate::Credentials;
use anyhow::{anyhow, Result};
use once_cell::sync::Lazy;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use tokio::sync::Mutex;

use super::asn1::*;
use super::crypto::{decrypt_rc4_hmac, encrypt_rc4_hmac, string2key_rc4, EncryptionType};
use rasn::types::GeneralizedTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KerberosTicket {
    pub client_realm: String,
    pub client_name: String,
    pub server_realm: String,
    pub server_name: String,
    pub session_key: Vec<u8>,
    pub ticket_data: Vec<u8>,
    pub enc_type: EncryptionType,
}

/// Primary Kerberos client for AS/TGS exchanges
pub struct KerberosClient {
    domain: String,
    kdc_ip: String,
}

static TICKET_CACHE: Lazy<Mutex<HashMap<String, KerberosTicket>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

impl KerberosClient {
    pub fn new(domain: &str, kdc_ip: &str) -> Self {
        Self { domain: domain.to_string(), kdc_ip: kdc_ip.to_string() }
    }

    /// Perform a TCP send/receive to the KDC (port 88)
    fn _send_tcp_req(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let addr = format!("{}:88", &self.kdc_ip);
        let mut stream = TcpStream::connect_timeout(&addr.parse()?, Duration::from_secs(5))?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;

        // 4 byte length header for Kerberos over TCP
        let len_bytes = (payload.len() as u32).to_be_bytes();
        stream.write_all(&len_bytes)?;
        stream.write_all(payload)?;

        // Receive length header
        let mut resp_len_buf = [0u8; 4];
        stream.read_exact(&mut resp_len_buf)?;
        let resp_len = u32::from_be_bytes(resp_len_buf) as usize;

        if resp_len > 10 * 1024 * 1024 {
            anyhow::bail!("KDC returned excessively large response");
        }

        let mut resp_data = vec![0u8; resp_len];
        stream.read_exact(&mut resp_data)?;

        Ok(resp_data)
    }

    /// Helper to request a TGT using a Credentials object.
    pub async fn request_tgt_with_creds(&self, creds: &Credentials) -> Result<KerberosTicket> {
        let cache_key = format!("{}@{}", creds.username.to_lowercase(), self.domain.to_lowercase());

        {
            let cache = TICKET_CACHE.lock().await;
            if let Some(ticket) = cache.get(&cache_key) {
                tracing::debug!("Kerberos: Using cached TGT for {}", cache_key);
                return Ok(ticket.clone());
            }
        }

        tracing::debug!("Kerberos: No cached TGT for {}, requesting new one...", cache_key);
        let ticket = self
            .request_tgt(
                &creds.username,
                creds.password.as_deref(),
                creds.nt_hash.as_deref(),
                creds.aes_256_key.as_deref(),
            )
            .await?;

        {
            let mut cache = TICKET_CACHE.lock().await;
            cache.insert(cache_key, ticket.clone());
        }

        Ok(ticket)
    }

    pub async fn request_tgt(
        &self,
        username: &str,
        password: Option<&str>,
        nt_hash: Option<&str>,
        _aes_key: Option<&str>,
    ) -> Result<KerberosTicket> {
        let domain_realm = self.domain.to_uppercase();

        let req_body = KdcReqBody {
            kdc_options: rasn::types::BitString::from_slice(&[0x40, 0x81, 0x00, 0x00]),
            cname: Some(PrincipalName::new(1, [username].as_slice())), // NT-PRINCIPAL
            realm: Realm::new(&domain_realm),
            sname: Some(PrincipalName::new(2, ["krbtgt", &domain_realm].as_slice())), // NT-SRV-INST
            from: None,
            till: GeneralizedTime::from(chrono::Utc::now() + chrono::Duration::hours(10)),
            rtime: Some(GeneralizedTime::from(chrono::Utc::now() + chrono::Duration::days(1))),
            nonce: rand::rng().random::<u32>() & 0x7FFFFFFF,
            etype: vec![18, 17, 23], // AES256, AES128, RC4
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        };

        let mut padata = Vec::new();

        let key = if let Some(hash) = nt_hash {
            hex::decode(hash)?
        } else if let Some(pass) = password {
            string2key_rc4(pass).to_vec()
        } else {
            vec![]
        };

        if !key.is_empty() {
            let now = GeneralizedTime::from(chrono::Utc::now());
            let ts_der = rasn::der::encode(&now).map_err(|e| anyhow!("ASN.1 encode error: {e}"))?;
            let enc_ts = encrypt_rc4_hmac(&key, 1, &ts_der)?; // Usage 1

            padata.push(PaData {
                padata_type: 2, // PA-ENC-TIMESTAMP
                padata_value: rasn::der::encode(&EncryptedData {
                    etype: 23,
                    kvno: None,
                    cipher: enc_ts.into(),
                })
                .map_err(|e| anyhow!("ASN.1 encode error: {e}"))?
                .into(),
            });
        }

        let as_req = AsReq(KdcReq {
            pvno: 5,
            msg_type: 10, // AS-REQ
            padata: if padata.is_empty() { None } else { Some(padata) },
            req_body,
        });

        let req_der = rasn::der::encode(&as_req).map_err(|e| anyhow!("ASN.1 encode error: {e}"))?;
        let resp_der = self._send_tcp_req(&req_der)?;

        // Parse AS-REP
        let as_rep: AsRep =
            rasn::der::decode(&resp_der).map_err(|e| anyhow!("ASN.1 decode error: {e}"))?;

        // Decrypt EncPart
        let enc_part = decrypt_rc4_hmac(&key, 3, &as_rep.0.enc_part.cipher)?; // Usage 3
        let decrypted_part: EncAsRepPart =
            rasn::der::decode(&enc_part).map_err(|e| anyhow!("Decryption parse error: {e}"))?;

        Ok(KerberosTicket {
            client_realm: self.domain.clone(),
            client_name: username.to_string(),
            server_realm: self.domain.clone(),
            server_name: "krbtgt".to_string(),
            session_key: decrypted_part.0.key.keyvalue.to_vec(),
            ticket_data: rasn::der::encode(&as_rep.0.ticket)
                .map_err(|e| anyhow!("Ticket re-encode error: {e}"))?,
            enc_type: EncryptionType::Rc4Hmac,
        })
    }

    pub async fn request_tgs(&self, tgt: &KerberosTicket, spn: &str) -> Result<KerberosTicket> {
        let domain_realm = self.domain.to_uppercase();
        let spn_parts: Vec<&str> = spn.split('/').collect();

        let req_body = KdcReqBody {
            kdc_options: rasn::types::BitString::from_slice(&[0x40, 0x81, 0x00, 0x00]),
            cname: None,
            realm: Realm::new(&domain_realm),
            sname: Some(PrincipalName::new(2, &spn_parts)), // NT-SRV-INST
            from: None,
            till: GeneralizedTime::from(chrono::Utc::now() + chrono::Duration::hours(10)),
            rtime: Some(GeneralizedTime::from(chrono::Utc::now() + chrono::Duration::days(1))),
            nonce: rand::rng().random::<u32>() & 0x7FFFFFFF,
            etype: vec![18, 17, 23],
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        };

        let ap_req = self.build_ap_req(tgt)?;
        let padata = vec![PaData {
            padata_type: 1, // PA-TGS-REQ
            padata_value: ap_req.into(),
        }];

        let tgs_req = TgsReq(KdcReq {
            pvno: 5,
            msg_type: 12, // TGS-REQ
            padata: Some(padata),
            req_body,
        });

        let req_der =
            rasn::der::encode(&tgs_req).map_err(|e| anyhow!("ASN.1 encode error: {e}"))?;
        let resp_der = self._send_tcp_req(&req_der)?;

        // Parse TGS-REP
        let tgs_rep: TgsRep =
            rasn::der::decode(&resp_der).map_err(|e| anyhow!("ASN.1 decode error: {e}"))?;

        // Decrypt EncPart
        let enc_part = decrypt_rc4_hmac(&tgt.session_key, 8, &tgs_rep.0.enc_part.cipher)?; // Usage 8
        let decrypted_part: EncTgsRepPart =
            rasn::der::decode(&enc_part).map_err(|e| anyhow!("Decryption parse error: {e}"))?;

        Ok(KerberosTicket {
            client_realm: self.domain.clone(),
            client_name: tgt.client_name.clone(),
            server_realm: self.domain.clone(),
            server_name: spn.to_string(),
            session_key: decrypted_part.0.key.keyvalue.to_vec(),
            ticket_data: rasn::der::encode(&tgs_rep.0.ticket)
                .map_err(|e| anyhow!("Ticket re-encode error: {e}"))?,
            enc_type: EncryptionType::Rc4Hmac,
        })
    }

    pub fn build_ap_req(&self, tgt: &KerberosTicket) -> Result<Vec<u8>> {
        let now = GeneralizedTime::from(chrono::Utc::now());
        let authenticator = Authenticator {
            authenticator_vno: 5,
            crealm: Realm::new(&tgt.client_realm),
            cname: PrincipalName::new(1, [tgt.client_name.as_str()].as_slice()), // NT-PRINCIPAL
            cksum: None,
            cusec: 0,
            ctime: now,
            subkey: None,
            seq_number: None,
            authorization_data: None,
        };

        let auth_der =
            rasn::der::encode(&authenticator).map_err(|e| anyhow!("ASN.1 encode error: {e}"))?;
        let enc_auth = encrypt_rc4_hmac(&tgt.session_key, 11, &auth_der)?; // Usage 11

        let ap_req = ApReq {
            pvno: 5,
            msg_type: 14, // AP-REQ
            ap_options: rasn::types::BitString::from_slice(&[0x00, 0x00, 0x00, 0x00]),
            ticket: rasn::der::decode(&tgt.ticket_data)
                .map_err(|e| anyhow!("Ticket parse error: {e}"))?,
            authenticator: EncryptedData { etype: 23, kvno: None, cipher: enc_auth.into() },
        };

        rasn::der::encode(&ap_req).map_err(|e| anyhow!("ASN.1 encode error: {e}"))
    }
}
