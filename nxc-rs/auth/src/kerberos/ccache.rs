//! # MIT CCache v4 Parser
//!
//! Parses MIT Kerberos credential cache files (version 0x0504) to extract
//! TGT and service tickets for offline/ccache-based authentication.

use anyhow::{anyhow, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use super::client::KerberosTicket;
use super::crypto::EncryptionType;

/// Parses a MIT CCache v4 file and extracts all credential entries as `KerberosTicket` objects.
pub fn parse_ccache_v4(path: &str) -> Result<Vec<KerberosTicket>> {
    let mut file = File::open(path)?;
    let mut magic = [0u8; 2];
    file.read_exact(&mut magic)?;

    if magic != [0x05, 0x04] {
        anyhow::bail!(
            "Unsupported CCache version. Expected 0x0504, got 0x{:02x}{:02x}.",
            magic[0],
            magic[1]
        );
    }

    // Read header length (big-endian u16)
    let header_len = read_u16_be(&mut file)?;

    // Skip header tags
    file.seek(SeekFrom::Current(header_len as i64))?;

    // Parse the default principal
    let _default_principal = read_principal(&mut file)?;

    // Parse credential entries
    let mut tickets = Vec::new();
    while let Ok(ticket) = read_credential(&mut file) {
        tickets.push(ticket);
    }

    if tickets.is_empty() {
        tracing::warn!("CCache: No credential entries found in {path}");
    } else {
        tracing::info!("CCache: Parsed {} credential(s) from {path}", tickets.len());
    }

    Ok(tickets)
}

/// Read a big-endian u16.
fn read_u16_be(r: &mut impl Read) -> Result<u16> {
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf)?;
    Ok(u16::from_be_bytes(buf))
}

/// Read a big-endian u32.
fn read_u32_be(r: &mut impl Read) -> Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

/// Read a counted octet string (4-byte BE length prefix + data).
fn read_data(r: &mut impl Read) -> Result<Vec<u8>> {
    let len = read_u32_be(r)? as usize;
    if len > 10 * 1024 * 1024 {
        return Err(anyhow!("CCache data field too large: {len} bytes"));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// A CCache principal: name_type (u32), num_components (u32), realm, components[].
#[derive(Debug, Clone)]
struct CcachePrincipal {
    #[allow(dead_code)]
    name_type: u32,
    realm: String,
    components: Vec<String>,
}

impl CcachePrincipal {
    fn to_string_rep(&self) -> String {
        let name = self.components.join("/");
        if self.realm.is_empty() {
            name
        } else {
            format!("{name}@{}", self.realm)
        }
    }
}

/// Read a principal from the CCache stream.
fn read_principal(r: &mut impl Read) -> Result<CcachePrincipal> {
    let name_type = read_u32_be(r)?;
    let num_components = read_u32_be(r)?;

    // Realm
    let realm_bytes = read_data(r)?;
    let realm = String::from_utf8_lossy(&realm_bytes).to_string();

    // Components
    let mut components = Vec::with_capacity(num_components as usize);
    for _ in 0..num_components {
        let comp_bytes = read_data(r)?;
        components.push(String::from_utf8_lossy(&comp_bytes).to_string());
    }

    Ok(CcachePrincipal { name_type, realm, components })
}

/// A Kerberos keyblock: enc_type (u16), data.
#[derive(Debug, Clone)]
struct CcacheKeyblock {
    enc_type: u16,
    data: Vec<u8>,
}

fn read_keyblock(r: &mut impl Read) -> Result<CcacheKeyblock> {
    let enc_type = read_u16_be(r)?;
    let data = read_data(r)?;
    Ok(CcacheKeyblock { enc_type, data })
}

/// Read a single credential entry and convert to `KerberosTicket`.
fn read_credential(r: &mut impl Read) -> Result<KerberosTicket> {
    // Client principal
    let client = read_principal(r)?;

    // Server principal
    let server = read_principal(r)?;

    // Keyblock (session key)
    let keyblock = read_keyblock(r)?;

    // Times: authtime, starttime, endtime, renew_till (4× u32)
    let _authtime = read_u32_be(r)?;
    let _starttime = read_u32_be(r)?;
    let _endtime = read_u32_be(r)?;
    let _renew_till = read_u32_be(r)?;

    // is_skey (u8), ticket_flags (u32)
    let mut is_skey_buf = [0u8; 1];
    r.read_exact(&mut is_skey_buf)?;
    let _ticket_flags = read_u32_be(r)?;

    // Addresses: count (u32) then addr entries
    let num_addrs = read_u32_be(r)?;
    for _ in 0..num_addrs {
        let _addr_type = read_u16_be(r)?;
        let _addr_data = read_data(r)?;
    }

    // AuthData: count (u32) then authdata entries
    let num_authdata = read_u32_be(r)?;
    for _ in 0..num_authdata {
        let _ad_type = read_u16_be(r)?;
        let _ad_data = read_data(r)?;
    }

    // Ticket (the actual Kerberos ticket blob)
    let ticket_data = read_data(r)?;

    // Second ticket (for user-to-user, usually empty)
    let _second_ticket = read_data(r)?;

    let enc_type = match keyblock.enc_type {
        17 => EncryptionType::Aes128CtsHmacSha196,
        18 => EncryptionType::Aes256CtsHmacSha196,
        23 => EncryptionType::Rc4Hmac,
        _ => EncryptionType::Rc4Hmac, // Fallback
    };

    Ok(KerberosTicket {
        client_realm: client.realm.clone(),
        client_name: client.to_string_rep(),
        server_realm: server.realm.clone(),
        server_name: server.to_string_rep(),
        session_key: keyblock.data,
        ticket_data,
        enc_type,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Build a minimal valid ccache v4 byte stream for testing.
    fn build_test_ccache() -> Vec<u8> {
        let mut buf = Vec::new();

        // Magic: 0x0504
        buf.extend_from_slice(&[0x05, 0x04]);
        // Header length: 0 (no header tags)
        buf.extend_from_slice(&[0x00, 0x00]);

        // Default principal: name_type=1, 1 component, realm="TEST.LOCAL", name="user"
        buf.extend_from_slice(&0u32.to_be_bytes()); // name_type (ignored for default)
        buf.extend_from_slice(&1u32.to_be_bytes()); // num_components
        let realm = b"TEST.LOCAL";
        buf.extend_from_slice(&(realm.len() as u32).to_be_bytes());
        buf.extend_from_slice(realm);
        let comp = b"user";
        buf.extend_from_slice(&(comp.len() as u32).to_be_bytes());
        buf.extend_from_slice(comp);

        // Credential entry
        // Client principal: same as default
        buf.extend_from_slice(&1u32.to_be_bytes()); // name_type
        buf.extend_from_slice(&1u32.to_be_bytes()); // num_components
        buf.extend_from_slice(&(realm.len() as u32).to_be_bytes());
        buf.extend_from_slice(realm);
        buf.extend_from_slice(&(comp.len() as u32).to_be_bytes());
        buf.extend_from_slice(comp);

        // Server principal: krbtgt/TEST.LOCAL@TEST.LOCAL
        buf.extend_from_slice(&2u32.to_be_bytes()); // name_type (NT-SRV-INST)
        buf.extend_from_slice(&2u32.to_be_bytes()); // num_components
        buf.extend_from_slice(&(realm.len() as u32).to_be_bytes());
        buf.extend_from_slice(realm);
        let svc = b"krbtgt";
        buf.extend_from_slice(&(svc.len() as u32).to_be_bytes());
        buf.extend_from_slice(svc);
        buf.extend_from_slice(&(realm.len() as u32).to_be_bytes());
        buf.extend_from_slice(realm);

        // Keyblock: enc_type=23 (RC4), 16 bytes key
        buf.extend_from_slice(&23u16.to_be_bytes());
        let key = [0xAAu8; 16];
        buf.extend_from_slice(&(key.len() as u32).to_be_bytes());
        buf.extend_from_slice(&key);

        // Times: authtime, starttime, endtime, renew_till
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());

        // is_skey=0, ticket_flags=0
        buf.push(0);
        buf.extend_from_slice(&0u32.to_be_bytes());

        // Addresses: 0
        buf.extend_from_slice(&0u32.to_be_bytes());

        // AuthData: 0
        buf.extend_from_slice(&0u32.to_be_bytes());

        // Ticket blob (dummy 4 bytes)
        let ticket = [0x30, 0x82, 0x01, 0x00];
        buf.extend_from_slice(&(ticket.len() as u32).to_be_bytes());
        buf.extend_from_slice(&ticket);

        // Second ticket: empty
        buf.extend_from_slice(&0u32.to_be_bytes());

        buf
    }

    #[test]
    fn test_parse_principal() {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_be_bytes()); // name_type
        data.extend_from_slice(&2u32.to_be_bytes()); // num_components
        let realm = b"CORP.LOCAL";
        data.extend_from_slice(&(realm.len() as u32).to_be_bytes());
        data.extend_from_slice(realm);
        let c1 = b"krbtgt";
        data.extend_from_slice(&(c1.len() as u32).to_be_bytes());
        data.extend_from_slice(c1);
        let c2 = b"CORP.LOCAL";
        data.extend_from_slice(&(c2.len() as u32).to_be_bytes());
        data.extend_from_slice(c2);

        let mut cursor = Cursor::new(data);
        let principal = read_principal(&mut cursor).unwrap();
        assert_eq!(principal.realm, "CORP.LOCAL");
        assert_eq!(principal.components, vec!["krbtgt", "CORP.LOCAL"]);
        assert_eq!(principal.to_string_rep(), "krbtgt/CORP.LOCAL@CORP.LOCAL");
    }

    #[test]
    fn test_parse_ccache_stream() {
        let data = build_test_ccache();
        // Write to temp file
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.ccache");
        std::fs::write(&path, &data).unwrap();

        let tickets = parse_ccache_v4(path.to_str().unwrap()).unwrap();
        assert_eq!(tickets.len(), 1);
        assert_eq!(tickets[0].client_realm, "TEST.LOCAL");
        assert_eq!(tickets[0].server_name, "krbtgt/TEST.LOCAL@TEST.LOCAL");
        assert_eq!(tickets[0].session_key, vec![0xAA; 16]);
    }

    #[test]
    fn test_invalid_magic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.ccache");
        std::fs::write(&path, &[0x05, 0x03, 0x00, 0x00]).unwrap();
        assert!(parse_ccache_v4(path.to_str().unwrap()).is_err());
    }
}
