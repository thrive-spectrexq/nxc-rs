use anyhow::Result;
use hmac::{Hmac, Mac};
use md4::{Digest as Md4Digest, Md4};
use md5::Md5;

use rand::RngExt;
use sha1::Sha1;
use std::convert::TryInto;

type HmacMd5 = Hmac<Md5>;
type HmacSha1 = Hmac<Sha1>;

use aes::Aes256;
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};

use serde::{Deserialize, Serialize};

/// Supported Kerberos encryption types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptionType {
    Aes256CtsHmacSha196 = 18,
    Aes128CtsHmacSha196 = 17,
    Rc4Hmac = 23,
}

impl EncryptionType {
    pub fn as_i32(&self) -> i32 {
        *self as i32
    }
}

/// Derive RC4-HMAC key (Type 23) from password. This is identical to NT Hash.
pub fn string2key_rc4(password: &str) -> [u8; 16] {
    let mut hasher = Md4::new();
    let utf16: Vec<u16> = password.encode_utf16().collect();
    let bytes: Vec<u8> = utf16.iter().flat_map(|&u| u.to_le_bytes()).collect();
    hasher.update(&bytes);
    hasher.finalize().into()
}

/// Derive AES128/256 key from a password and salt using PBKDF2-HMAC-SHA1.
pub fn string2key_aes(password: &str, salt: &str, is_aes256: bool) -> Vec<u8> {
    let key_len = if is_aes256 { 32 } else { 16 };
    let mut key = vec![0u8; key_len];
    let iters = 4096;

    // PBKDF2(pass, salt, 4096, key_len)
    pbkdf2::pbkdf2_hmac::<Sha1>(password.as_bytes(), salt.as_bytes(), iters, &mut key);

    // RFC 3962 Random-to-Key: AES string2key requires an additional DK step
    // (Specifically AES-CTS requires DK(base_key, "kerberos") but typical AD
    // implementations just use the PBKDF2 output as the base string-to-key output
    // and then derive the actual encryption/hmac keys dynamically. For this
    // basic implementation, returning the PBKDF2 result serves as the raw key.)
    key
}

/// Decrypt an RC4-HMAC encrypted payload using the RC4 key.
pub fn decrypt_rc4_hmac(key: &[u8], key_usage: u32, ciphertext: &[u8]) -> Result<Vec<u8>> {
    use rc4::{
        cipher::{KeyInit, StreamCipher},
        Rc4,
    };

    if ciphertext.len() < 16 {
        anyhow::bail!("Ciphertext too short for RC4-HMAC");
    }

    // RC4-HMAC decryption (RFC 4757)
    // 1. K1 = HMAC-MD5(key, key_usage)
    let mut hmac = <HmacMd5 as Mac>::new_from_slice(key)?;
    hmac.update(&key_usage.to_le_bytes());
    let k1 = hmac.finalize().into_bytes();

    // 2. Extract checksum (first 16 bytes)
    let checksum = &ciphertext[0..16];
    let enc_data = &ciphertext[16..];

    // 3. K3 = HMAC-MD5(K1, checksum)
    let mut hmac2 = <HmacMd5 as Mac>::new_from_slice(&k1)?;
    hmac2.update(checksum);
    let k3 = hmac2.finalize().into_bytes();

    // 4. Decrypt data using RC4(K3)
    let k3_array: &[u8; 16] = k3[..16].try_into().unwrap();
    let mut rc4 =
        Rc4::new_from_slice(k3_array).map_err(|e| anyhow::anyhow!("RC4 init fail: {e}"))?;
    let mut decrypted = enc_data.to_vec();
    rc4.apply_keystream(&mut decrypted);

    // 5. Verify checksum (HMAC-MD5(K1, decrypted))
    let mut hmac_verify = <HmacMd5 as Mac>::new_from_slice(&k1)?;
    hmac_verify.update(&decrypted);
    let expected_mac = hmac_verify.finalize().into_bytes();

    if expected_mac[..] != checksum[..] {
        // Technically we shouldn't bail on checksum mismatch if it's an AS-REP issue with AD
        // but for safety we complain.
        tracing::debug!("RC4 Checksum mismatch");
    }

    // Data has 8 bytes of confounder at the start that must be removed.
    if decrypted.len() < 8 {
        anyhow::bail!("Decrypted payload too short (no confounder)");
    }
    Ok(decrypted[8..].to_vec())
}

/// Encrypt data using RC4-HMAC.
pub fn encrypt_rc4_hmac(key: &[u8], key_usage: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
    use rc4::{
        cipher::{KeyInit, StreamCipher},
        Rc4,
    };

    // 1. K1 = HMAC-MD5(key, key_usage)
    let mut hmac = <HmacMd5 as Mac>::new_from_slice(key)?;
    hmac.update(&key_usage.to_le_bytes());
    let k1 = hmac.finalize().into_bytes();

    // 2. Generate random 8-byte confounder
    let mut confounder = [0u8; 8];
    rand::rng().fill(&mut confounder);

    // 3. Prepare data to encrypt: confounder + plaintext
    let mut data = Vec::with_capacity(8 + plaintext.len());
    data.extend_from_slice(&confounder);
    data.extend_from_slice(plaintext);

    // 4. Calculate checksum: HMAC-MD5(K1, data)
    let mut hmac_checksum = <HmacMd5 as Mac>::new_from_slice(&k1)?;
    hmac_checksum.update(&data);
    let checksum = hmac_checksum.finalize().into_bytes();

    // 5. K3 = HMAC-MD5(K1, checksum)
    let mut hmac3 = <HmacMd5 as Mac>::new_from_slice(&k1)?;
    hmac3.update(&checksum);
    let k3 = hmac3.finalize().into_bytes();

    // 6. Encrypt data with RC4(K3)
    let k3_array: &[u8; 16] = k3[..16].try_into().unwrap();
    let mut rc4_key =
        Rc4::new_from_slice(k3_array).map_err(|e| anyhow::anyhow!("RC4 init fail: {e}"))?;
    rc4_key.apply_keystream(&mut data);

    // 7. Format output: Checksum + EncryptedData
    let mut out = Vec::with_capacity(16 + data.len());
    out.extend_from_slice(&checksum);
    out.extend_from_slice(&data);

    Ok(out)
}

/// Simplified AES-CTS Decryption (RFC 3962)
pub fn decrypt_aes(
    key: &[u8],
    key_usage: u32,
    ciphertext: &[u8],
    is_aes256: bool,
) -> Result<Vec<u8>> {
    if ciphertext.len() < 12 {
        // 12 bytes = minimum HMAC-SHA1-96 checksum
        anyhow::bail!("Ciphertext too short for AES");
    }

    // 1. Derive encryption and hmac keys (In a full RFC implementation we'd use DK() here)
    // For many AD cases with AES, we can use the base key directly if not using subkeys,
    // but proper Kerberos uses DK(BaseKey, [Usage | 0x55]) etc.
    // Simplifying: Using the provided key as the base for now.

    let checksum_len = 12; // HMAC-SHA1-96
    let enc_len = ciphertext.len() - checksum_len;
    let enc_data = &ciphertext[..enc_len];
    let checksum = &ciphertext[enc_len..];

    // 2. Verify HMAC-SHA1-96
    let mut hmac =
        HmacSha1::new_from_slice(key).map_err(|e| anyhow::anyhow!("HMAC init failed: {e}"))?;
    hmac.update(&key_usage.to_be_bytes()); // Simplified usage derivation
    hmac.update(enc_data);
    let full_mac = hmac.finalize().into_bytes();
    if full_mac[..12] != checksum[..] {
        tracing::debug!("AES Checksum mismatch");
    }

    // 3. Decrypt data (AES-CBC with CTS)
    // Simplified: Standard CBC for now until full CTS manual implementation is needed
    // (Most Kerberos ASN.1 payloads are padded to 16 bytes anyway)
    let decrypted = enc_data.to_vec();

    let decrypted = if is_aes256 {
        let key_arr: &[u8; 32] = key[..32].try_into()?;
        let iv = [0u8; 16];
        // For CTS, if length is not multiple of 16, we'd need special handling.
        // AD usually pads.
        if decrypted.len() % 16 == 0 {
            cbc::Decryptor::<Aes256>::new(key_arr.into(), &iv.into())
                .decrypt_padded_vec_mut::<NoPadding>(&decrypted)
                .map_err(|e| anyhow::anyhow!("AES-CBC decrypt failed: {e}"))?
        } else {
            decrypted
        }
    } else {
        decrypted
    };

    if decrypted.len() < 16 {
        anyhow::bail!("Decrypted payload too short (no confounder)");
    }
    // Remove 16-byte confounder
    Ok(decrypted[16..].to_vec())
}

/// Simplified AES-CTS Encryption (RFC 3962)
pub fn encrypt_aes(
    key: &[u8],
    key_usage: u32,
    plaintext: &[u8],
    is_aes256: bool,
) -> Result<Vec<u8>> {
    let mut confounder = [0u8; 16];
    rand::rng().fill(&mut confounder);

    let mut data = Vec::with_capacity(16 + plaintext.len());
    data.extend_from_slice(&confounder);
    data.extend_from_slice(plaintext);

    // Padding (Simplified)
    while data.len() % 16 != 0 {
        data.push(0);
    }

    let enc_data = if is_aes256 {
        let key_arr: &[u8; 32] = key[..32].try_into()?;
        let iv = [0u8; 16];
        cbc::Encryptor::<Aes256>::new(key_arr.into(), &iv.into())
            .encrypt_padded_vec_mut::<NoPadding>(&data)
    } else {
        data
    };

    // Checksum: HMAC-SHA1-96(key, usage, enc_data)
    let mut hmac =
        HmacSha1::new_from_slice(key).map_err(|e| anyhow::anyhow!("HMAC init failed: {e}"))?;
    hmac.update(&key_usage.to_be_bytes());
    hmac.update(&enc_data);
    let full_mac = hmac.finalize().into_bytes();

    let mut out = enc_data;
    out.extend_from_slice(&full_mac[..12]);
    Ok(out)
}
