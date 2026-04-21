//! # String Obfuscation Utility
//!
//! XOR-based and AES-based obfuscation to hide common IOC strings from static analysis.
//! Supports single-byte XOR, multi-byte XOR keys, and AES-128-ECB encrypted strings.

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::Aes128;

// ─── Single-byte XOR ────────────────────────────────────────────

/// Deobfuscate an XOR-encoded string with a single-byte key.
pub fn deobfuscate(encoded: &[u8], key: u8) -> String {
    let decoded: Vec<u8> = encoded.iter().map(|&b| b ^ key).collect();
    String::from_utf8_lossy(&decoded).into_owned()
}

/// Obfuscate a string with a single-byte XOR key.
pub fn obfuscate(s: &str, key: u8) -> Vec<u8> {
    s.as_bytes().iter().map(|&b| b ^ key).collect()
}

// ─── Multi-byte XOR ─────────────────────────────────────────────

/// Obfuscate a string with a multi-byte XOR key.
///
/// Each byte of the input is XOR'd with the corresponding byte of the key
/// (cycling through the key for inputs longer than the key).
pub fn obfuscate_multi(s: &str, key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return s.as_bytes().to_vec();
    }
    s.as_bytes()
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

/// Deobfuscate data encrypted with a multi-byte XOR key.
pub fn deobfuscate_multi(encoded: &[u8], key: &[u8]) -> String {
    if key.is_empty() {
        return String::from_utf8_lossy(encoded).into_owned();
    }
    let decoded: Vec<u8> = encoded
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect();
    String::from_utf8_lossy(&decoded).into_owned()
}

// ─── Compile-time String Obfuscation ────────────────────────────

/// Compile-time XOR obfuscation macro.
///
/// Usage: `obfstr!("svcctl")` expands to a runtime-deobfuscated `String`.
/// The key `0xAA` is used; the obfuscated bytes are embedded as a const array.
///
/// This prevents plain-text IOC strings from appearing in the binary.
#[macro_export]
macro_rules! obfstr {
    ($s:expr) => {{
        const KEY: u8 = 0xAA;
        const INPUT: &[u8] = $s.as_bytes();
        const LEN: usize = INPUT.len();

        // Build the XOR'd array at compile time
        const fn xor_array<const N: usize>(input: &[u8]) -> [u8; N] {
            let mut out = [0u8; N];
            let mut i = 0;
            while i < N {
                out[i] = input[i] ^ KEY;
                i += 1;
            }
            out
        }

        // SAFETY: LEN is const, so this is deterministic
        let encoded: [u8; LEN] = xor_array::<LEN>(INPUT);
        let decoded: Vec<u8> = encoded.iter().map(|&b| b ^ KEY).collect();
        String::from_utf8_lossy(&decoded).into_owned()
    }};
}

// ─── AES-128 Encrypted Strings ──────────────────────────────────

/// Encrypt a string using AES-128-ECB with PKCS7 padding.
///
/// Returns the ciphertext bytes. The key must be exactly 16 bytes.
pub fn aes_encrypt(plaintext: &str, key: &[u8; 16]) -> Vec<u8> {
    let cipher = Aes128::new(key.into());
    let data = plaintext.as_bytes();

    // PKCS7 padding to 16-byte block boundary
    let pad_len = 16 - (data.len() % 16);
    let mut padded = data.to_vec();
    padded.extend(std::iter::repeat(pad_len as u8).take(pad_len));

    let mut ciphertext = Vec::with_capacity(padded.len());
    for chunk in padded.chunks_exact(16) {
        let mut block: aes::Block = chunk.try_into().unwrap();
        cipher.encrypt_block(&mut block);
        ciphertext.extend_from_slice(&block);
    }
    ciphertext
}

/// Decrypt an AES-128-ECB encrypted string, removing PKCS7 padding.
///
/// Returns the original plaintext. The key must be exactly 16 bytes.
pub fn aes_decrypt(ciphertext: &[u8], key: &[u8; 16]) -> Result<String, &'static str> {
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Err("Invalid ciphertext length");
    }

    let cipher = Aes128::new(key.into());
    let mut plaintext = Vec::with_capacity(ciphertext.len());

    for chunk in ciphertext.chunks_exact(16) {
        let mut block: aes::Block = chunk.try_into().unwrap();
        cipher.decrypt_block(&mut block);
        plaintext.extend_from_slice(&block);
    }

    // Remove PKCS7 padding
    let pad_byte = *plaintext.last().ok_or("Empty decrypted data")?;
    let pad_len = pad_byte as usize;
    if pad_len == 0 || pad_len > 16 {
        return Err("Invalid padding");
    }
    if plaintext.len() < pad_len {
        return Err("Padding exceeds data length");
    }
    // Verify padding bytes
    for &b in &plaintext[plaintext.len() - pad_len..] {
        if b != pad_byte {
            return Err("Invalid padding bytes");
        }
    }
    plaintext.truncate(plaintext.len() - pad_len);

    String::from_utf8(plaintext).map_err(|_| "Invalid UTF-8 after decryption")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_obfuscation_roundtrip() {
        let original = "svcctl";
        let key = 0x42;
        let encoded = obfuscate(original, key);
        let decoded = deobfuscate(&encoded, key);
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_multi_byte_xor_roundtrip() {
        let original = "\\\\target\\IPC$";
        let key = b"\xDE\xAD\xBE\xEF";
        let encoded = obfuscate_multi(original, key);
        let decoded = deobfuscate_multi(&encoded, key);
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_multi_byte_xor_longer_than_key() {
        let original = "This is a much longer string than the key";
        let key = b"\x01\x02\x03";
        let encoded = obfuscate_multi(original, key);
        let decoded = deobfuscate_multi(&encoded, key);
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_multi_byte_xor_empty_key() {
        let original = "passthrough";
        let encoded = obfuscate_multi(original, b"");
        assert_eq!(encoded, original.as_bytes());
        let decoded = deobfuscate_multi(&encoded, b"");
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_obfstr_macro() {
        let s = obfstr!("svcctl");
        assert_eq!(s, "svcctl");

        let s2 = obfstr!("cmd.exe /c whoami");
        assert_eq!(s2, "cmd.exe /c whoami");
    }

    #[test]
    fn test_aes_encrypt_decrypt_roundtrip() {
        let key: [u8; 16] = *b"NetExecRS_Key_1!";
        let original = "HKLM\\SAM";
        let encrypted = aes_encrypt(original, &key);
        assert_ne!(encrypted, original.as_bytes());

        let decrypted = aes_decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_aes_various_lengths() {
        let key: [u8; 16] = *b"0123456789abcdef";

        // Exact block size (16 bytes)
        let s16 = "0123456789abcdef";
        assert_eq!(aes_decrypt(&aes_encrypt(s16, &key), &key).unwrap(), s16);

        // Short string
        let short = "hi";
        assert_eq!(aes_decrypt(&aes_encrypt(short, &key), &key).unwrap(), short);

        // Multi-block string
        let long = "This string is definitely longer than sixteen bytes!";
        assert_eq!(aes_decrypt(&aes_encrypt(long, &key), &key).unwrap(), long);
    }

    #[test]
    fn test_aes_invalid_ciphertext() {
        let key: [u8; 16] = *b"0123456789abcdef";
        assert!(aes_decrypt(b"", &key).is_err());
        assert!(aes_decrypt(b"short", &key).is_err());
    }
}
