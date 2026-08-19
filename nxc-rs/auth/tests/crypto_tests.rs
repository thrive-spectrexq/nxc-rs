//! Integration tests for Kerberos cryptographic operations.

use nxc_auth::kerberos::{
    decrypt_aes, decrypt_rc4_hmac, encrypt_aes, encrypt_rc4_hmac, string2key_aes, string2key_rc4,
};

#[test]
fn test_rc4_hmac_roundtrip() {
    let key = string2key_rc4("TestPassword123");
    let plaintext = b"Kerberos test payload for RC4-HMAC";
    let encrypted = encrypt_rc4_hmac(&key, 7, plaintext).unwrap();
    let decrypted = decrypt_rc4_hmac(&key, 7, &encrypted).unwrap();
    assert_eq!(&decrypted, plaintext);
}

#[test]
fn test_rc4_hmac_different_usage() {
    let key = string2key_rc4("Password");
    let plaintext = b"test data";
    let enc1 = encrypt_rc4_hmac(&key, 1, plaintext).unwrap();
    let enc2 = encrypt_rc4_hmac(&key, 3, plaintext).unwrap();
    // Different usage numbers must produce different ciphertext
    assert_ne!(enc1, enc2);
}

#[test]
fn test_rc4_checksum_tamper_detection() {
    let key = string2key_rc4("TestPassword");
    let plaintext = b"sensitive data";
    let mut encrypted = encrypt_rc4_hmac(&key, 7, plaintext).unwrap();
    // Tamper with the checksum (first 16 bytes)
    encrypted[4] ^= 0xFF;
    let result = decrypt_rc4_hmac(&key, 7, &encrypted);
    assert!(result.is_err(), "Tampered checksum should be detected");
}

#[test]
fn test_rc4_ciphertext_tamper_detection() {
    let key = string2key_rc4("TestPassword");
    let plaintext = b"sensitive data";
    let mut encrypted = encrypt_rc4_hmac(&key, 7, plaintext).unwrap();
    // Tamper with the encrypted data (after checksum)
    if encrypted.len() > 20 {
        encrypted[20] ^= 0xFF;
    }
    let result = decrypt_rc4_hmac(&key, 7, &encrypted);
    assert!(result.is_err(), "Tampered ciphertext should be detected");
}

#[test]
fn test_rc4_wrong_key() {
    let key1 = string2key_rc4("CorrectPassword");
    let key2 = string2key_rc4("WrongPassword");
    let plaintext = b"test data";
    let encrypted = encrypt_rc4_hmac(&key1, 7, plaintext).unwrap();
    let result = decrypt_rc4_hmac(&key2, 7, &encrypted);
    assert!(result.is_err(), "Wrong key should fail checksum");
}

#[test]
fn test_aes256_roundtrip() {
    let key = string2key_aes("TestPassword", "CORP.LOCALuser", true);
    assert_eq!(key.len(), 32, "AES-256 key should be 32 bytes");
    let plaintext = b"Kerberos AES-256 test payload!!!"; // 32 bytes, aligned
    let encrypted = encrypt_aes(&key, 7, plaintext, true).unwrap();
    let decrypted = decrypt_aes(&key, 7, &encrypted, true).unwrap();
    // After decryption, remove 16-byte confounder
    assert_eq!(&decrypted, plaintext);
}

#[test]
fn test_aes128_roundtrip() {
    let key = string2key_aes("TestPassword", "CORP.LOCALuser", false);
    assert_eq!(key.len(), 16, "AES-128 key should be 16 bytes");
    let plaintext = b"Kerberos AES-128 test payload!!!"; // 32 bytes, aligned
    let encrypted = encrypt_aes(&key, 7, plaintext, false).unwrap();
    let decrypted = decrypt_aes(&key, 7, &encrypted, false).unwrap();
    assert_eq!(&decrypted, plaintext);
}

#[test]
fn test_aes256_checksum_tamper_detection() {
    let key = string2key_aes("TestPassword", "CORP.LOCALuser", true);
    let plaintext = b"test sensitive Kerberos payload!!"; // 32 bytes
    let mut encrypted = encrypt_aes(&key, 7, plaintext, true).unwrap();
    // Tamper with the HMAC (last 12 bytes)
    let last = encrypted.len() - 1;
    encrypted[last] ^= 0xFF;
    let result = decrypt_aes(&key, 7, &encrypted, true);
    assert!(result.is_err(), "Tampered HMAC should be detected");
}

#[test]
fn test_string2key_rc4_deterministic() {
    let key1 = string2key_rc4("Password");
    let key2 = string2key_rc4("Password");
    assert_eq!(key1, key2);
}

#[test]
fn test_string2key_aes_deterministic() {
    let key1 = string2key_aes("Password", "EXAMPLE.COMuser", true);
    let key2 = string2key_aes("Password", "EXAMPLE.COMuser", true);
    assert_eq!(key1, key2);
}

#[test]
fn test_rc4_short_ciphertext_rejected() {
    let key = string2key_rc4("Password");
    let result = decrypt_rc4_hmac(&key, 7, &[0u8; 10]);
    assert!(result.is_err());
}

#[test]
fn test_aes_short_ciphertext_rejected() {
    let key = string2key_aes("Password", "CORP.LOCALuser", true);
    let result = decrypt_aes(&key, 7, &[0u8; 5], true);
    assert!(result.is_err());
}
