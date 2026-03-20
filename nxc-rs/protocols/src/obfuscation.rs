//! # String Obfuscation Utility
//!
//! Simple XOR-based obfuscation to hide common IOC strings from static analysis.

/// Deobfuscate an XOR-encoded string.
pub fn deobfuscate(encoded: &[u8], key: u8) -> String {
    let decoded: Vec<u8> = encoded.iter().map(|&b| b ^ key).collect();
    String::from_utf8_lossy(&decoded).into_owned()
}

/// Helper to obfuscate a string at compile-time (manual for now or use this to generate).
pub fn obfuscate(s: &str, key: u8) -> Vec<u8> {
    s.as_bytes().iter().map(|&b| b ^ key).collect()
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
}
