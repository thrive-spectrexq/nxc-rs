//! # Windows Registry Hive Parser & Credential Extractor
//!
//! Logic for parsing offline SAM, SYSTEM, and SECURITY hives to extract
//! Boot Key, NT hashes, and LSA secrets.

use anyhow::{anyhow, Result};
use hmac::Hmac;
use md5::{Digest, Md5};
use nt_hive::{Hive, KeyNode, KeyValue};
use rc4::{KeyInit, Rc4, StreamCipher};
use sha2::Sha256;

#[allow(dead_code)]
type HmacSha256 = Hmac<Sha256>;

/// Registry Secret Extractor
pub struct RegistrySecrets;

impl RegistrySecrets {
    /// Extract the 16-byte Boot Key (System Key) from the SYSTEM hive.
    pub fn get_boot_key(system_hive_data: &[u8]) -> Result<[u8; 16]> {
        let hive = Hive::new(system_hive_data)
            .map_err(|e| anyhow!("Failed to parse SYSTEM hive: {}", e))?;
        let root = hive
            .root_key_node()
            .map_err(|e| anyhow!("No root key node in SYSTEM hive: {}", e))?;

        let jd = Self::get_classname_by_path(&root, "ControlSet001\\Control\\Lsa\\JD")?;
        let skew1 = Self::get_classname_by_path(&root, "ControlSet001\\Control\\Lsa\\Skew1")?;
        let gbg = Self::get_classname_by_path(&root, "ControlSet001\\Control\\Lsa\\GBG")?;
        let data = Self::get_classname_by_path(&root, "ControlSet001\\Control\\Lsa\\Data")?;

        let scrambled_hex = format!("{}{}{}{}", jd, skew1, gbg, data);
        let decoded = hex::decode(scrambled_hex)?;
        if decoded.len() < 16 {
            return Err(anyhow!("Invalid boot key length"));
        }

        let transforms = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7];
        let mut boot_key = [0u8; 16];
        for i in 0..16 {
            boot_key[i] = decoded[transforms[i]];
        }
        Ok(boot_key)
    }

    /// Extract NT hashes from the SAM hive using the Boot Key.
    pub fn get_sam_hashes(sam_data: &[u8], boot_key: &[u8; 16]) -> Result<Vec<(String, String)>> {
        let hive = Hive::new(sam_data).map_err(|e| anyhow!("Failed to parse SAM hive: {}", e))?;
        let root = hive
            .root_key_node()
            .map_err(|e| anyhow!("No root key node in SAM hive: {}", e))?;

        let users_node = root
            .subpath("SAM\\Domains\\Account\\Users")
            .ok_or_else(|| anyhow!("Users key not found"))?
            .map_err(|e| anyhow!("Error accessing Users key: {}", e))?;

        let names_node = users_node
            .subpath("Names")
            .ok_or_else(|| anyhow!("Names key not found"))?
            .map_err(|e| anyhow!("Error accessing Names key: {}", e))?;

        let mut rid_to_name = std::collections::HashMap::new();
        if let Some(subkeys_res) = names_node.subkeys() {
            let subkeys = subkeys_res.map_err(|e| anyhow!("Error listing Names subkeys: {}", e))?;
            for subkey_res in subkeys.into_iter() {
                let node: KeyNode<'_, _> =
                    subkey_res.map_err(|e| anyhow!("Error accessing subkey: {}", e))?;
                let rid_hex = node
                    .class_name()
                    .transpose()
                    .map_err(|e| anyhow!("Error getting classname: {}", e))?
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                let rid = if rid_hex.len() >= 8 {
                    u32::from_str_radix(&rid_hex[..8], 16).unwrap_or(0)
                } else {
                    0
                };
                rid_to_name.insert(
                    rid,
                    node.name()
                        .map_err(|e| anyhow!("Error getting node name: {}", e))?
                        .to_string(),
                );
            }
        }

        let mut results = Vec::new();
        if let Some(subkeys_res) = users_node.subkeys() {
            let subkeys = subkeys_res.map_err(|e| anyhow!("Error listing Users subkeys: {}", e))?;
            for subkey_res in subkeys.into_iter() {
                let user_node: KeyNode<'_, _> =
                    subkey_res.map_err(|e| anyhow!("Error accessing subkey: {}", e))?;
                let rid_str = user_node
                    .name()
                    .map_err(|e| anyhow!("Error getting node name: {}", e))?
                    .to_string();
                if rid_str == "Names" {
                    continue;
                }

                let rid = u32::from_str_radix(&rid_str, 16).unwrap_or(0);
                let username = rid_to_name
                    .get(&rid)
                    .cloned()
                    .unwrap_or_else(|| format!("User_{}", rid));

                if let Some(v_val_res) = user_node.value("V") {
                    let v_val: KeyValue<'_, _> =
                        v_val_res.map_err(|e| anyhow!("Error getting V value: {}", e))?;
                    let v_data_res = v_val.data();
                    let v_data = v_data_res.map_err(|e| anyhow!("Error getting V data: {}", e))?;

                    // KeyValueData matches the Windows Registry data types
                    // We need to extract the raw bytes. BigDataSlices is an iterator.
                    let v_bytes_vec: Vec<u8>;
                    let v_bytes = match v_data {
                        nt_hive::KeyValueData::Small(data) => data,
                        nt_hive::KeyValueData::Big(mut big_data) => {
                            v_bytes_vec = big_data
                                .next()
                                .transpose()
                                .map_err(|e| anyhow!("Big data error: {}", e))?
                                .unwrap_or(&[])
                                .to_vec();
                            &v_bytes_vec
                        }
                    };

                    if let Ok(nt_hash) = Self::decrypt_sam_hash(v_bytes, boot_key, rid, "NT") {
                        results.push((username, nt_hash));
                    }
                }
            }
        }
        Ok(results)
    }

    fn decrypt_sam_hash(
        v_data: &[u8],
        boot_key: &[u8; 16],
        rid: u32,
        hash_type: &str,
    ) -> Result<String> {
        if v_data.len() < 160 {
            return Err(anyhow!("V structure too short"));
        }

        let off = if hash_type == "NT" { 164 } else { 152 }; // Simplified offsets
        if v_data.len() < off + 16 {
            return Err(anyhow!("Hash offset beyond V length"));
        }

        let encrypted = &v_data[off..off + 16];
        let mut key = [0u8; 16];
        let rid_bytes = rid.to_le_bytes();

        let mut hasher = Md5::new();
        hasher.update(boot_key);
        hasher.update(rid_bytes);
        hasher.update(b"NTPASSWORD\0");
        let derived = hasher.finalize();
        key.copy_from_slice(&derived);

        let mut rc4 = Rc4::new_from_slice(&key).map_err(|e| anyhow!("RC4 init error: {}", e))?;
        let mut decrypted = [0u8; 16];
        decrypted.copy_from_slice(encrypted);
        rc4.apply_keystream(&mut decrypted);

        Ok(hex::encode(decrypted))
    }

    fn get_classname_by_path(root: &KeyNode<'_, &[u8]>, path: &str) -> Result<String> {
        let node: KeyNode<'_, &[u8]> = root
            .subpath(path)
            .ok_or_else(|| anyhow!("Key not found: {}", path))?
            .map_err(|e| anyhow!("Error accessing {}: {}", path, e))?;

        node.class_name()
            .transpose()
            .map_err(|e| anyhow!("Error getting classname: {}", e))?
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("No classname for {}", path))
    }
}
