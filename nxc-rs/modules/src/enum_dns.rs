//! # enum_dns — LDAP DNS Enumeration Module
//!
//! Dumps DNS from an AD DNS Server.
//! Equivalent to `nxc ldap <target> -u <user> -p <pass> -M enum_dns [-o DOMAIN=<target_domain>]`.

use anyhow::Result;
use async_trait::async_trait;
use nxc_protocols::NxcSession;

use crate::{ModuleOption, ModuleOptions, ModuleResult, NxcModule};

/// LDAP DNS enumeration module.
pub struct EnumDns;

impl EnumDns {
    pub fn new() -> Self {
        Self
    }
}

impl Default for EnumDns {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NxcModule for EnumDns {
    fn name(&self) -> &'static str {
        "enum_dns"
    }

    fn description(&self) -> &'static str {
        "Uses LDAP queries to dump DNS records from an AD DNS Server"
    }

    fn supported_protocols(&self) -> &[&str] {
        &["ldap", "wmi"] // Python reference supports WMI/SMB, we'll map this for both
    }

    fn options(&self) -> Vec<ModuleOption> {
        vec![ModuleOption {
            name: "DOMAIN".to_string(),
            description: "Domain to enumerate DNS for. Defaults to all zones.".to_string(),
            required: false,
            default: None,
        }]
    }

    async fn run(
        &self,
        session: &mut dyn NxcSession,
        opts: &ModuleOptions,
    ) -> Result<ModuleResult> {
        let domain_filter = opts.get("DOMAIN").map(|s| s.as_str());

        let ldap_session = match session.protocol() {
            "ldap" => session
                .downcast_mut::<nxc_protocols::ldap::LdapSession>()
                .unwrap(),
            _ => return Err(anyhow::anyhow!("Module only supports LDAP")),
        };

        let protocol = nxc_protocols::ldap::LdapProtocol::new();
        let base_dn = protocol.get_base_dn(ldap_session).await?;

        // Possible partitions for DNS information
        let partitions = vec![
            format!("DC=DomainDnsZones,{}", base_dn),
            format!("DC=ForestDnsZones,{}", base_dn),
            format!("CN=MicrosoftDNS,CN=System,{}", base_dn),
        ];

        let mut all_records = serde_json::Map::new();
        let mut output_lines = Vec::new();

        output_lines.push("Enumerating AD DNS Zones...".to_string());

        for partition in partitions {
            tracing::debug!("enum_dns: Checking partition {}", partition);

            // 1. Find dnsZone objects
            let zones = match protocol
                .search(
                    ldap_session,
                    &partition,
                    ldap3::Scope::Subtree,
                    "(objectClass=dnsZone)",
                    vec!["name"],
                )
                .await
            {
                Ok(entries) => entries,
                Err(_) => continue, // Partition likely doesn't exist or no access
            };

            for zone_entry in zones {
                let zone_name = zone_entry
                    .attrs
                    .get("name")
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_default();
                if let Some(filter) = domain_filter {
                    if !zone_name.to_lowercase().contains(&filter.to_lowercase()) {
                        continue;
                    }
                }

                output_lines.push(format!("Found Zone: {}", zone_name));
                let mut zone_records = serde_json::Map::new();

                // 2. Find dnsNode objects in this zone
                let nodes = match protocol
                    .search(
                        ldap_session,
                        &zone_entry.dn,
                        ldap3::Scope::OneLevel,
                        "(objectClass=dnsNode)",
                        vec!["name", "dnsRecord"],
                    )
                    .await
                {
                    Ok(entries) => entries,
                    Err(_) => continue,
                };

                for node_entry in nodes {
                    let node_name = node_entry
                        .attrs
                        .get("name")
                        .and_then(|v| v.first())
                        .cloned()
                        .unwrap_or_default();

                    // dnsRecord is binary and multi-valued
                    if let Some(record_blobs) = node_entry.bin_attrs.get("dnsRecord") {
                        let mut records_for_node = Vec::new();
                        for blob in record_blobs {
                            if let Some(parsed) = parse_dns_record(blob) {
                                output_lines.push(format!(
                                    "  {:<20} {:<6} {}",
                                    node_name, parsed.rtype, parsed.value
                                ));
                                records_for_node.push(serde_json::json!({
                                    "type": parsed.rtype,
                                    "value": parsed.value
                                }));
                            }
                        }
                        if !records_for_node.is_empty() {
                            zone_records.insert(node_name, serde_json::json!(records_for_node));
                        }
                    }
                }
                all_records.insert(zone_name, serde_json::Value::Object(zone_records));
            }
        }

        Ok(ModuleResult {
            success: true,
            output: output_lines.join("\n"),
            data: serde_json::Value::Object(all_records),
        })
    }
}

struct ParsedDnsRecord {
    rtype: String,
    value: String,
}

/// Rudimentary parser for MS-DNSP dnsRecord blobs.
fn parse_dns_record(blob: &[u8]) -> Option<ParsedDnsRecord> {
    if blob.len() < 4 {
        return None;
    }

    // Data starts after header. Header length is usually 24 bytes for most types.
    // Offset 0-1: Data Length
    // Offset 2-3: Type
    let rtype_code = u16::from_le_bytes([blob[2], blob[3]]);

    let (rtype, value) = match rtype_code {
        0x0001 => ("A", parse_ip_address(&blob[24..])),
        0x0002 => ("NS", parse_dns_name(&blob[24..])),
        0x0005 => ("CNAME", parse_dns_name(&blob[24..])),
        0x0006 => ("SOA", "SOA Record".to_string()),
        0x000c => ("PTR", parse_dns_name(&blob[24..])),
        0x000f => ("MX", parse_mx_record(&blob[24..])),
        0x001c => ("AAAA", parse_ipv6_address(&blob[24..])),
        0x0021 => ("SRV", parse_srv_record(&blob[24..])),
        _ => return None,
    };

    Some(ParsedDnsRecord {
        rtype: rtype.to_string(),
        value,
    })
}

fn parse_ip_address(data: &[u8]) -> String {
    if data.len() < 4 {
        return "invalid".to_string();
    }
    format!("{}.{}.{}.{}", data[0], data[1], data[2], data[3])
}

fn parse_ipv6_address(data: &[u8]) -> String {
    if data.len() < 16 {
        return "invalid".to_string();
    }
    let mut parts = Vec::new();
    for i in 0..8 {
        parts.push(format!(
            "{:x}",
            u16::from_be_bytes([data[i * 2], data[i * 2 + 1]])
        ));
    }
    parts.join(":")
}

/// Parses an MX record: Priority (2 bytes) + Name
fn parse_mx_record(data: &[u8]) -> String {
    if data.len() < 2 {
        return "invalid".to_string();
    }
    let priority = u16::from_le_bytes([data[0], data[1]]);
    let name = parse_dns_name(&data[2..]);
    format!("priority={} exchange={}", priority, name)
}

/// Parses an SRV record: Priority (2 bytes) + Weight (2 bytes) + Port (2 bytes) + Target
fn parse_srv_record(data: &[u8]) -> String {
    if data.len() < 6 {
        return "invalid".to_string();
    }
    let priority = u16::from_le_bytes([data[0], data[1]]);
    let weight = u16::from_le_bytes([data[2], data[3]]);
    let port = u16::from_le_bytes([data[4], data[5]]);
    let target = parse_dns_name(&data[6..]);
    format!("priority={} weight={} port={} target={}", priority, weight, port, target)
}

/// AD DNS names are often compressed or encoded in a specific way.
/// This is a simplified version that tries to extract plain strings.
fn parse_dns_name(data: &[u8]) -> String {
    let mut name = String::new();
    let mut i = 0;
    while i < data.len() {
        let len = data[i] as usize;
        if len == 0 {
            break;
        }
        
        // Handle potential compression markers (simplified)
        if (len & 0xc0) == 0xc0 {
            // This is a pointer, but we don't have the full context here easily
            // In truncated blobs, we just stop
            break;
        }

        i += 1;
        if i + len > data.len() {
            break;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(&data[i..i + len]));
        i += len;
    }
    if name.is_empty() {
        ".".to_string()
    } else {
        name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enum_dns_metadata() {
        let module = EnumDns::new();
        assert_eq!(module.name(), "enum_dns");
        assert!(module.supported_protocols().contains(&"ldap"));
    }

    #[test]
    fn test_parse_mx() {
        // MX: Priority 10, Name: mail.example.com
        // 0a 00 (Priority 10)
        // 04 6d 61 69 6c (mail)
        // 07 65 78 61 6d 70 6c 65 (example)
        // 03 63 6f 6d (com)
        // 00 (null)
        let data = vec![0x0a, 0x00, 0x04, b'm', b'a', b'i', b'l', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00];
        let result = parse_mx_record(&data);
        assert_eq!(result, "priority=10 exchange=mail.example.com");
    }

    #[test]
    fn test_parse_srv() {
        // SRV: Priority 1, Weight 2, Port 389, Target: dc1.example.com
        let data = vec![0x01, 0x00, 0x02, 0x00, 0x85, 0x01, 0x03, b'd', b'c', b'1', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00];
        let result = parse_srv_record(&data);
        assert_eq!(result, "priority=1 weight=2 port=389 target=dc1.example.com");
    }
}
