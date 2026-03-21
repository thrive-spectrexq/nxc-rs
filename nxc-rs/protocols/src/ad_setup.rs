//! # AD Setup Utilities
//!
//! Utilities for generating environment configuration files (hosts, krb5.conf)
//! based on discovered Active Directory information.

use anyhow::Result;
use std::fs;
use std::path::Path;
use tracing::info;

/// Generate a local hosts file entries for the discovered domain.
pub fn generate_hosts_file(domain: &str, dc_ip: &str, dc_name: &str) -> String {
    let mut output = String::new();
    output.push_str("# NXC-RS Generated Hosts Entries\n");
    output.push_str(&format!("{:<15} {} {}.{}\n", dc_ip, dc_name, dc_name, domain.to_lowercase()));
    output.push_str(&format!("{:<15} {}\n", dc_ip, domain.to_lowercase()));
    output
}

/// Generate a krb5.conf file for the discovered realm.
pub fn generate_krb5_conf(realm: &str, kdc_host: &str) -> String {
    let realm_upper = realm.to_uppercase();
    let kdc_lower = kdc_host.to_lowercase();
    
    format!(
r#"[libdefaults]
    default_realm = {realm_upper}
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    rdns = false

[realms]
    {realm_upper} = {{
        kdc = {kdc_lower}
        admin_server = {kdc_lower}
    }}

[domain_realm]
    .{realm_lower} = {realm_upper}
    {realm_lower} = {realm_upper}
"#, 
    realm_upper = realm_upper,
    realm_lower = realm.to_lowercase(),
    kdc_lower = kdc_lower
    )
}

/// Save the generated configurations to disk.
pub fn save_setup_files(
    output_dir: &Path,
    domain: &str,
    dc_ip: &str,
    dc_name: &str
) -> Result<()> {
    fs::create_dir_all(output_dir)?;
    
    let hosts_content = generate_hosts_file(domain, dc_ip, dc_name);
    let hosts_path = output_dir.join("hosts.txt");
    fs::write(&hosts_path, hosts_content)?;
    info!("AD Setup: Hosts entries saved to {:?}", hosts_path);
    
    let krb5_content = generate_krb5_conf(domain, dc_ip); // Using IP as KDC if name is unknown
    let krb5_path = output_dir.join("krb5.conf");
    fs::write(&krb5_path, krb5_content)?;
    info!("AD Setup: Kerberos config saved to {:?}", krb5_path);
    
    Ok(())
}
