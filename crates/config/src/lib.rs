use anyhow::Result;
pub use netsage_common::NetSageConfig;
use std::fs;
use std::path::Path;

pub fn load_config(path: &Path) -> Result<NetSageConfig> {
    let content = fs::read_to_string(path)?;
    let config: NetSageConfig = toml::from_str(&content)?;
    Ok(config)
}

pub fn load_network_context(path: &Path) -> Result<String> {
    let content = fs::read_to_string(path)?;
    Ok(content)
}
