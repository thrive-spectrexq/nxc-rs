use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub core: CoreConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CoreConfig {
    pub provider: String, // "anthropic", "openai", or "gemini"
    pub model: String,
    pub approval_mode: String,
}

pub fn load_config(path: &Path) -> Result<Config> {
    let content = fs::read_to_string(path)?;
    let config: Config = toml::from_str(&content)?;
    Ok(config)
}

pub fn load_network_context(path: &Path) -> Result<String> {
    let content = fs::read_to_string(path)?;
    Ok(content)
}
