//! C2 backend infrastructure for nxc-rs
//!
//! Provides traits and implementations for connecting to and interacting with
//! Command and Control (C2) frameworks like Sliver.

use async_trait::async_trait;
use serde_json::Value;

pub mod custom_api;
pub mod sliver;

#[async_trait]
pub trait C2Backend {
    async fn connect(&mut self) -> anyhow::Result<()>;
    async fn execute_command(&self, session_id: &str, command: &str) -> anyhow::Result<String>;
    async fn list_sessions(&self) -> anyhow::Result<Vec<Box<dyn C2Session>>>;
    async fn upload_file(
        &self,
        session_id: &str,
        local_path: &str,
        remote_path: &str,
    ) -> anyhow::Result<()>;
    async fn download_file(
        &self,
        session_id: &str,
        remote_path: &str,
        local_path: &str,
    ) -> anyhow::Result<()>;
}

pub trait C2Session {
    fn get_id(&self) -> String;
    fn get_hostname(&self) -> String;
    fn get_username(&self) -> String;
    fn get_os(&self) -> String;
    fn is_alive(&self) -> bool;
    fn get_details(&self) -> Value;
}
