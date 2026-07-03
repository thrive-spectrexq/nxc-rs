//! Session management for nxc-rs
//! 
//! Handles caching, storing, and tracking of network execution sessions 
//! across different protocols and targets.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::uninlined_format_args,
    clippy::redundant_closure
)]

use anyhow::Result;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// A globally unique identifier for a session.
pub type SessionId = String;

/// Core structure for a serialized session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    pub id: SessionId,
    pub protocol: String,
    pub target: String,
    pub username: Option<String>,
    pub domain: Option<String>,
    pub state_data: Vec<u8>,
    pub created_at: i64,
    pub last_accessed: i64,
    pub linked_sessions: Vec<SessionId>,
}

#[async_trait::async_trait]
pub trait SessionCache: Send + Sync {
    async fn get_session(&self, id: &str) -> Result<Option<SessionRecord>>;
    async fn store_session(&self, record: SessionRecord) -> Result<()>;
    async fn link_sessions(&self, parent_id: &str, child_id: &str) -> Result<()>;
    async fn get_linked_sessions(&self, parent_id: &str) -> Result<Vec<SessionRecord>>;
}

/// Returns the current time in seconds since the UNIX epoch.
fn current_time_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// An in-memory distributed session cache implementation.
///
/// # TTL Mechanism
/// The `SessionManager` implements a Time-To-Live (TTL) mechanism to prevent memory leaks.
/// Each `SessionRecord` has a `last_accessed` timestamp that is updated whenever the session
/// is read or modified. A background Tokio task runs periodically to remove sessions that 
/// have not been accessed within the configured TTL duration. You can also manually trigger
/// a cleanup using the `cleanup_expired` method.
#[derive(Clone)]
pub struct SessionManager {
    cache: Arc<DashMap<SessionId, SessionRecord>>,
    ttl: std::time::Duration,
}

impl SessionManager {
    /// Create a new session manager with a default TTL of 1 hour.
    pub fn new() -> Self {
        Self::with_ttl(std::time::Duration::from_secs(3600))
    }

    /// Create a new session manager with a specific TTL.
    /// Spawns a background Tokio task to periodically remove expired sessions.
    pub fn with_ttl(ttl: std::time::Duration) -> Self {
        let cache = Arc::new(DashMap::new());
        let cache_clone = Arc::clone(&cache);
        
        let manager = Self { cache, ttl };
        
        // Spawn cleanup task
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let now = current_time_secs();
                let ttl_secs = ttl.as_secs() as i64;
                cache_clone.retain(|_, record| {
                    (now - record.last_accessed) < ttl_secs
                });
            }
        });

        manager
    }

    /// Manually remove sessions that have expired based on the configured TTL.
    pub fn cleanup_expired(&self) {
        let now = current_time_secs();
        let ttl_secs = self.ttl.as_secs() as i64;
        self.cache.retain(|_, record| {
            (now - record.last_accessed) < ttl_secs
        });
    }

    pub fn generate_id() -> SessionId {
        Uuid::new_v4().to_string()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl SessionCache for SessionManager {
    async fn get_session(&self, id: &str) -> Result<Option<SessionRecord>> {
        if let Some(mut record) = self.cache.get_mut(id) {
            record.last_accessed = current_time_secs();
            Ok(Some(record.clone()))
        } else {
            Ok(None)
        }
    }

    async fn store_session(&self, mut record: SessionRecord) -> Result<()> {
        record.last_accessed = current_time_secs();
        self.cache.insert(record.id.clone(), record);
        Ok(())
    }

    async fn link_sessions(&self, parent_id: &str, child_id: &str) -> Result<()> {
        if let Some(mut parent) = self.cache.get_mut(parent_id) {
            if !parent.linked_sessions.contains(&child_id.to_string()) {
                parent.linked_sessions.push(child_id.to_string());
            }
            parent.last_accessed = current_time_secs();
        }
        Ok(())
    }

    async fn get_linked_sessions(&self, parent_id: &str) -> Result<Vec<SessionRecord>> {
        let parent = match self.cache.get_mut(parent_id) {
            Some(mut p) => {
                p.last_accessed = current_time_secs();
                p.clone()
            },
            None => return Ok(vec![]),
        };

        let mut linked = Vec::new();
        for child_id in &parent.linked_sessions {
            if let Some(mut child) = self.cache.get_mut(child_id) {
                child.last_accessed = current_time_secs();
                linked.push(child.clone());
            }
        }
        Ok(linked)
    }
}
