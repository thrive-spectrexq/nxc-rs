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
    pub linked_sessions: Vec<SessionId>,
}

#[async_trait::async_trait]
pub trait SessionCache: Send + Sync {
    async fn get_session(&self, id: &str) -> Result<Option<SessionRecord>>;
    async fn store_session(&self, record: SessionRecord) -> Result<()>;
    async fn link_sessions(&self, parent_id: &str, child_id: &str) -> Result<()>;
    async fn get_linked_sessions(&self, parent_id: &str) -> Result<Vec<SessionRecord>>;
}

/// An in-memory distributed session cache implementation.
#[derive(Clone)]
pub struct SessionManager {
    cache: Arc<DashMap<SessionId, SessionRecord>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(DashMap::new()),
        }
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
        Ok(self.cache.get(id).map(|r| r.clone()))
    }

    async fn store_session(&self, record: SessionRecord) -> Result<()> {
        self.cache.insert(record.id.clone(), record);
        Ok(())
    }

    async fn link_sessions(&self, parent_id: &str, child_id: &str) -> Result<()> {
        if let Some(mut parent) = self.cache.get_mut(parent_id) {
            if !parent.linked_sessions.contains(&child_id.to_string()) {
                parent.linked_sessions.push(child_id.to_string());
            }
        }
        Ok(())
    }

    async fn get_linked_sessions(&self, parent_id: &str) -> Result<Vec<SessionRecord>> {
        let parent = match self.cache.get(parent_id) {
            Some(p) => p,
            None => return Ok(vec![]),
        };

        let mut linked = Vec::new();
        for child_id in &parent.linked_sessions {
            if let Some(child) = self.cache.get(child_id) {
                linked.push(child.clone());
            }
        }
        Ok(linked)
    }
}
