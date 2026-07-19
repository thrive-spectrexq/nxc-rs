//! Session management for nxc-rs
//! 
//! Handles caching, storing, and tracking of network execution sessions 
//! across different protocols and targets.



use anyhow::Result;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// A globally unique identifier for a session.
pub type SessionId = String;

/// Core structure for a serialized session.
///
/// # Examples
/// ```
/// use nxc_sessions::SessionRecord;
///
/// let record = SessionRecord {
///     id: "session-123".to_string(),
///     protocol: "smb".to_string(),
///     target: "192.168.1.100".to_string(),
///     username: Some("admin".to_string()),
///     domain: Some("WORKGROUP".to_string()),
///     state_data: vec![],
///     created_at: 0,
///     last_accessed: 0,
///     linked_sessions: vec![],
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    /// The unique identifier for the session.
    pub id: SessionId,
    /// The protocol used by the session (e.g., "smb", "ssh").
    pub protocol: String,
    /// The target host or IP address.
    pub target: String,
    /// The username used for authentication, if any.
    pub username: Option<String>,
    /// The domain used for authentication, if any.
    pub domain: Option<String>,
    /// Protocol-specific state data.
    pub state_data: Vec<u8>,
    /// Timestamp when the session was created (Unix epoch seconds).
    pub created_at: i64,
    /// Timestamp when the session was last accessed (Unix epoch seconds).
    pub last_accessed: i64,
    /// A list of session IDs linked to this session.
    pub linked_sessions: Vec<SessionId>,
}

/// A trait defining the core operations for a session cache.
///
/// Implementors of this trait are responsible for providing storage,
/// retrieval, and linkage of session records.
#[async_trait::async_trait]
pub trait SessionCache: Send + Sync {
    /// Retrieves a session by its unique ID.
    async fn get_session(&self, id: &str) -> Result<Option<SessionRecord>>;
    /// Stores a new session record or updates an existing one.
    async fn store_session(&self, record: SessionRecord) -> Result<()>;
    /// Links a child session to a parent session.
    async fn link_sessions(&self, parent_id: &str, child_id: &str) -> Result<()>;
    /// Retrieves all child sessions linked to a specific parent session.
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

    /// Generate a new unique session identifier.
    ///
    /// # Examples
    /// ```
    /// use nxc_sessions::SessionManager;
    ///
    /// let id = SessionManager::generate_id();
    /// assert_eq!(id.len(), 36); // UUID v4 string length
    /// ```
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn create_test_record(id: &str) -> SessionRecord {
        SessionRecord {
            id: id.to_string(),
            protocol: "smb".to_string(),
            target: "192.168.1.1".to_string(),
            username: Some("admin".to_string()),
            domain: Some("WORKGROUP".to_string()),
            state_data: vec![1, 2, 3],
            created_at: current_time_secs(),
            last_accessed: current_time_secs(),
            linked_sessions: vec![],
        }
    }

    #[tokio::test]
    async fn test_store_and_get_session() {
        let manager = SessionManager::new();
        let id = SessionManager::generate_id();
        let record = create_test_record(&id);

        manager.store_session(record.clone()).await.unwrap();
        let retrieved = manager.get_session(&id).await.unwrap().expect("Session should exist");

        assert_eq!(retrieved.id, id);
        assert_eq!(retrieved.protocol, "smb");
    }

    #[tokio::test]
    async fn test_link_sessions() {
        let manager = SessionManager::new();
        let parent_id = SessionManager::generate_id();
        let child_id = SessionManager::generate_id();

        let parent_record = create_test_record(&parent_id);
        let child_record = create_test_record(&child_id);

        manager.store_session(parent_record).await.unwrap();
        manager.store_session(child_record).await.unwrap();

        manager.link_sessions(&parent_id, &child_id).await.unwrap();

        let linked = manager.get_linked_sessions(&parent_id).await.unwrap();
        assert_eq!(linked.len(), 1);
        assert_eq!(linked[0].id, child_id);
    }

    #[tokio::test]
    async fn test_ttl_expiration() {
        let manager = SessionManager::with_ttl(Duration::from_secs(2));
        let id = SessionManager::generate_id();
        let mut record = create_test_record(&id);

        // Modify the record's last_accessed to be in the past
        record.last_accessed = current_time_secs() - 10;
        
        // Insert directly to bypass `store_session` which updates `last_accessed`
        manager.cache.insert(id.clone(), record);

        manager.cleanup_expired();

        let retrieved = manager.get_session(&id).await.unwrap();
        assert!(retrieved.is_none());
    }
}

