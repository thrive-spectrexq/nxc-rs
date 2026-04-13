//! # Connection Pool — Async Connection Reuse
//!
//! A generic async connection pool that manages a set of idle connections
//! with configurable maximum size, idle timeout, and connection lifecycle.

use anyhow::Result;
use std::collections::VecDeque;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, warn};

/// A pooled connection wrapper that tracks creation time.
struct PooledEntry<C> {
    connection: C,
    created_at: Instant,
    last_used: Instant,
}

/// A generic async connection pool.
///
/// # Type Parameters
/// - `C`: The connection type. Must be `Send + 'static`.
///
/// # Example
/// ```ignore
/// let pool = ConnectionPool::new(10, Duration::from_secs(300));
///
/// // Check out a connection (or create one if the pool is empty)
/// let conn = pool.get_or_create(|| async {
///     TcpStream::connect("10.0.0.1:445").await
/// }).await?;
///
/// // Return it when done
/// pool.put(conn).await;
/// ```
pub struct ConnectionPool<C: Send + 'static> {
    /// Pool of idle connections.
    idle: Arc<Mutex<VecDeque<PooledEntry<C>>>>,
    /// Maximum number of idle connections to hold.
    max_size: usize,
    /// Maximum time a connection can sit idle before being evicted.
    idle_timeout: Duration,
    /// Maximum total lifetime of a connection.
    max_lifetime: Duration,
    /// Name for logging.
    name: String,
}

impl<C: Send + 'static> ConnectionPool<C> {
    /// Create a new connection pool.
    ///
    /// - `max_size`: Maximum number of idle connections.
    /// - `idle_timeout`: How long a connection can remain idle before eviction.
    pub fn new(max_size: usize, idle_timeout: Duration) -> Self {
        Self {
            idle: Arc::new(Mutex::new(VecDeque::with_capacity(max_size))),
            max_size,
            idle_timeout,
            max_lifetime: Duration::from_secs(3600), // 1 hour default
            name: "pool".to_string(),
        }
    }

    /// Create a named pool (name appears in logs).
    pub fn with_name(name: &str, max_size: usize, idle_timeout: Duration) -> Self {
        Self {
            name: name.to_string(),
            ..Self::new(max_size, idle_timeout)
        }
    }

    /// Set the maximum total lifetime for a pooled connection.
    pub fn with_max_lifetime(mut self, max_lifetime: Duration) -> Self {
        self.max_lifetime = max_lifetime;
        self
    }

    /// Get a connection from the pool, or create one using the provided factory.
    pub async fn get_or_create<F, Fut>(&self, factory: F) -> Result<C>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<C>>,
    {
        // Try to get an idle connection
        {
            let mut pool = self.idle.lock().await;
            while let Some(entry) = pool.pop_front() {
                // Check idle timeout
                if entry.last_used.elapsed() > self.idle_timeout {
                    debug!(
                        "Pool '{}': evicting idle connection (idle {}ms)",
                        self.name,
                        entry.last_used.elapsed().as_millis()
                    );
                    continue;
                }

                // Check max lifetime
                if entry.created_at.elapsed() > self.max_lifetime {
                    debug!(
                        "Pool '{}': evicting expired connection (age {}s)",
                        self.name,
                        entry.created_at.elapsed().as_secs()
                    );
                    continue;
                }

                debug!("Pool '{}': reusing idle connection", self.name);
                return Ok(entry.connection);
            }
        }

        // No valid idle connection — create a new one
        debug!("Pool '{}': creating new connection", self.name);
        factory().await
    }

    /// Return a connection to the pool for reuse.
    ///
    /// If the pool is full, the connection is dropped instead.
    pub async fn put(&self, connection: C) {
        let mut pool = self.idle.lock().await;

        if pool.len() >= self.max_size {
            warn!(
                "Pool '{}': at capacity ({}), dropping connection",
                self.name, self.max_size
            );
            return;
        }

        pool.push_back(PooledEntry {
            connection,
            created_at: Instant::now(),
            last_used: Instant::now(),
        });

        debug!(
            "Pool '{}': connection returned ({}/{})",
            self.name,
            pool.len(),
            self.max_size
        );
    }

    /// Evict all expired connections from the pool.
    pub async fn evict_expired(&self) -> usize {
        let mut pool = self.idle.lock().await;
        let before = pool.len();

        pool.retain(|entry| {
            entry.last_used.elapsed() <= self.idle_timeout
                && entry.created_at.elapsed() <= self.max_lifetime
        });

        let evicted = before - pool.len();
        if evicted > 0 {
            debug!(
                "Pool '{}': evicted {} expired connections",
                self.name, evicted
            );
        }
        evicted
    }

    /// Get the current number of idle connections.
    pub async fn idle_count(&self) -> usize {
        self.idle.lock().await.len()
    }

    /// Clear all connections from the pool.
    pub async fn clear(&self) {
        let mut pool = self.idle.lock().await;
        let count = pool.len();
        pool.clear();
        debug!("Pool '{}': cleared {} connections", self.name, count);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_when_empty() {
        let pool: ConnectionPool<String> = ConnectionPool::new(5, Duration::from_secs(60));

        let conn = pool
            .get_or_create(|| async { Ok("new_connection".to_string()) })
            .await
            .unwrap();

        assert_eq!(conn, "new_connection");
        assert_eq!(pool.idle_count().await, 0);
    }

    #[tokio::test]
    async fn test_reuse_from_pool() {
        let pool: ConnectionPool<String> = ConnectionPool::new(5, Duration::from_secs(60));

        // Put a connection
        pool.put("cached_conn".to_string()).await;
        assert_eq!(pool.idle_count().await, 1);

        // Should reuse instead of creating new
        let conn = pool
            .get_or_create(|| async { Ok("should_not_create".to_string()) })
            .await
            .unwrap();

        assert_eq!(conn, "cached_conn");
        assert_eq!(pool.idle_count().await, 0);
    }

    #[tokio::test]
    async fn test_drops_when_full() {
        let pool: ConnectionPool<String> = ConnectionPool::new(2, Duration::from_secs(60));

        pool.put("c1".to_string()).await;
        pool.put("c2".to_string()).await;
        pool.put("c3".to_string()).await; // Should be dropped

        assert_eq!(pool.idle_count().await, 2);
    }

    #[tokio::test]
    async fn test_evicts_expired() {
        let pool: ConnectionPool<String> = ConnectionPool::new(5, Duration::from_millis(50));

        pool.put("expiring".to_string()).await;
        assert_eq!(pool.idle_count().await, 1);

        tokio::time::sleep(Duration::from_millis(100)).await;

        let evicted = pool.evict_expired().await;
        assert_eq!(evicted, 1);
        assert_eq!(pool.idle_count().await, 0);
    }

    #[tokio::test]
    async fn test_clear() {
        let pool: ConnectionPool<String> = ConnectionPool::new(10, Duration::from_secs(60));

        pool.put("a".to_string()).await;
        pool.put("b".to_string()).await;
        pool.put("c".to_string()).await;

        pool.clear().await;
        assert_eq!(pool.idle_count().await, 0);
    }

    #[tokio::test]
    async fn test_skips_expired_on_get() {
        let pool: ConnectionPool<String> = ConnectionPool::new(5, Duration::from_millis(50));

        pool.put("old_conn".to_string()).await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Should skip the expired connection and create a new one
        let conn = pool
            .get_or_create(|| async { Ok("fresh_conn".to_string()) })
            .await
            .unwrap();

        assert_eq!(conn, "fresh_conn");
    }
}
