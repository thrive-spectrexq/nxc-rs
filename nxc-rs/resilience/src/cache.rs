//! # TTL Cache — Time-to-Live Caching Layer
//!
//! A thread-safe LRU-style cache with per-entry TTL expiration, used to cache
//! frequently accessed data like DNS lookups, host fingerprints, and protocol
//! negotiation results.

use dashmap::DashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::debug;

/// A cache entry with its value and expiration timestamp.
struct CacheEntry<V> {
    value: V,
    inserted_at: Instant,
    ttl: Duration,
}

impl<V> CacheEntry<V> {
    fn is_expired(&self) -> bool {
        self.inserted_at.elapsed() >= self.ttl
    }
}

/// A concurrent TTL cache.
///
/// Thread-safe via `DashMap`. Expired entries are lazily evicted on access
/// and can also be explicitly purged.
///
/// # Type Parameters
/// - `K`: Key type. Must be `Hash + Eq + Clone + Send + Sync`.
/// - `V`: Value type. Must be `Clone + Send + Sync`.
///
/// # Example
/// ```ignore
/// let cache: TtlCache<String, Vec<u16>> = TtlCache::new(
///     Duration::from_secs(300),
///     1000,
/// );
///
/// cache.insert("10.0.0.1".into(), vec![22, 80, 443]);
///
/// if let Some(ports) = cache.get(&"10.0.0.1".into()) {
///     println!("Cached ports: {:?}", ports);
/// }
/// ```
pub struct TtlCache<K, V>
where
    K: Hash + Eq + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    entries: Arc<DashMap<K, CacheEntry<V>>>,
    default_ttl: Duration,
    max_entries: usize,
    name: String,
}

impl<K, V> TtlCache<K, V>
where
    K: Hash + Eq + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// Create a new cache with a default TTL and maximum number of entries.
    pub fn new(default_ttl: Duration, max_entries: usize) -> Self {
        Self {
            entries: Arc::new(DashMap::with_capacity(max_entries.min(256))),
            default_ttl,
            max_entries,
            name: "cache".to_string(),
        }
    }

    /// Create a named cache (name appears in logs).
    pub fn with_name(name: &str, default_ttl: Duration, max_entries: usize) -> Self {
        Self { name: name.to_string(), ..Self::new(default_ttl, max_entries) }
    }

    /// Insert a value with the default TTL.
    pub fn insert(&self, key: K, value: V) {
        self.insert_with_ttl(key, value, self.default_ttl);
    }

    /// Insert a value with a custom TTL.
    pub fn insert_with_ttl(&self, key: K, value: V, ttl: Duration) {
        // Evict oldest expired entries if at capacity
        if self.entries.len() >= self.max_entries {
            self.evict_expired();
        }

        // If still at capacity after eviction, skip insertion
        if self.entries.len() >= self.max_entries {
            debug!("Cache '{}': at capacity ({}), skipping insert", self.name, self.max_entries);
            return;
        }

        self.entries.insert(key, CacheEntry { value, inserted_at: Instant::now(), ttl });
    }

    /// Get a cached value if it exists and hasn't expired.
    pub fn get(&self, key: &K) -> Option<V> {
        let entry = self.entries.get(key)?;

        if entry.is_expired() {
            // Drop the read guard before removing
            drop(entry);
            self.entries.remove(key);
            None
        } else {
            Some(entry.value.clone())
        }
    }

    /// Get a value or compute and cache it if absent/expired.
    pub fn get_or_insert<F>(&self, key: K, factory: F) -> V
    where
        F: FnOnce() -> V,
    {
        if let Some(value) = self.get(&key) {
            return value;
        }

        let value = factory();
        self.insert(key, value.clone());
        value
    }

    /// Check if a key exists and is not expired.
    pub fn contains(&self, key: &K) -> bool {
        self.get(key).is_some()
    }

    /// Remove a specific key.
    pub fn remove(&self, key: &K) -> Option<V> {
        self.entries.remove(key).map(|(_, entry)| entry.value)
    }

    /// Remove all expired entries.
    pub fn evict_expired(&self) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| !entry.is_expired());
        let evicted = before - self.entries.len();

        if evicted > 0 {
            debug!("Cache '{}': evicted {} expired entries", self.name, evicted);
        }
        evicted
    }

    /// Get the current number of entries (including potentially expired ones).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries.
    pub fn clear(&self) {
        self.entries.clear();
        debug!("Cache '{}': cleared", self.name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_get() {
        let cache: TtlCache<String, i32> = TtlCache::new(Duration::from_secs(60), 100);

        cache.insert("key1".into(), 42);
        assert_eq!(cache.get(&"key1".into()), Some(42));
    }

    #[test]
    fn test_missing_key() {
        let cache: TtlCache<String, i32> = TtlCache::new(Duration::from_secs(60), 100);
        assert_eq!(cache.get(&"missing".into()), None);
    }

    #[test]
    fn test_expiration() {
        let cache: TtlCache<String, i32> = TtlCache::new(Duration::from_millis(50), 100);

        cache.insert("key1".into(), 42);
        assert_eq!(cache.get(&"key1".into()), Some(42));

        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(cache.get(&"key1".into()), None);
    }

    #[test]
    fn test_custom_ttl() {
        let cache: TtlCache<String, i32> = TtlCache::new(Duration::from_secs(60), 100);

        cache.insert_with_ttl("short".into(), 1, Duration::from_millis(50));
        cache.insert_with_ttl("long".into(), 2, Duration::from_secs(60));

        std::thread::sleep(Duration::from_millis(100));

        assert_eq!(cache.get(&"short".into()), None);
        assert_eq!(cache.get(&"long".into()), Some(2));
    }

    #[test]
    fn test_get_or_insert() {
        let cache: TtlCache<String, i32> = TtlCache::new(Duration::from_secs(60), 100);

        let value = cache.get_or_insert("key1".into(), || 42);
        assert_eq!(value, 42);

        // Second call should return cached value
        let value = cache.get_or_insert("key1".into(), || 99);
        assert_eq!(value, 42);
    }

    #[test]
    fn test_remove() {
        let cache: TtlCache<String, i32> = TtlCache::new(Duration::from_secs(60), 100);

        cache.insert("key1".into(), 42);
        assert_eq!(cache.remove(&"key1".into()), Some(42));
        assert_eq!(cache.get(&"key1".into()), None);
    }

    #[test]
    fn test_evict_expired() {
        let cache: TtlCache<String, i32> = TtlCache::new(Duration::from_millis(50), 100);

        cache.insert("a".into(), 1);
        cache.insert("b".into(), 2);
        cache.insert("c".into(), 3);

        std::thread::sleep(Duration::from_millis(100));

        let evicted = cache.evict_expired();
        assert_eq!(evicted, 3);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_max_entries_cap() {
        let cache: TtlCache<i32, i32> = TtlCache::new(Duration::from_secs(60), 3);

        cache.insert(1, 10);
        cache.insert(2, 20);
        cache.insert(3, 30);
        cache.insert(4, 40); // Should be skipped (at capacity, none expired)

        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn test_clear() {
        let cache: TtlCache<String, i32> = TtlCache::new(Duration::from_secs(60), 100);

        cache.insert("a".into(), 1);
        cache.insert("b".into(), 2);

        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_contains() {
        let cache: TtlCache<String, i32> = TtlCache::new(Duration::from_secs(60), 100);

        cache.insert("exists".into(), 42);
        assert!(cache.contains(&"exists".into()));
        assert!(!cache.contains(&"missing".into()));
    }
}
