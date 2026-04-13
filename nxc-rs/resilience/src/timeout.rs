//! # Timeout Manager — Unified Timeout Management
//!
//! Provides a centralized timeout configuration that protocols can reference
//! for consistent behavior. Supports per-phase timeouts (connect, auth, exec)
//! and adaptive timeout adjustment based on network conditions.

use anyhow::{anyhow, Result};
use std::future::Future;
use std::time::Duration;
use tracing::warn;

/// Timeout configuration for different operation phases.
#[derive(Debug, Clone)]
pub struct TimeoutManager {
    /// Timeout for TCP connection establishment.
    pub connect: Duration,
    /// Timeout for authentication handshake.
    pub auth: Duration,
    /// Timeout for command execution.
    pub exec: Duration,
    /// Timeout for file read/write operations.
    pub io: Duration,
    /// Global timeout for the entire operation lifecycle.
    pub global: Duration,
}

impl Default for TimeoutManager {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(10),
            auth: Duration::from_secs(15),
            exec: Duration::from_secs(30),
            io: Duration::from_secs(60),
            global: Duration::from_secs(120),
        }
    }
}

impl TimeoutManager {
    /// Create a timeout manager with a single base timeout,
    /// scaling each phase proportionally.
    pub fn from_base(base: Duration) -> Self {
        Self {
            connect: base,
            auth: base + Duration::from_secs(5),
            exec: base * 2,
            io: base * 4,
            global: base * 8,
        }
    }

    /// Create a fast timeout profile for responsive networks.
    pub fn fast() -> Self {
        Self {
            connect: Duration::from_secs(3),
            auth: Duration::from_secs(5),
            exec: Duration::from_secs(10),
            io: Duration::from_secs(20),
            global: Duration::from_secs(45),
        }
    }

    /// Create a slow/tolerant timeout profile for high-latency networks.
    pub fn slow() -> Self {
        Self {
            connect: Duration::from_secs(30),
            auth: Duration::from_secs(45),
            exec: Duration::from_secs(120),
            io: Duration::from_secs(300),
            global: Duration::from_secs(600),
        }
    }

    /// Execute a future with the connect timeout.
    pub async fn with_connect_timeout<F, T>(&self, fut: F) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        self.with_timeout("connect", self.connect, fut).await
    }

    /// Execute a future with the auth timeout.
    pub async fn with_auth_timeout<F, T>(&self, fut: F) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        self.with_timeout("auth", self.auth, fut).await
    }

    /// Execute a future with the exec timeout.
    pub async fn with_exec_timeout<F, T>(&self, fut: F) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        self.with_timeout("exec", self.exec, fut).await
    }

    /// Execute a future with the I/O timeout.
    pub async fn with_io_timeout<F, T>(&self, fut: F) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        self.with_timeout("io", self.io, fut).await
    }

    /// Execute a future with a named timeout duration.
    async fn with_timeout<F, T>(&self, phase: &str, timeout: Duration, fut: F) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        match tokio::time::timeout(timeout, fut).await {
            Ok(result) => result,
            Err(_) => {
                warn!(
                    "Timeout exceeded for '{}' phase ({}ms)",
                    phase,
                    timeout.as_millis()
                );
                Err(anyhow!(
                    "Operation timed out during '{}' phase after {}ms",
                    phase,
                    timeout.as_millis()
                ))
            }
        }
    }

    /// Execute a future with an arbitrary timeout.
    pub async fn with_custom_timeout<F, T>(
        &self,
        label: &str,
        timeout: Duration,
        fut: F,
    ) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        self.with_timeout(label, timeout, fut).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_timeout_succeeds_within_limit() {
        let tm = TimeoutManager::default();
        let result = tm
            .with_connect_timeout(async { Ok::<_, anyhow::Error>(42) })
            .await;
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn test_timeout_expires() {
        let tm = TimeoutManager {
            connect: Duration::from_millis(50),
            ..Default::default()
        };

        let result = tm
            .with_connect_timeout(async {
                tokio::time::sleep(Duration::from_millis(200)).await;
                Ok::<_, anyhow::Error>(42)
            })
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("timed out"));
    }

    #[test]
    fn test_from_base() {
        let tm = TimeoutManager::from_base(Duration::from_secs(5));
        assert_eq!(tm.connect, Duration::from_secs(5));
        assert_eq!(tm.auth, Duration::from_secs(10));
        assert_eq!(tm.exec, Duration::from_secs(10));
    }

    #[test]
    fn test_fast_profile() {
        let tm = TimeoutManager::fast();
        assert_eq!(tm.connect, Duration::from_secs(3));
        assert!(tm.global < Duration::from_secs(60));
    }

    #[test]
    fn test_slow_profile() {
        let tm = TimeoutManager::slow();
        assert_eq!(tm.connect, Duration::from_secs(30));
        assert!(tm.global >= Duration::from_secs(600));
    }
}
