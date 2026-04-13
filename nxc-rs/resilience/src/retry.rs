//! # Retry Policy — Exponential Backoff with Jitter
//!
//! Retries an async operation with configurable exponential backoff,
//! random jitter, and a maximum retry count.

use anyhow::{anyhow, Result};
use std::future::Future;
use std::time::Duration;
use tracing::{debug, warn};

/// Configuration for retry behavior.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts (0 = no retries, just the initial attempt).
    pub max_retries: u32,
    /// Base delay before the first retry.
    pub base_delay: Duration,
    /// Maximum delay cap (backoff will not exceed this).
    pub max_delay: Duration,
    /// Multiplicative factor for each retry (e.g., 2.0 for doubling).
    pub backoff_factor: f64,
    /// Whether to add random jitter (±50% of computed delay).
    pub jitter: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(30),
            backoff_factor: 2.0,
            jitter: true,
        }
    }
}

impl RetryPolicy {
    /// Create a new retry policy with the given parameters.
    pub fn new(
        max_retries: u32,
        base_delay: Duration,
        max_delay: Duration,
        backoff_factor: f64,
    ) -> Self {
        Self {
            max_retries,
            base_delay,
            max_delay,
            backoff_factor,
            jitter: true,
        }
    }

    /// Create a policy that never retries (single attempt).
    pub fn no_retry() -> Self {
        Self {
            max_retries: 0,
            ..Default::default()
        }
    }

    /// Create an aggressive retry policy for critical operations.
    pub fn aggressive() -> Self {
        Self {
            max_retries: 5,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(60),
            backoff_factor: 2.0,
            jitter: true,
        }
    }

    /// Create a gentle retry policy for non-critical operations.
    pub fn gentle() -> Self {
        Self {
            max_retries: 2,
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(10),
            backoff_factor: 1.5,
            jitter: true,
        }
    }

    /// Compute the delay for a given attempt number (0-indexed).
    fn compute_delay(&self, attempt: u32) -> Duration {
        let base_ms = self.base_delay.as_millis() as f64;
        let factor = self.backoff_factor.powi(attempt as i32);
        let delay_ms = (base_ms * factor).min(self.max_delay.as_millis() as f64);

        let final_ms = if self.jitter {
            let half_jitter = delay_ms * 0.5;
            let jitter_offset = rand::random_range(-half_jitter..half_jitter);
            (delay_ms + jitter_offset).max(0.0)
        } else {
            delay_ms
        };

        Duration::from_millis(final_ms as u64)
    }

    /// Execute an async operation with this retry policy.
    ///
    /// The closure `operation` is called repeatedly until it succeeds or
    /// the maximum number of retries is exhausted.
    pub async fn execute<F, Fut, T>(&self, operation: F) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let mut last_error = anyhow!("Operation failed with no attempts");

        for attempt in 0..=self.max_retries {
            match operation().await {
                Ok(result) => {
                    if attempt > 0 {
                        debug!("Operation succeeded on attempt {}", attempt + 1);
                    }
                    return Ok(result);
                }
                Err(e) => {
                    last_error = e;

                    if attempt < self.max_retries {
                        let delay = self.compute_delay(attempt);
                        warn!(
                            "Attempt {}/{} failed, retrying in {}ms: {}",
                            attempt + 1,
                            self.max_retries + 1,
                            delay.as_millis(),
                            last_error
                        );
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        Err(anyhow!(
            "All {} attempts exhausted. Last error: {}",
            self.max_retries + 1,
            last_error
        ))
    }

    /// Execute with a custom predicate to decide whether to retry.
    ///
    /// `should_retry` receives the error and returns `true` if the operation
    /// should be retried. This allows skipping retries on non-transient errors
    /// (e.g., authentication failures).
    pub async fn execute_with_predicate<F, Fut, T, P>(
        &self,
        operation: F,
        should_retry: P,
    ) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T>>,
        P: Fn(&anyhow::Error) -> bool,
    {
        let mut last_error = anyhow!("Operation failed with no attempts");

        for attempt in 0..=self.max_retries {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    if !should_retry(&e) {
                        return Err(e);
                    }

                    last_error = e;

                    if attempt < self.max_retries {
                        let delay = self.compute_delay(attempt);
                        warn!(
                            "Attempt {}/{} failed (retryable), retrying in {}ms",
                            attempt + 1,
                            self.max_retries + 1,
                            delay.as_millis()
                        );
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        Err(anyhow!(
            "All {} attempts exhausted. Last error: {}",
            self.max_retries + 1,
            last_error
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_immediate_success() {
        let policy = RetryPolicy::no_retry();
        let result = policy.execute(|| async { Ok::<_, anyhow::Error>(42) }).await;
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn test_retry_then_success() {
        let counter = Arc::new(AtomicU32::new(0));
        let policy = RetryPolicy {
            max_retries: 3,
            base_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(100),
            backoff_factor: 2.0,
            jitter: false,
        };

        let counter_clone = counter.clone();
        let result = policy
            .execute(move || {
                let c = counter_clone.clone();
                async move {
                    let attempt = c.fetch_add(1, Ordering::SeqCst);
                    if attempt < 2 {
                        Err(anyhow!("transient error"))
                    } else {
                        Ok(42)
                    }
                }
            })
            .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_all_retries_exhausted() {
        let policy = RetryPolicy {
            max_retries: 2,
            base_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(50),
            backoff_factor: 2.0,
            jitter: false,
        };

        let result = policy
            .execute(|| async { Err::<i32, _>(anyhow!("permanent error")) })
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("All 3 attempts exhausted"));
    }

    #[tokio::test]
    async fn test_predicate_stops_retry_on_non_transient() {
        let counter = Arc::new(AtomicU32::new(0));
        let policy = RetryPolicy {
            max_retries: 5,
            base_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(50),
            backoff_factor: 2.0,
            jitter: false,
        };

        let counter_clone = counter.clone();
        let result = policy
            .execute_with_predicate(
                move || {
                    let c = counter_clone.clone();
                    async move {
                        c.fetch_add(1, Ordering::SeqCst);
                        Err::<i32, _>(anyhow!("AUTH_FAILED"))
                    }
                },
                |e| !e.to_string().contains("AUTH_FAILED"),
            )
            .await;

        assert!(result.is_err());
        // Should have stopped after 1 attempt (predicate returned false)
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_compute_delay_exponential() {
        let policy = RetryPolicy {
            max_retries: 5,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            backoff_factor: 2.0,
            jitter: false,
        };

        assert_eq!(policy.compute_delay(0), Duration::from_millis(100));
        assert_eq!(policy.compute_delay(1), Duration::from_millis(200));
        assert_eq!(policy.compute_delay(2), Duration::from_millis(400));
        assert_eq!(policy.compute_delay(3), Duration::from_millis(800));
    }

    #[test]
    fn test_compute_delay_capped() {
        let policy = RetryPolicy {
            max_retries: 10,
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(5),
            backoff_factor: 10.0,
            jitter: false,
        };

        // 1s * 10^3 = 1000s, but capped at 5s
        assert_eq!(policy.compute_delay(3), Duration::from_secs(5));
    }
}
