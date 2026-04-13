//! # Circuit Breaker — Cascading Failure Prevention
//!
//! Implements the circuit breaker pattern to prevent cascading failures
//! when a target or service becomes unreachable. After a threshold of
//! consecutive failures, the breaker "opens" and fast-fails subsequent
//! requests for a cooldown period before allowing a probe ("half-open").

use anyhow::{anyhow, Result};
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, warn};

/// The three states of a circuit breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation — requests flow through.
    Closed,
    /// Failure threshold exceeded — requests are fast-failed.
    Open,
    /// Cooldown expired — one probe request is allowed through.
    HalfOpen,
}

impl std::fmt::Display for CircuitState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitState::Closed => write!(f, "CLOSED"),
            CircuitState::Open => write!(f, "OPEN"),
            CircuitState::HalfOpen => write!(f, "HALF-OPEN"),
        }
    }
}

/// Internal mutable state of the circuit breaker.
struct BreakerState {
    state: CircuitState,
    consecutive_failures: u32,
    last_failure_time: Option<Instant>,
    total_successes: u64,
    total_failures: u64,
}

/// Circuit breaker for a single target or service endpoint.
///
/// # Example
/// ```ignore
/// let breaker = CircuitBreaker::new(5, Duration::from_secs(30));
///
/// let result = breaker.call(|| async {
///     connect_to_target("10.0.0.1", 445).await
/// }).await;
/// ```
pub struct CircuitBreaker {
    /// Name/identifier for logging.
    name: String,
    /// Number of consecutive failures before opening the circuit.
    failure_threshold: u32,
    /// Duration to wait before transitioning from Open to HalfOpen.
    reset_timeout: Duration,
    /// Protected internal state.
    state: Arc<Mutex<BreakerState>>,
}

impl CircuitBreaker {
    /// Create a new circuit breaker.
    ///
    /// - `failure_threshold`: Number of consecutive failures to trigger Open state.
    /// - `reset_timeout`: Duration to wait before allowing a probe request.
    pub fn new(failure_threshold: u32, reset_timeout: Duration) -> Self {
        Self::with_name("default", failure_threshold, reset_timeout)
    }

    /// Create a named circuit breaker (name appears in logs).
    pub fn with_name(name: &str, failure_threshold: u32, reset_timeout: Duration) -> Self {
        Self {
            name: name.to_string(),
            failure_threshold,
            reset_timeout,
            state: Arc::new(Mutex::new(BreakerState {
                state: CircuitState::Closed,
                consecutive_failures: 0,
                last_failure_time: None,
                total_successes: 0,
                total_failures: 0,
            })),
        }
    }

    /// Get the current circuit state.
    pub async fn state(&self) -> CircuitState {
        let mut inner = self.state.lock().await;
        self.evaluate_state(&mut inner);
        inner.state
    }

    /// Check if the circuit breaker is allowing requests.
    pub async fn is_available(&self) -> bool {
        let state = self.state().await;
        matches!(state, CircuitState::Closed | CircuitState::HalfOpen)
    }

    /// Execute an async operation through the circuit breaker.
    pub async fn call<F, Fut, T>(&self, operation: F) -> Result<T>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        // Check if the circuit allows the call
        {
            let mut inner = self.state.lock().await;
            self.evaluate_state(&mut inner);

            match inner.state {
                CircuitState::Open => {
                    debug!(
                        "Circuit breaker '{}' is OPEN, fast-failing request",
                        self.name
                    );
                    return Err(anyhow!(
                        "Circuit breaker '{}' is open — target unreachable",
                        self.name
                    ));
                }
                CircuitState::HalfOpen => {
                    debug!(
                        "Circuit breaker '{}' is HALF-OPEN, allowing probe request",
                        self.name
                    );
                }
                CircuitState::Closed => {}
            }
        }

        // Execute the operation
        match operation().await {
            Ok(result) => {
                self.record_success().await;
                Ok(result)
            }
            Err(e) => {
                self.record_failure().await;
                Err(e)
            }
        }
    }

    /// Record a successful operation — resets failure counter.
    async fn record_success(&self) {
        let mut inner = self.state.lock().await;
        let previous_state = inner.state;
        inner.consecutive_failures = 0;
        inner.total_successes += 1;
        inner.state = CircuitState::Closed;

        if previous_state != CircuitState::Closed {
            debug!(
                "Circuit breaker '{}' transitioned {} -> CLOSED (success)",
                self.name, previous_state
            );
        }
    }

    /// Record a failed operation — may trigger state transition.
    async fn record_failure(&self) {
        let mut inner = self.state.lock().await;
        inner.consecutive_failures += 1;
        inner.total_failures += 1;
        inner.last_failure_time = Some(Instant::now());

        if inner.consecutive_failures >= self.failure_threshold {
            if inner.state != CircuitState::Open {
                warn!(
                    "Circuit breaker '{}' OPENED after {} consecutive failures",
                    self.name, inner.consecutive_failures
                );
            }
            inner.state = CircuitState::Open;
        }
    }

    /// Evaluate whether an Open breaker should transition to HalfOpen.
    fn evaluate_state(&self, inner: &mut BreakerState) {
        if inner.state == CircuitState::Open {
            if let Some(last_failure) = inner.last_failure_time {
                if last_failure.elapsed() >= self.reset_timeout {
                    debug!(
                        "Circuit breaker '{}' cooldown expired, transitioning to HALF-OPEN",
                        self.name
                    );
                    inner.state = CircuitState::HalfOpen;
                }
            }
        }
    }

    /// Manually reset the circuit breaker to Closed state.
    pub async fn reset(&self) {
        let mut inner = self.state.lock().await;
        inner.state = CircuitState::Closed;
        inner.consecutive_failures = 0;
        inner.last_failure_time = None;
        debug!("Circuit breaker '{}' manually reset to CLOSED", self.name);
    }

    /// Get statistics about the circuit breaker.
    pub async fn stats(&self) -> CircuitBreakerStats {
        let inner = self.state.lock().await;
        CircuitBreakerStats {
            state: inner.state,
            consecutive_failures: inner.consecutive_failures,
            total_successes: inner.total_successes,
            total_failures: inner.total_failures,
        }
    }
}

/// Statistics snapshot for a circuit breaker.
#[derive(Debug, Clone)]
pub struct CircuitBreakerStats {
    pub state: CircuitState,
    pub consecutive_failures: u32,
    pub total_successes: u64,
    pub total_failures: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_closed_on_success() {
        let cb = CircuitBreaker::new(3, Duration::from_secs(10));
        let result = cb.call(|| async { Ok::<_, anyhow::Error>(42) }).await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(cb.state().await, CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_opens_after_threshold() {
        let cb = CircuitBreaker::new(3, Duration::from_secs(10));

        for _ in 0..3 {
            let _ = cb
                .call(|| async { Err::<i32, _>(anyhow!("fail")) })
                .await;
        }

        assert_eq!(cb.state().await, CircuitState::Open);
    }

    #[tokio::test]
    async fn test_fast_fails_when_open() {
        let cb = CircuitBreaker::new(2, Duration::from_secs(60));

        // Trip the breaker
        for _ in 0..2 {
            let _ = cb
                .call(|| async { Err::<i32, _>(anyhow!("fail")) })
                .await;
        }

        // Should fast-fail without calling the operation
        let result = cb.call(|| async { Ok::<_, anyhow::Error>(42) }).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("open"));
    }

    #[tokio::test]
    async fn test_half_open_after_timeout() {
        let cb = CircuitBreaker::new(2, Duration::from_millis(50));

        // Trip the breaker
        for _ in 0..2 {
            let _ = cb
                .call(|| async { Err::<i32, _>(anyhow!("fail")) })
                .await;
        }

        assert_eq!(cb.state().await, CircuitState::Open);

        // Wait for cooldown
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(cb.state().await, CircuitState::HalfOpen);
    }

    #[tokio::test]
    async fn test_closes_on_successful_probe() {
        let cb = CircuitBreaker::new(2, Duration::from_millis(50));

        // Trip the breaker
        for _ in 0..2 {
            let _ = cb
                .call(|| async { Err::<i32, _>(anyhow!("fail")) })
                .await;
        }

        // Wait for half-open
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Successful probe closes the circuit
        let result = cb.call(|| async { Ok::<_, anyhow::Error>(42) }).await;
        assert_eq!(result.unwrap(), 42);
        assert_eq!(cb.state().await, CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_manual_reset() {
        let cb = CircuitBreaker::new(1, Duration::from_secs(60));

        let _ = cb
            .call(|| async { Err::<i32, _>(anyhow!("fail")) })
            .await;
        assert_eq!(cb.state().await, CircuitState::Open);

        cb.reset().await;
        assert_eq!(cb.state().await, CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_stats() {
        let cb = CircuitBreaker::new(5, Duration::from_secs(10));

        let _ = cb.call(|| async { Ok::<_, anyhow::Error>(1) }).await;
        let _ = cb.call(|| async { Ok::<_, anyhow::Error>(2) }).await;
        let _ = cb
            .call(|| async { Err::<i32, _>(anyhow!("fail")) })
            .await;

        let stats = cb.stats().await;
        assert_eq!(stats.total_successes, 2);
        assert_eq!(stats.total_failures, 1);
        assert_eq!(stats.consecutive_failures, 1);
    }
}
