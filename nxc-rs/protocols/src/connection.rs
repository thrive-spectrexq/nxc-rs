use anyhow::{Context, Result};
use nxc_resilience::{CircuitBreaker, RetryPolicy, TimeoutManager};
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_socks::tcp::Socks5Stream;
use tracing::debug;
use url::Url;

/// Global circuit breaker registry — one breaker per target IP.
///
/// When a target accumulates too many consecutive failures, its circuit
/// opens and subsequent connection attempts are fast-failed until the
/// cooldown expires.
pub struct ConnectionManager {
    breakers: Arc<Mutex<HashMap<String, Arc<CircuitBreaker>>>>,
    retry_policy: RetryPolicy,
    timeout_manager: TimeoutManager,
    failure_threshold: u32,
    reset_timeout: Duration,
}

impl Default for ConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionManager {
    /// Create a new connection manager with default settings.
    pub fn new() -> Self {
        Self {
            breakers: Arc::new(Mutex::new(HashMap::new())),
            retry_policy: RetryPolicy::default(),
            timeout_manager: TimeoutManager::default(),
            failure_threshold: 5,
            reset_timeout: Duration::from_secs(60),
        }
    }

    /// Configure the retry policy.
    pub fn with_retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry_policy = policy;
        self
    }

    /// Configure the timeout manager.
    pub fn with_timeout_manager(mut self, tm: TimeoutManager) -> Self {
        self.timeout_manager = tm;
        self
    }

    /// Configure the circuit breaker parameters.
    pub fn with_circuit_breaker(mut self, failure_threshold: u32, reset_timeout: Duration) -> Self {
        self.failure_threshold = failure_threshold;
        self.reset_timeout = reset_timeout;
        self
    }

    /// Get or create a circuit breaker for a specific target.
    pub async fn get_breaker(&self, target: &str) -> Arc<CircuitBreaker> {
        let mut breakers = self.breakers.lock().await;
        breakers
            .entry(target.to_string())
            .or_insert_with(|| {
                Arc::new(CircuitBreaker::with_name(
                    target,
                    self.failure_threshold,
                    self.reset_timeout,
                ))
            })
            .clone()
    }

    /// Execute a generic async operation with resilience (retry + circuit breaker).
    pub async fn call<F, Fut, T>(&self, target: &str, operation: F) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let breaker = self.get_breaker(target).await;
        let retry_policy = self.retry_policy.clone();

        breaker.call(|| async { retry_policy.execute(operation).await }).await
    }

    /// Check if a target is available (circuit not open).
    pub async fn is_target_available(&self, target: &str) -> bool {
        let breaker = self.get_breaker(target).await;
        breaker.is_available().await
    }

    /// Set the failure threshold for new circuit breakers.
    pub fn set_failure_threshold(&mut self, threshold: u32) {
        self.failure_threshold = threshold;
    }

    /// Set the reset timeout for new circuit breakers.
    pub fn set_reset_timeout(&mut self, timeout: Duration) {
        self.reset_timeout = timeout;
    }

    /// Get a mutable reference to the retry policy.
    pub fn retry_policy_mut(&mut self) -> &mut RetryPolicy {
        &mut self.retry_policy
    }

    /// Connect to a target with retry, circuit breaker, and timeout support.
    pub async fn connect(&self, target: &str, port: u16, proxy: Option<&str>) -> Result<TcpStream> {
        let breaker = self.get_breaker(target).await;

        breaker
            .call(|| {
                let target = target.to_string();
                let proxy = proxy.map(|s| s.to_string());
                let retry_policy = self.retry_policy.clone();
                let tm = self.timeout_manager.clone();

                async move {
                    retry_policy
                        .execute(|| {
                            let target = target.clone();
                            let proxy = proxy.clone();
                            let tm = tm.clone();

                            async move {
                                tm.with_connect_timeout(connect_raw(
                                    &target,
                                    port,
                                    proxy.as_deref(),
                                ))
                                .await
                            }
                        })
                        .await
                }
            })
            .await
    }

    /// Reset the circuit breaker for a specific target.
    pub async fn reset_target(&self, target: &str) {
        let breaker = self.get_breaker(target).await;
        breaker.reset().await;
    }

    /// Get a reference to the timeout manager.
    pub fn timeout_manager(&self) -> &TimeoutManager {
        &self.timeout_manager
    }
}

/// Establishes a TCP connection, routing through a SOCKS5 proxy if provided.
///
/// This is the raw connection function — it does NOT apply retry, circuit
/// breaking, or timeouts. Use `ConnectionManager::connect()` for that.
pub async fn connect_raw(target: &str, port: u16, proxy: Option<&str>) -> Result<TcpStream> {
    if let Some(proxy_url) = proxy {
        // Parse the proxy string (expected format: socks5://ip:port)
        let parsed_url = Url::parse(proxy_url).context("Failed to parse proxy URL")?;

        if parsed_url.scheme() != "socks5" {
            anyhow::bail!("Only socks5:// proxy scheme is supported");
        }

        let proxy_host =
            parsed_url.host_str().ok_or_else(|| anyhow::anyhow!("Proxy URL missing host"))?;
        let proxy_port = parsed_url.port().unwrap_or(1080);
        let proxy_addr = format!("{proxy_host}:{proxy_port}");

        // Resolve the target hostname to an IP address locally for the initial implementation,
        // though true SOCKS5 can resolve remotely. (For nxc-rs, Target parsing usually already resolves IP).
        let target_addr = format!("{target}:{port}");

        debug!("Connecting via SOCKS5 proxy {proxy_addr} -> {target_addr}");

        // Connect via SOCKS5 wrapper
        let proxy_stream = tokio::net::TcpStream::connect(&proxy_addr)
            .await
            .with_context(|| format!("Failed to connect to proxy at {proxy_addr}"))?;

        // Upgrade the raw TCP stream to a SOCKS5 stream
        let socks_stream = Socks5Stream::connect_with_socket(proxy_stream, target_addr.as_str())
            .await
            .with_context(|| {
                format!("Failed to negotiate SOCKS5 connection to target {target_addr}")
            })?;

        // In tokio-socks 0.5, into_inner() extracts the underlying TcpStream.
        // It's still a standard TcpStream but traffic passing over it is transparently
        // sent to the remote destination via the proxy's negotiation.
        Ok(socks_stream.into_inner())
    } else {
        // Direct connection
        let target_addr = format!("{target}:{port}");
        debug!("Connecting directly to {target_addr}");
        TcpStream::connect(target_addr)
            .await
            .with_context(|| format!("Failed to connect directly to {target}:{port}"))
    }
}

/// Legacy compatibility — simple connect function without resilience.
///
/// Protocols that haven't been migrated to `ConnectionManager` can still
/// use this function directly.
pub async fn connect(target: &str, port: u16, proxy: Option<&str>) -> Result<TcpStream> {
    connect_raw(target, port, proxy).await
}
