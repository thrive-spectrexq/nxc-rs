//! # nxc-resilience — NetExec-RS Resilience Primitives
//!
//! Shared infrastructure for retry logic, circuit breaking, connection pooling,
//! timeout management, and caching across all protocol handlers.

pub mod cache;
pub mod circuit_breaker;
pub mod pool;
pub mod retry;
pub mod timeout;

pub use cache::TtlCache;
pub use circuit_breaker::{CircuitBreaker, CircuitState};
pub use pool::ConnectionPool;
pub use retry::RetryPolicy;
pub use timeout::TimeoutManager;
