use nxc_resilience::circuit_breaker::{CircuitState, CircuitBreaker};
use nxc_protocols::errors::{ProtocolError, ProtocolErrorCategory};

#[tokio::test]
async fn test_circuit_breaker_state_transitions() {
    let breaker = CircuitBreaker::new(3, std::time::Duration::from_secs(1));

    // Initial state
    assert_eq!(breaker.state().await, CircuitState::Closed);

    // Fail 3 times with a critical error
    for _ in 0..3 {
        let err = ProtocolError::new(ProtocolErrorCategory::ConnectionFailure, "Connection refused");
        breaker.record_failure(&err).await;
    }

    // Should be open now
    assert_eq!(breaker.state().await, CircuitState::Open);

    // Wait for reset timeout
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    // After timeout, if we query state, it should transition to HalfOpen
    assert_eq!(breaker.state().await, CircuitState::HalfOpen);

    // Record success in HalfOpen
    breaker.record_success().await;

    // Should be closed now
    assert_eq!(breaker.state().await, CircuitState::Closed);
}

#[tokio::test]
async fn test_circuit_breaker_ignores_auth_failures() {
    let breaker = CircuitBreaker::new(3, std::time::Duration::from_secs(1));

    // Fail 5 times with auth errors
    for _ in 0..5 {
        let err = ProtocolError::new(ProtocolErrorCategory::AuthFailure, "Logon failure");
        breaker.record_failure(&err).await;
    }

    // Should remain closed because auth failures don't trip the breaker
    assert_eq!(breaker.state().await, CircuitState::Closed);
}
