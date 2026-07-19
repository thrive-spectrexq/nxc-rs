use dashmap::DashMap;
use std::time::{Duration, Instant};

/// Tracks connection failures to subnets/domains to quickly detect network-wide outages.
pub struct NetworkConditionDetector {
    /// Maps a subnet (e.g., "10.0.0.0/24") to consecutive failures.
    subnet_failures: DashMap<String, (u32, Instant)>,
    /// Threshold of consecutive failures to declare subnet unreachable.
    failure_threshold: u32,
    /// Cooldown before trying a subnet again.
    cooldown: Duration,
}

impl NetworkConditionDetector {
    pub fn new(failure_threshold: u32, cooldown: Duration) -> Self {
        Self { subnet_failures: DashMap::new(), failure_threshold, cooldown }
    }

    pub fn record_failure(&self, subnet: &str) {
        let mut entry =
            self.subnet_failures.entry(subnet.to_string()).or_insert((0, Instant::now()));
        entry.0 += 1;
        entry.1 = Instant::now();
    }

    pub fn record_success(&self, subnet: &str) {
        self.subnet_failures.remove(subnet);
    }

    pub fn is_unreachable(&self, subnet: &str) -> bool {
        if let Some(entry) = self.subnet_failures.get(subnet) {
            if entry.0 >= self.failure_threshold && entry.1.elapsed() < self.cooldown {
                return true;
            }
        }
        false
    }
}
