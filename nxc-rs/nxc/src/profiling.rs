//! # NXC Profiling — Optional Memory & Performance Profiling
//!
//! Provides conditional profiling support for tracking memory usage
//! and performance metrics during execution. Enabled via the `profiling`
//! feature flag.

use tracing::info;

/// Memory usage snapshot.
#[derive(Debug, Clone)]
pub struct MemorySnapshot {
    /// Resident set size in bytes (if available).
    pub rss_bytes: Option<u64>,
    /// Virtual memory size in bytes (if available).
    pub vms_bytes: Option<u64>,
    /// Timestamp of the snapshot.
    pub timestamp: std::time::Instant,
}

/// Capture a memory snapshot of the current process.
///
/// Uses OS-specific mechanisms to read `/proc/self/status` on Linux
/// or `GetProcessMemoryInfo` on Windows.
pub fn capture_memory_snapshot() -> MemorySnapshot {
    let (rss, vms) = get_process_memory();

    MemorySnapshot {
        rss_bytes: rss,
        vms_bytes: vms,
        timestamp: std::time::Instant::now(),
    }
}

/// Log the current memory usage.
pub fn log_memory_usage(label: &str) {
    let snapshot = capture_memory_snapshot();
    let rss_mb = snapshot.rss_bytes.map(|b| b as f64 / 1_048_576.0);
    let vms_mb = snapshot.vms_bytes.map(|b| b as f64 / 1_048_576.0);

    info!(
        "[PROFILING] {}: RSS={:.1}MB, VMS={:.1}MB",
        label,
        rss_mb.unwrap_or(0.0),
        vms_mb.unwrap_or(0.0),
    );
}

/// Get process memory usage from the OS.
#[cfg(target_os = "windows")]
fn get_process_memory() -> (Option<u64>, Option<u64>) {
    // On Windows, we'd use GetProcessMemoryInfo from kernel32
    // For now, return None — full implementation requires winapi crate
    (None, None)
}

#[cfg(target_os = "linux")]
fn get_process_memory() -> (Option<u64>, Option<u64>) {
    use std::fs;

    let status = match fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return (None, None),
    };

    let mut rss = None;
    let mut vms = None;

    for line in status.lines() {
        if line.starts_with("VmRSS:") {
            if let Some(kb_str) = line.split_whitespace().nth(1) {
                if let Ok(kb) = kb_str.parse::<u64>() {
                    rss = Some(kb * 1024);
                }
            }
        } else if line.starts_with("VmSize:") {
            if let Some(kb_str) = line.split_whitespace().nth(1) {
                if let Ok(kb) = kb_str.parse::<u64>() {
                    vms = Some(kb * 1024);
                }
            }
        }
    }

    (rss, vms)
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn get_process_memory() -> (Option<u64>, Option<u64>) {
    (None, None)
}

/// A simple scoped timer for measuring operation duration.
pub struct ScopedTimer {
    label: String,
    start: std::time::Instant,
}

impl ScopedTimer {
    /// Start a new timer with the given label.
    pub fn new(label: &str) -> Self {
        Self {
            label: label.to_string(),
            start: std::time::Instant::now(),
        }
    }

    /// Get the elapsed time.
    pub fn elapsed(&self) -> std::time::Duration {
        self.start.elapsed()
    }
}

impl Drop for ScopedTimer {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed();
        info!(
            "[PROFILING] {} completed in {:.2}ms",
            self.label,
            elapsed.as_secs_f64() * 1000.0
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capture_snapshot() {
        let snapshot = capture_memory_snapshot();
        // Just verify it doesn't panic
        let _ = snapshot.rss_bytes;
        let _ = snapshot.vms_bytes;
    }

    #[test]
    fn test_scoped_timer() {
        let timer = ScopedTimer::new("test_op");
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(timer.elapsed().as_millis() >= 10);
        // Timer logs on drop
    }
}
