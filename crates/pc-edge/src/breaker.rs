//! Per-upstream circuit breakers.
//!
//! A failing upstream should be shed quickly rather than have every request
//! pile up against it (CLAUDE.md §5 row #11). Each upstream key has a breaker
//! that opens after a run of failures, stays open for a cooldown, then allows a
//! single half-open probe before closing or re-opening. Time is an explicit
//! monotonic-millis clock for deterministic tests.

use std::collections::HashMap;
use std::sync::Mutex;

/// Observable breaker state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakerState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug)]
struct BreakerCell {
    consecutive_failures: u32,
    state: BreakerState,
    opened_at_ms: u64,
    /// Set while a half-open probe is in flight so only one probe is admitted.
    probe_in_flight: bool,
}

impl Default for BreakerCell {
    fn default() -> Self {
        Self {
            consecutive_failures: 0,
            state: BreakerState::Closed,
            opened_at_ms: 0,
            probe_in_flight: false,
        }
    }
}

/// A set of per-key circuit breakers.
#[derive(Debug)]
pub struct CircuitBreakers {
    cells: Mutex<HashMap<String, BreakerCell>>,
    failure_threshold: u32,
    cooldown_ms: u64,
}

impl CircuitBreakers {
    /// Open after `failure_threshold` consecutive failures; probe again after
    /// `cooldown_ms`.
    #[must_use]
    pub fn new(failure_threshold: u32, cooldown_ms: u64) -> Self {
        Self {
            cells: Mutex::new(HashMap::new()),
            failure_threshold,
            cooldown_ms,
        }
    }

    /// Whether a request to `key` may proceed at `now_ms`. Admits normally when
    /// closed, never when open (until cooldown elapses), and exactly one probe
    /// when half-open.
    #[must_use]
    pub fn allow(&self, key: &str, now_ms: u64) -> bool {
        let mut cells = self.cells.lock().expect("breaker lock poisoned");
        let cell = cells.entry(key.to_string()).or_default();
        match cell.state {
            BreakerState::Closed => true,
            BreakerState::Open => {
                if now_ms.saturating_sub(cell.opened_at_ms) >= self.cooldown_ms {
                    cell.state = BreakerState::HalfOpen;
                    cell.probe_in_flight = true;
                    true
                } else {
                    false
                }
            }
            BreakerState::HalfOpen => {
                if cell.probe_in_flight {
                    false // a probe is already outstanding
                } else {
                    cell.probe_in_flight = true;
                    true
                }
            }
        }
    }

    /// Record the outcome of a request to `key`.
    pub fn record(&self, key: &str, success: bool, now_ms: u64) {
        let mut cells = self.cells.lock().expect("breaker lock poisoned");
        let cell = cells.entry(key.to_string()).or_default();
        cell.probe_in_flight = false;
        if success {
            cell.consecutive_failures = 0;
            cell.state = BreakerState::Closed;
        } else {
            cell.consecutive_failures += 1;
            if cell.state == BreakerState::HalfOpen
                || cell.consecutive_failures >= self.failure_threshold
            {
                cell.state = BreakerState::Open;
                cell.opened_at_ms = now_ms;
            }
        }
    }

    /// Current state of a key's breaker (diagnostics/metrics).
    #[must_use]
    pub fn state(&self, key: &str) -> BreakerState {
        self.cells
            .lock()
            .expect("breaker lock poisoned")
            .get(key)
            .map_or(BreakerState::Closed, |c| c.state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_after_threshold_failures() {
        let cb = CircuitBreakers::new(3, 1000);
        for _ in 0..3 {
            assert!(cb.allow("up", 0));
            cb.record("up", false, 0);
        }
        assert_eq!(cb.state("up"), BreakerState::Open);
        assert!(!cb.allow("up", 100)); // still within cooldown
    }

    #[test]
    fn half_open_probe_then_close_on_success() {
        let cb = CircuitBreakers::new(1, 500);
        assert!(cb.allow("up", 0));
        cb.record("up", false, 0); // opens
        assert!(!cb.allow("up", 100));
        // After cooldown, a single probe is admitted.
        assert!(cb.allow("up", 600));
        assert_eq!(cb.state("up"), BreakerState::HalfOpen);
        assert!(!cb.allow("up", 600)); // no second concurrent probe
        cb.record("up", true, 600); // probe succeeded -> closed
        assert_eq!(cb.state("up"), BreakerState::Closed);
        assert!(cb.allow("up", 700));
    }

    #[test]
    fn half_open_probe_failure_reopens() {
        let cb = CircuitBreakers::new(1, 500);
        assert!(cb.allow("up", 0));
        cb.record("up", false, 0);
        assert!(cb.allow("up", 600)); // probe
        cb.record("up", false, 600); // probe failed
        assert_eq!(cb.state("up"), BreakerState::Open);
        assert!(!cb.allow("up", 700));
    }

    #[test]
    fn success_resets_failure_count() {
        let cb = CircuitBreakers::new(3, 1000);
        cb.record("up", false, 0);
        cb.record("up", false, 0);
        cb.record("up", true, 0); // reset
        cb.record("up", false, 0);
        assert_eq!(cb.state("up"), BreakerState::Closed);
    }
}
