//! Token-bucket rate limiting.
//!
//! Per-tenant / per-principal / per-capability buckets bound request rate
//! (CLAUDE.md §5 row #11). The limiter is keyed by an opaque string the caller
//! composes, and is time-driven by an explicit monotonic-millis clock so it is
//! deterministically testable.

use std::collections::HashMap;
use std::sync::Mutex;

/// A capacity-bounded token-bucket rate limiter shared across keys.
#[derive(Debug)]
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, Bucket>>,
    capacity: f64,
    refill_per_sec: f64,
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last_ms: u64,
}

impl RateLimiter {
    /// Create a limiter where each key gets `capacity` burst tokens, refilling at
    /// `refill_per_sec` tokens per second.
    #[must_use]
    pub fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            capacity,
            refill_per_sec,
        }
    }

    /// Attempt to consume one token for `key` at `now_ms`. Returns `true` if the
    /// request is allowed, `false` if the bucket is empty.
    #[must_use]
    pub fn allow(&self, key: &str, now_ms: u64) -> bool {
        let mut buckets = self.buckets.lock().expect("rate limiter lock poisoned");
        let bucket = buckets.entry(key.to_string()).or_insert(Bucket {
            tokens: self.capacity,
            last_ms: now_ms,
        });
        // Refill based on elapsed time.
        let elapsed = now_ms.saturating_sub(bucket.last_ms);
        if elapsed > 0 {
            // Elapsed millis are small in practice; f64 precision loss at the
            // extreme is irrelevant to a rate calculation.
            #[allow(clippy::cast_precision_loss)]
            let refill = (elapsed as f64 / 1000.0) * self.refill_per_sec;
            bucket.tokens = (bucket.tokens + refill).min(self.capacity);
            bucket.last_ms = now_ms;
        }
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Number of tracked keys (diagnostics).
    #[must_use]
    pub fn tracked_keys(&self) -> usize {
        self.buckets
            .lock()
            .expect("rate limiter lock poisoned")
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_capacity_then_denies() {
        let rl = RateLimiter::new(3.0, 1.0);
        assert!(rl.allow("k", 0));
        assert!(rl.allow("k", 0));
        assert!(rl.allow("k", 0));
        assert!(!rl.allow("k", 0)); // burst exhausted
    }

    #[test]
    fn refills_over_time() {
        let rl = RateLimiter::new(1.0, 2.0); // 2 tokens/sec
        assert!(rl.allow("k", 0));
        assert!(!rl.allow("k", 0));
        // 500ms -> 1 token refilled.
        assert!(rl.allow("k", 500));
    }

    #[test]
    fn keys_are_independent() {
        let rl = RateLimiter::new(1.0, 0.0);
        assert!(rl.allow("a", 0));
        assert!(!rl.allow("a", 0));
        assert!(rl.allow("b", 0)); // separate bucket
    }

    #[test]
    fn refill_is_capped_at_capacity() {
        let rl = RateLimiter::new(2.0, 100.0);
        assert!(rl.allow("k", 0));
        // Long gap would overfill, but capacity caps it at 2.
        assert!(rl.allow("k", 10_000));
        assert!(rl.allow("k", 10_000));
        assert!(!rl.allow("k", 10_000));
    }
}
