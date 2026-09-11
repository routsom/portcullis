//! A small, bounded decision cache.
//!
//! Keyed on a fully-qualifying string (tenant, principal, capability, arg-shape,
//! subject fingerprint, policy epoch), so a hit is always a correct reuse
//! (CLAUDE.md §5 row #1). Eviction is FIFO, which is enough to bound memory; the
//! working set of active (principal, capability) pairs is small.

use std::collections::HashMap;
use std::collections::VecDeque;

/// A capacity-bounded FIFO cache.
#[derive(Debug)]
pub struct DecisionCache<V> {
    map: HashMap<String, V>,
    order: VecDeque<String>,
    capacity: usize,
}

impl<V: Clone> DecisionCache<V> {
    /// Create a cache holding at most `capacity` entries. A capacity of 0
    /// disables caching.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    /// Fetch a cached value.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<V> {
        self.map.get(key).cloned()
    }

    /// Insert a value, evicting the oldest entry if at capacity.
    pub fn put(&mut self, key: String, value: V) {
        if self.capacity == 0 {
            return;
        }
        if let Some(slot) = self.map.get_mut(&key) {
            *slot = value;
            return;
        }
        while self.map.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.map.remove(&oldest);
            } else {
                break;
            }
        }
        self.order.push_back(key.clone());
        self.map.insert(key, value);
    }

    /// Drop all entries (e.g. after a policy reload).
    pub fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evicts_oldest_when_over_capacity() {
        let mut c = DecisionCache::new(2);
        c.put("a".into(), 1);
        c.put("b".into(), 2);
        c.put("c".into(), 3); // evicts "a"
        assert_eq!(c.get("a"), None);
        assert_eq!(c.get("b"), Some(2));
        assert_eq!(c.get("c"), Some(3));
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn zero_capacity_disables_caching() {
        let mut c = DecisionCache::new(0);
        c.put("a".into(), 1);
        assert_eq!(c.get("a"), None);
    }

    #[test]
    fn overwrite_does_not_grow() {
        let mut c = DecisionCache::new(2);
        c.put("a".into(), 1);
        c.put("a".into(), 9);
        assert_eq!(c.get("a"), Some(9));
        assert_eq!(c.len(), 1);
    }
}
