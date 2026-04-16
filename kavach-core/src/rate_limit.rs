//! Pluggable rate-limit storage.
//!
//! The gate records action timestamps and queries counts within a sliding
//! window to enforce `Condition::RateLimit`. In a single-process deployment
//! the in-memory default is sufficient; in a clustered deployment the counts
//! must live in a shared store (Redis, etc.) so every node sees the same
//! view.
//!
//! Implementations are plugged into [`PolicyEngine`](crate::policy::PolicyEngine)
//! via [`PolicyEngine::with_rate_store`](crate::policy::PolicyEngine::with_rate_store).
//!
//! # Failure semantics
//!
//! Any `Err` returned by a store implementation is treated by the gate as a
//! **fail-closed** signal: the rate-limit condition evaluates to `false`, so
//! the policy does **not** match. This matches Kavach's default-deny posture:
//! if we can't prove the caller is under the limit, we refuse to permit.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::RwLock;
use thiserror::Error;

/// Errors returned by a [`RateLimitStore`] implementation.
#[derive(Debug, Error)]
pub enum RateLimitStoreError {
    /// The backing store is unreachable (Redis down, DB disconnected, etc.).
    #[error("rate-limit backend unavailable: {0}")]
    BackendUnavailable(String),

    /// A value already in the store was corrupt or malformed.
    #[error("rate-limit store corruption: {0}")]
    Corrupt(String),

    /// Any other store-specific failure.
    #[error("rate-limit store: {0}")]
    Other(String),
}

/// Backing store for rate-limit accounting.
///
/// Implementations must be safe to share across threads (`Send + Sync`) and
/// safe to call concurrently — the gate hits the store from every evaluation
/// on the hot path.
#[async_trait]
pub trait RateLimitStore: Send + Sync {
    /// Record one occurrence of `key` at unix-second `at`.
    ///
    /// `at` is supplied by the caller so the store doesn't read the system
    /// clock itself (which would drift across nodes and break tests).
    async fn record(&self, key: &str, at: i64) -> Result<(), RateLimitStoreError>;

    /// Count occurrences of `key` in the half-open interval `(now - window_secs, now]`.
    ///
    /// The interval is inclusive on the "now" side so that a just-recorded
    /// event counts immediately — this is what keeps rate limits accurate
    /// under record-first-then-check.
    async fn count_in_window(
        &self,
        key: &str,
        now: i64,
        window_secs: u64,
    ) -> Result<u64, RateLimitStoreError>;
}

/// Process-local in-memory rate-limit store.
///
/// Not distributed: each process has its own counts. Suitable for single-node
/// deployments, tests, and as a sensible default. Old entries are pruned
/// opportunistically on `record` (24-hour retention) to bound memory.
#[derive(Debug, Default)]
pub struct InMemoryRateLimitStore {
    actions: RwLock<HashMap<String, Vec<i64>>>,
}

impl InMemoryRateLimitStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Hard retention beyond which records are purged on write. 24 hours is
    /// long enough for the longest realistic rate-limit window and short
    /// enough that a long-lived process doesn't leak memory.
    const RETENTION_SECS: i64 = 86_400;
}

#[async_trait]
impl RateLimitStore for InMemoryRateLimitStore {
    async fn record(&self, key: &str, at: i64) -> Result<(), RateLimitStoreError> {
        let mut guard = self
            .actions
            .write()
            .map_err(|_| RateLimitStoreError::Other("rate-limit lock poisoned".into()))?;
        let entry = guard.entry(key.to_string()).or_default();
        entry.push(at);

        let cutoff = at - Self::RETENTION_SECS;
        entry.retain(|&t| t > cutoff);
        Ok(())
    }

    async fn count_in_window(
        &self,
        key: &str,
        now: i64,
        window_secs: u64,
    ) -> Result<u64, RateLimitStoreError> {
        let guard = self
            .actions
            .read()
            .map_err(|_| RateLimitStoreError::Other("rate-limit lock poisoned".into()))?;
        let cutoff = now - window_secs as i64;
        let count = guard
            .get(key)
            .map(|ts| ts.iter().filter(|&&t| t > cutoff && t <= now).count() as u64)
            .unwrap_or(0);
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn record_then_count_returns_one() {
        let store = InMemoryRateLimitStore::new();
        store.record("k", 100).await.unwrap();
        assert_eq!(store.count_in_window("k", 100, 60).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn count_without_record_returns_zero() {
        let store = InMemoryRateLimitStore::new();
        assert_eq!(store.count_in_window("missing", 100, 60).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn window_evicts_old_entries_from_count() {
        let store = InMemoryRateLimitStore::new();
        store.record("k", 100).await.unwrap();
        store.record("k", 150).await.unwrap();
        store.record("k", 200).await.unwrap();

        // At now=200 with window=60s → cutoff=140 → only t=150 and t=200 qualify.
        assert_eq!(store.count_in_window("k", 200, 60).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn keys_are_isolated() {
        let store = InMemoryRateLimitStore::new();
        store.record("a", 100).await.unwrap();
        store.record("a", 101).await.unwrap();
        store.record("b", 100).await.unwrap();

        assert_eq!(store.count_in_window("a", 200, 3600).await.unwrap(), 2);
        assert_eq!(store.count_in_window("b", 200, 3600).await.unwrap(), 1);
        assert_eq!(store.count_in_window("c", 200, 3600).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn retention_prunes_entries_beyond_24h() {
        let store = InMemoryRateLimitStore::new();
        let day = 86_400;

        // Write something 30 hours "ago"
        store.record("k", 0).await.unwrap();
        // Write something now — the prune runs on record
        store.record("k", day + 3600).await.unwrap();

        // Total records in the internal vec should be 1 (the old one pruned).
        let count = store
            .count_in_window("k", day + 3600, day as u64 * 2)
            .await
            .unwrap();
        assert_eq!(
            count, 1,
            "old entry should be pruned by record-time retention"
        );
    }

    #[tokio::test]
    async fn count_excludes_future_entries() {
        let store = InMemoryRateLimitStore::new();
        store.record("k", 200).await.unwrap();

        // Querying at now=100: the entry at t=200 is "in the future" and
        // should not count.
        assert_eq!(store.count_in_window("k", 100, 60).await.unwrap(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_records_are_all_counted() {
        use std::sync::Arc;
        let store = Arc::new(InMemoryRateLimitStore::new());
        let mut handles = Vec::new();

        for i in 0..100 {
            let s = store.clone();
            handles.push(tokio::spawn(async move {
                s.record("hot", 1_000 + i).await.unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        let count = store.count_in_window("hot", 1_200, 3600).await.unwrap();
        assert_eq!(count, 100, "no records should be lost under contention");
    }
}
