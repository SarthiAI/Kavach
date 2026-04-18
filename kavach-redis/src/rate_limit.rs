//! Redis-backed sliding-window rate-limit store.
//!
//! Each `key` maps to a sorted set whose members are unique timestamps. A
//! counter `record` inserts a new entry and prunes anything older than
//! [`RETENTION_SECS`]; `count_in_window` uses `ZCOUNT` on the `(cutoff, now]`
//! interval.
//!
//! This matches the semantics of
//! [`InMemoryRateLimitStore`](kavach_core::rate_limit::InMemoryRateLimitStore):
//! half-open interval, record-first-then-check, 24-hour retention.

use async_trait::async_trait;
use kavach_core::rate_limit::{RateLimitStore, RateLimitStoreError};
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use uuid::Uuid;

/// 24-hour retention — anything older is pruned opportunistically on `record`.
/// Matches the in-memory default's retention so hot paths see identical
/// memory/key shapes across deployments.
const RETENTION_SECS: i64 = 86_400;

/// Redis key prefix for rate-limit sorted sets. All keys produced by this
/// store live under `kavach:rl:*` so operators can monitor / flush them
/// without touching unrelated Redis state.
const KEY_PREFIX: &str = "kavach:rl";

/// Redis-backed rate-limit store.
///
/// Clone is cheap — the underlying [`ConnectionManager`] is internally
/// reference-counted, so clones share the same pool and auto-reconnect logic.
#[derive(Clone)]
pub struct RedisRateLimitStore {
    conn: ConnectionManager,
}

impl RedisRateLimitStore {
    /// Build a store from an already-configured [`redis::Client`].
    ///
    /// This is the preferred constructor when you want to share a client
    /// across [`RedisRateLimitStore`], [`crate::RedisSessionStore`], and
    /// [`crate::RedisInvalidationBroadcaster`].
    pub async fn new(client: redis::Client) -> Result<Self, RateLimitStoreError> {
        let conn = tokio::time::timeout(crate::CONNECT_TIMEOUT, ConnectionManager::new(client))
            .await
            .map_err(|_| {
                RateLimitStoreError::BackendUnavailable(format!(
                    "redis connect timed out after {:?}",
                    crate::CONNECT_TIMEOUT
                ))
            })?
            .map_err(|e| RateLimitStoreError::BackendUnavailable(e.to_string()))?;
        Ok(Self { conn })
    }

    /// Convenience constructor from a Redis URL (`redis://host:port/db`).
    pub async fn from_url(url: &str) -> Result<Self, RateLimitStoreError> {
        let client = redis::Client::open(url)
            .map_err(|e| RateLimitStoreError::BackendUnavailable(e.to_string()))?;
        Self::new(client).await
    }

    fn key(user_key: &str) -> String {
        format!("{KEY_PREFIX}:{user_key}")
    }
}

#[async_trait]
impl RateLimitStore for RedisRateLimitStore {
    async fn record(&self, key: &str, at: i64) -> Result<(), RateLimitStoreError> {
        let redis_key = Self::key(key);

        // Unique member per record — two records with the same timestamp must
        // both be counted. Using a uuid suffix guarantees ZADD inserts rather
        // than updates on timestamp collision.
        let member = format!("{at}:{}", Uuid::new_v4());

        let mut conn = self.conn.clone();
        let mut pipe = redis::pipe();
        pipe.atomic()
            .zadd(&redis_key, &member, at)
            .zrembyscore(&redis_key, i64::MIN, at - RETENTION_SECS)
            .expire(&redis_key, RETENTION_SECS);

        pipe.query_async::<()>(&mut conn)
            .await
            .map_err(|e| RateLimitStoreError::BackendUnavailable(e.to_string()))?;
        Ok(())
    }

    async fn count_in_window(
        &self,
        key: &str,
        now: i64,
        window_secs: u64,
    ) -> Result<u64, RateLimitStoreError> {
        let redis_key = Self::key(key);
        let cutoff = now - window_secs as i64;

        // `(cutoff` is Redis' notation for exclusive lower bound — matches the
        // in-memory `t > cutoff` check. Upper bound is inclusive (`now`).
        let exclusive_lower = format!("({cutoff}");

        let mut conn = self.conn.clone();
        let count: u64 = conn
            .zcount(&redis_key, exclusive_lower, now)
            .await
            .map_err(|e| RateLimitStoreError::BackendUnavailable(e.to_string()))?;
        Ok(count)
    }
}
