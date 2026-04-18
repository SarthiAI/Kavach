//! Redis-backed session store.
//!
//! Stores each session as a JSON blob under `kavach:session:{key}` with a
//! configurable TTL. Redis handles expiration automatically — the trait's
//! `cleanup` method is a no-op here because there is nothing for us to do
//! that Redis' own TTL plumbing doesn't already do better.
//!
//! ## TTL vs. `cleanup`
//!
//! The in-memory store's `cleanup(max_age_seconds)` iterates and removes
//! sessions whose `age()` exceeds the threshold. In Redis we instead set a
//! TTL at `put` time — so expired sessions vanish on their own schedule, and
//! `cleanup` has nothing to do. It returns `Ok(0)` and a debug-level log line.
//!
//! If the integrator needs a *different* max-age than the one configured at
//! construction, they should rebuild the store with the new TTL rather than
//! calling `cleanup`.

use async_trait::async_trait;
use kavach_core::context::SessionState;
use kavach_core::session_store::{SessionStore, SessionStoreError};
use redis::aio::ConnectionManager;
use redis::AsyncCommands;

const KEY_PREFIX: &str = "kavach:session";
const DEFAULT_TTL_SECS: u64 = 86_400;

/// Redis-backed session store.
///
/// Sessions are serialized as JSON and written with a Redis TTL. Cheap to
/// clone — the connection manager is internally reference-counted.
#[derive(Clone)]
pub struct RedisSessionStore {
    conn: ConnectionManager,
    ttl_secs: u64,
}

impl RedisSessionStore {
    /// Build a store from an already-configured [`redis::Client`] with a
    /// default 24-hour TTL per session.
    pub async fn new(client: redis::Client) -> Result<Self, SessionStoreError> {
        Self::with_ttl(client, DEFAULT_TTL_SECS).await
    }

    /// Build a store with a custom TTL (in seconds) applied on every `put`.
    ///
    /// A TTL of 0 is rejected — Redis treats it as "delete immediately",
    /// which would make the store useless.
    pub async fn with_ttl(client: redis::Client, ttl_secs: u64) -> Result<Self, SessionStoreError> {
        if ttl_secs == 0 {
            return Err(SessionStoreError::Other(
                "ttl_secs must be > 0 (Redis treats 0 as expire-now)".into(),
            ));
        }
        let conn = tokio::time::timeout(crate::CONNECT_TIMEOUT, ConnectionManager::new(client))
            .await
            .map_err(|_| {
                SessionStoreError::BackendUnavailable(format!(
                    "redis connect timed out after {:?}",
                    crate::CONNECT_TIMEOUT
                ))
            })?
            .map_err(|e| SessionStoreError::BackendUnavailable(e.to_string()))?;
        Ok(Self { conn, ttl_secs })
    }

    /// Convenience constructor from a Redis URL.
    pub async fn from_url(url: &str) -> Result<Self, SessionStoreError> {
        let client = redis::Client::open(url)
            .map_err(|e| SessionStoreError::BackendUnavailable(e.to_string()))?;
        Self::new(client).await
    }

    /// Convenience constructor from a URL plus custom TTL.
    pub async fn from_url_with_ttl(url: &str, ttl_secs: u64) -> Result<Self, SessionStoreError> {
        let client = redis::Client::open(url)
            .map_err(|e| SessionStoreError::BackendUnavailable(e.to_string()))?;
        Self::with_ttl(client, ttl_secs).await
    }

    fn key(session_id: &str) -> String {
        format!("{KEY_PREFIX}:{session_id}")
    }
}

#[async_trait]
impl SessionStore for RedisSessionStore {
    async fn get(&self, session_id: &str) -> Result<Option<SessionState>, SessionStoreError> {
        let redis_key = Self::key(session_id);
        let mut conn = self.conn.clone();

        let raw: Option<String> = conn
            .get(&redis_key)
            .await
            .map_err(|e| SessionStoreError::BackendUnavailable(e.to_string()))?;

        match raw {
            Some(json) => {
                let state: SessionState = serde_json::from_str(&json).map_err(|e| {
                    SessionStoreError::Corrupt(format!("session decode failed: {e}"))
                })?;
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }

    async fn put(&self, session_id: &str, session: SessionState) -> Result<(), SessionStoreError> {
        let redis_key = Self::key(session_id);
        let json = serde_json::to_string(&session)
            .map_err(|e| SessionStoreError::Corrupt(format!("session encode failed: {e}")))?;

        let mut conn = self.conn.clone();
        let _: () = conn
            .set_ex(&redis_key, json, self.ttl_secs)
            .await
            .map_err(|e| SessionStoreError::BackendUnavailable(e.to_string()))?;
        Ok(())
    }

    async fn delete(&self, session_id: &str) -> Result<(), SessionStoreError> {
        let redis_key = Self::key(session_id);
        let mut conn = self.conn.clone();

        // `DEL` returns the number of keys actually removed — not an error if
        // the key was absent. Idempotency matches the trait contract.
        let _: i64 = conn
            .del(&redis_key)
            .await
            .map_err(|e| SessionStoreError::BackendUnavailable(e.to_string()))?;
        Ok(())
    }

    async fn cleanup(&self, _max_age_seconds: i64) -> Result<u64, SessionStoreError> {
        // Redis TTL expires keys on its own schedule. We don't have a cheap
        // way to count expirations since the last call, and we won't SCAN the
        // whole keyspace just to produce a number. Return 0 and note it.
        tracing::debug!(
            "RedisSessionStore::cleanup is a no-op — Redis TTL handles expiration automatically"
        );
        Ok(0)
    }
}
