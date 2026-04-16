//! Pluggable session storage.
//!
//! Integration layers (MCP, HTTP, etc.) track `SessionState` across multiple
//! actions for the same caller. The default in-memory store is fine for
//! single-node use; multi-node deployments need a shared store (Redis, etc.)
//! so invalidation on node A is visible to node B.
//!
//! # Failure semantics
//!
//! `get` returns `Ok(None)` when the session is not found — that is *not* an
//! error. `Err` is reserved for genuine backend failures. Callers should
//! treat `Err` on `get` as fail-closed: do not permit an action when session
//! state cannot be verified.

use crate::context::SessionState;
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::RwLock;
use thiserror::Error;

/// Errors returned by a [`SessionStore`] implementation.
#[derive(Debug, Error)]
pub enum SessionStoreError {
    /// The backing store is unreachable.
    #[error("session backend unavailable: {0}")]
    BackendUnavailable(String),

    /// A stored session could not be decoded.
    #[error("session store corruption: {0}")]
    Corrupt(String),

    /// Any other store-specific failure.
    #[error("session store: {0}")]
    Other(String),
}

/// Backing store for session state.
///
/// `get` on an unknown session returns `Ok(None)`, not an error.
#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Fetch a session by id. Returns `Ok(None)` if absent.
    async fn get(&self, session_id: &str) -> Result<Option<SessionState>, SessionStoreError>;

    /// Store (create or overwrite) a session.
    async fn put(&self, session_id: &str, session: SessionState) -> Result<(), SessionStoreError>;

    /// Remove a session. Idempotent — removing a missing session is not an error.
    async fn delete(&self, session_id: &str) -> Result<(), SessionStoreError>;

    /// Remove sessions whose `age()` exceeds `max_age_seconds`.
    /// Returns the number of sessions removed for observability.
    async fn cleanup(&self, max_age_seconds: i64) -> Result<u64, SessionStoreError>;
}

/// Process-local in-memory session store.
///
/// Not distributed. Sessions are lost on process restart.
#[derive(Debug, Default)]
pub struct InMemorySessionStore {
    sessions: RwLock<HashMap<String, SessionState>>,
}

impl InMemorySessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Count of currently stored sessions (for observability/tests).
    pub fn len(&self) -> usize {
        self.sessions.read().map(|g| g.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl SessionStore for InMemorySessionStore {
    async fn get(&self, session_id: &str) -> Result<Option<SessionState>, SessionStoreError> {
        let guard = self
            .sessions
            .read()
            .map_err(|_| SessionStoreError::Other("session lock poisoned".into()))?;
        Ok(guard.get(session_id).cloned())
    }

    async fn put(&self, session_id: &str, session: SessionState) -> Result<(), SessionStoreError> {
        let mut guard = self
            .sessions
            .write()
            .map_err(|_| SessionStoreError::Other("session lock poisoned".into()))?;
        guard.insert(session_id.to_string(), session);
        Ok(())
    }

    async fn delete(&self, session_id: &str) -> Result<(), SessionStoreError> {
        let mut guard = self
            .sessions
            .write()
            .map_err(|_| SessionStoreError::Other("session lock poisoned".into()))?;
        guard.remove(session_id);
        Ok(())
    }

    async fn cleanup(&self, max_age_seconds: i64) -> Result<u64, SessionStoreError> {
        let mut guard = self
            .sessions
            .write()
            .map_err(|_| SessionStoreError::Other("session lock poisoned".into()))?;
        let before = guard.len();
        let now = Utc::now();
        guard.retain(|_, s| (now - s.started_at).num_seconds() < max_age_seconds);
        let removed = before.saturating_sub(guard.len()) as u64;
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_session() -> SessionState {
        SessionState::new()
    }

    #[tokio::test]
    async fn get_missing_returns_none() {
        let store = InMemorySessionStore::new();
        assert!(store.get("nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn put_then_get_roundtrip() {
        let store = InMemorySessionStore::new();
        let s = sample_session();
        let id = s.session_id.to_string();
        store.put(&id, s.clone()).await.unwrap();

        let loaded = store.get(&id).await.unwrap().expect("session present");
        assert_eq!(loaded.session_id, s.session_id);
    }

    #[tokio::test]
    async fn put_overwrites_existing() {
        let store = InMemorySessionStore::new();
        let mut s = sample_session();
        let id = s.session_id.to_string();
        store.put(&id, s.clone()).await.unwrap();

        s.invalidated = true;
        store.put(&id, s.clone()).await.unwrap();

        let loaded = store.get(&id).await.unwrap().unwrap();
        assert!(loaded.invalidated);
    }

    #[tokio::test]
    async fn delete_removes_and_is_idempotent() {
        let store = InMemorySessionStore::new();
        let s = sample_session();
        let id = s.session_id.to_string();
        store.put(&id, s).await.unwrap();
        store.delete(&id).await.unwrap();
        assert!(store.get(&id).await.unwrap().is_none());

        // Idempotent — second delete still succeeds.
        store.delete(&id).await.unwrap();
    }

    #[tokio::test]
    async fn cleanup_removes_old_sessions() {
        let store = InMemorySessionStore::new();

        // A "fresh" session (started_at = now).
        let fresh = sample_session();
        let fresh_id = fresh.session_id.to_string();
        store.put(&fresh_id, fresh).await.unwrap();

        // An "old" session — manually age its started_at by 10 minutes.
        let mut old = sample_session();
        old.started_at = Utc::now() - chrono::Duration::minutes(10);
        let old_id = old.session_id.to_string();
        store.put(&old_id, old).await.unwrap();

        // Cleanup sessions older than 60s.
        let removed = store.cleanup(60).await.unwrap();
        assert_eq!(removed, 1);

        assert!(store.get(&fresh_id).await.unwrap().is_some());
        assert!(store.get(&old_id).await.unwrap().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_put_and_get_dont_race() {
        use std::sync::Arc;
        let store = Arc::new(InMemorySessionStore::new());
        let mut handles = Vec::new();

        for i in 0..50 {
            let s = store.clone();
            handles.push(tokio::spawn(async move {
                let session = sample_session();
                let id = format!("s-{i}");
                s.put(&id, session).await.unwrap();
                let loaded = s.get(&id).await.unwrap();
                assert!(loaded.is_some());
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(store.len(), 50);
    }
}
