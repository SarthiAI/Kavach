//! Pluggable session-invalidation broadcast.
//!
//! When the gate returns `Verdict::Invalidate` on one node, every other node
//! that holds the same session must be told — otherwise an attacker whose
//! session was killed on node A can hop to node B and keep operating.
//!
//! This module defines the fan-out primitive:
//!
//! - [`InvalidationBroadcaster`] — publish+subscribe trait that ships an
//!   [`InvalidationScope`] to every interested node.
//! - [`NoopInvalidationBroadcaster`] — default. Single-node deployments see
//!   exactly today's behavior (invalidation is local-only). No background
//!   tasks, no network.
//! - [`InMemoryInvalidationBroadcaster`] — process-local fan-out over a
//!   `tokio::sync::broadcast` channel. Useful for multi-listener testing and
//!   for in-process integrations where the gate and session handler are
//!   separate subsystems.
//! - [`spawn_invalidation_listener`] — helper that drives a user-supplied
//!   async handler with every received scope. The integrator owns the
//!   returned [`JoinHandle`] and decides when to stop the listener.
//!
//! # Failure semantics
//!
//! Publishing is best-effort. If the broadcaster returns `Err` on `publish`,
//! the gate logs the failure and **still returns the `Invalidate` verdict**
//! — the local node invalidates normally. A broadcast outage must not
//! downgrade a security decision the local evaluators already made.
//!
//! `BroadcastError::Lagged(n)` specifically means `n` messages were dropped
//! because a subscriber was too slow. Listeners should treat this as a
//! signal to resync from an authoritative source if they track state.

use crate::session_store::{SessionStore, SessionStoreError};
use crate::verdict::{InvalidationScope, InvalidationTarget};
use async_trait::async_trait;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

/// Default channel capacity for [`InMemoryInvalidationBroadcaster`]. Large
/// enough to absorb a brief subscriber pause without lagging; small enough
/// that the buffer won't hide a chronically stuck subscriber.
const DEFAULT_BROADCAST_CAPACITY: usize = 1024;

/// Errors returned by an [`InvalidationBroadcaster`] implementation.
#[derive(Debug, Error)]
pub enum BroadcastError {
    /// The backing transport is unavailable (Redis down, NATS disconnected, etc.).
    #[error("invalidation broadcast backend unavailable: {0}")]
    BackendUnavailable(String),

    /// Subscriber fell behind and missed `n` messages.
    #[error("invalidation subscriber lagged — {0} messages dropped")]
    Lagged(u64),

    /// The broadcast channel has been closed (sender dropped, etc.).
    #[error("invalidation channel closed")]
    Closed,

    /// Any other implementation-specific failure.
    #[error("invalidation broadcast: {0}")]
    Other(String),
}

/// Publish+subscribe primitive for session invalidations.
///
/// Implementations must be `Send + Sync` and safe to share across threads.
#[async_trait]
pub trait InvalidationBroadcaster: Send + Sync {
    /// Publish an invalidation scope to all subscribers.
    ///
    /// Returns `Err` only on backend failure. Returning `Ok` does not
    /// guarantee every subscriber received the message (a slow subscriber
    /// may still `Lag`).
    async fn publish(&self, scope: InvalidationScope) -> Result<(), BroadcastError>;

    /// Open a new subscription. Each call returns an independent receiver
    /// — calling `subscribe()` twice yields two receivers, both of which
    /// will see every future `publish`.
    ///
    /// Subscribers created *after* a `publish` do not see that publish.
    fn subscribe(&self) -> broadcast::Receiver<InvalidationScope>;
}

/// No-op broadcaster — the default.
///
/// `publish` succeeds without doing anything. `subscribe` returns a receiver
/// attached to a channel no one sends on; the receiver stays open forever
/// but never yields.
#[derive(Debug)]
pub struct NoopInvalidationBroadcaster {
    // Hold the sender so receivers stay open (a dropped sender would cause
    // receivers to resolve to `Closed` immediately, which subscribers would
    // have to handle specially).
    sender: broadcast::Sender<InvalidationScope>,
}

impl NoopInvalidationBroadcaster {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(1);
        Self { sender }
    }
}

impl Default for NoopInvalidationBroadcaster {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl InvalidationBroadcaster for NoopInvalidationBroadcaster {
    async fn publish(&self, _scope: InvalidationScope) -> Result<(), BroadcastError> {
        Ok(())
    }

    fn subscribe(&self) -> broadcast::Receiver<InvalidationScope> {
        self.sender.subscribe()
    }
}

/// Process-local broadcaster backed by `tokio::sync::broadcast`.
///
/// Every `subscribe()` returns a new receiver; every `publish()` fans out to
/// all live receivers. Not distributed — each process has its own sender.
#[derive(Debug, Clone)]
pub struct InMemoryInvalidationBroadcaster {
    sender: broadcast::Sender<InvalidationScope>,
}

impl InMemoryInvalidationBroadcaster {
    /// Build a broadcaster with the default channel capacity.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_BROADCAST_CAPACITY)
    }

    /// Build a broadcaster with a custom channel capacity. A larger capacity
    /// tolerates slower subscribers at the cost of more memory per pending
    /// message.
    pub fn with_capacity(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Current number of live subscribers (observability/tests).
    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

impl Default for InMemoryInvalidationBroadcaster {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl InvalidationBroadcaster for InMemoryInvalidationBroadcaster {
    async fn publish(&self, scope: InvalidationScope) -> Result<(), BroadcastError> {
        // `broadcast::Sender::send` returns `Err` only when there are zero
        // receivers — which is legitimate ("nobody is listening") and should
        // not surface as an error. Treat it as success.
        let _ = self.sender.send(scope);
        Ok(())
    }

    fn subscribe(&self) -> broadcast::Receiver<InvalidationScope> {
        self.sender.subscribe()
    }
}

/// Spawn a tokio task that reads scopes from `broadcaster` and feeds each
/// one into `handler`.
///
/// Returns the task's [`JoinHandle`] so the integrator controls lifecycle
/// (abort on shutdown, etc.). The task exits cleanly when the broadcaster
/// has no more senders (channel closed).
///
/// `Lagged` errors are logged and recovery continues — a temporarily slow
/// handler shouldn't kill the listener.
pub fn spawn_invalidation_listener<F, Fut>(
    broadcaster: Arc<dyn InvalidationBroadcaster>,
    mut handler: F,
) -> JoinHandle<()>
where
    F: FnMut(InvalidationScope) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    let mut rx = broadcaster.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(scope) => handler(scope).await,
                Err(broadcast::error::RecvError::Closed) => {
                    tracing::debug!("invalidation listener: channel closed, exiting");
                    return;
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(
                        dropped = n,
                        "invalidation listener lagged — messages dropped",
                    );
                    // Continue — next recv will get a fresh message.
                }
            }
        }
    })
}

/// Convenience listener that applies every received invalidation to a
/// [`SessionStore`].
///
/// For `InvalidationTarget::Session(uuid)`, looks up the session by its
/// external key (if the integrator stores sessions keyed by the UUID
/// string). For `Principal` and `Role` targets, iterates the store is not
/// possible through the trait — those require integrator-specific logic
/// and are logged as "unhandled" here.
///
/// Use [`spawn_invalidation_listener`] with a custom handler if you need
/// principal- or role-scoped invalidation.
pub fn spawn_session_store_listener(
    broadcaster: Arc<dyn InvalidationBroadcaster>,
    store: Arc<dyn SessionStore>,
) -> JoinHandle<()> {
    spawn_invalidation_listener(broadcaster, move |scope| {
        let store = store.clone();
        async move {
            match &scope.target {
                InvalidationTarget::Session(uuid) => {
                    let key = uuid.to_string();
                    match store.get(&key).await {
                        Ok(Some(mut session)) => {
                            session.invalidated = true;
                            if let Err(err) = store.put(&key, session).await {
                                warn_store_err("put after remote invalidate", &key, err);
                            }
                        }
                        Ok(None) => {
                            tracing::debug!(
                                session_id = %uuid,
                                "remote invalidation for session not present locally"
                            );
                        }
                        Err(err) => warn_store_err("get during remote invalidate", &key, err),
                    }
                }
                InvalidationTarget::Principal(id) => {
                    tracing::info!(
                        principal = %id,
                        "remote principal invalidation received — integrator must handle"
                    );
                }
                InvalidationTarget::Role(role) => {
                    tracing::info!(
                        role = %role,
                        "remote role invalidation received — integrator must handle"
                    );
                }
            }
        }
    })
}

fn warn_store_err(op: &str, key: &str, err: SessionStoreError) {
    tracing::warn!(
        op = op,
        key = key,
        error = %err,
        "session store error during remote invalidation"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::InvalidationTarget;
    use tokio::time::{timeout, Duration};
    use uuid::Uuid;

    fn sample_scope() -> InvalidationScope {
        InvalidationScope {
            target: InvalidationTarget::Session(Uuid::new_v4()),
            reason: "test".into(),
            evaluator: "test".into(),
        }
    }

    #[tokio::test]
    async fn noop_publish_succeeds_and_subscribe_never_yields() {
        let b = NoopInvalidationBroadcaster::new();
        b.publish(sample_scope()).await.unwrap();

        let mut rx = b.subscribe();
        let got = timeout(Duration::from_millis(50), rx.recv()).await;
        assert!(got.is_err(), "noop subscriber must not receive anything");
    }

    #[tokio::test]
    async fn in_memory_publish_reaches_subscriber() {
        let b = InMemoryInvalidationBroadcaster::new();
        let mut rx = b.subscribe();
        let scope = sample_scope();
        b.publish(scope.clone()).await.unwrap();

        let got = timeout(Duration::from_millis(200), rx.recv())
            .await
            .expect("receive within timeout")
            .expect("channel open");
        assert_eq!(got.reason, scope.reason);
    }

    #[tokio::test]
    async fn in_memory_fans_out_to_every_subscriber() {
        let b = InMemoryInvalidationBroadcaster::new();
        let mut rx1 = b.subscribe();
        let mut rx2 = b.subscribe();
        assert_eq!(b.subscriber_count(), 2);

        b.publish(sample_scope()).await.unwrap();

        timeout(Duration::from_millis(200), rx1.recv())
            .await
            .unwrap()
            .unwrap();
        timeout(Duration::from_millis(200), rx2.recv())
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn publish_with_no_subscribers_is_not_an_error() {
        let b = InMemoryInvalidationBroadcaster::new();
        b.publish(sample_scope()).await.unwrap();
    }

    #[tokio::test]
    async fn late_subscriber_misses_earlier_messages() {
        let b = InMemoryInvalidationBroadcaster::new();
        b.publish(sample_scope()).await.unwrap();

        let mut rx = b.subscribe();
        let got = timeout(Duration::from_millis(50), rx.recv()).await;
        assert!(got.is_err(), "late subscriber should not see prior publish");
    }

    #[tokio::test]
    async fn listener_helper_delivers_every_scope_to_handler() {
        use std::sync::atomic::{AtomicU64, Ordering};

        let b: Arc<dyn InvalidationBroadcaster> = Arc::new(InMemoryInvalidationBroadcaster::new());
        let counter = Arc::new(AtomicU64::new(0));

        let c = counter.clone();
        let handle = spawn_invalidation_listener(b.clone(), move |_scope| {
            let c = c.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
            }
        });

        // Give the listener time to attach its subscriber before publishing.
        tokio::task::yield_now().await;

        for _ in 0..5 {
            b.publish(sample_scope()).await.unwrap();
        }

        // Wait long enough for all 5 scopes to be handled.
        for _ in 0..20 {
            if counter.load(Ordering::SeqCst) == 5 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(counter.load(Ordering::SeqCst), 5);

        handle.abort();
    }

    #[tokio::test]
    async fn listener_exits_cleanly_when_broadcaster_dropped() {
        // Construct a broadcaster, subscribe via the helper, then drop the
        // broadcaster. The listener should exit on its own (not block forever).
        let b: Arc<dyn InvalidationBroadcaster> = Arc::new(InMemoryInvalidationBroadcaster::new());
        let handle = spawn_invalidation_listener(b.clone(), |_scope| async {});

        drop(b);

        let result = timeout(Duration::from_millis(500), handle).await;
        assert!(
            result.is_ok(),
            "listener should exit when broadcaster is dropped"
        );
    }

    #[tokio::test]
    async fn session_store_listener_marks_session_invalidated() {
        use crate::context::SessionState;
        use crate::session_store::InMemorySessionStore;

        let broadcaster: Arc<dyn InvalidationBroadcaster> =
            Arc::new(InMemoryInvalidationBroadcaster::new());
        let store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());

        // Seed a session stored under its own uuid as the key.
        let session = SessionState::new();
        let session_key = session.session_id.to_string();
        store.put(&session_key, session.clone()).await.unwrap();

        let handle = spawn_session_store_listener(broadcaster.clone(), store.clone());
        tokio::task::yield_now().await;

        // Publish an invalidation for that session.
        broadcaster
            .publish(InvalidationScope {
                target: InvalidationTarget::Session(session.session_id),
                reason: "drift".into(),
                evaluator: "test".into(),
            })
            .await
            .unwrap();

        // Poll until the session is marked invalidated, or fail after 500ms.
        for _ in 0..50 {
            if let Ok(Some(s)) = store.get(&session_key).await {
                if s.invalidated {
                    handle.abort();
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("session was never marked invalidated by the listener");
    }
}
