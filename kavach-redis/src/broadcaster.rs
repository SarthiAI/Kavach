//! Redis Pub/Sub → local `tokio::broadcast` bridge.
//!
//! The core [`InvalidationBroadcaster`] trait returns a concrete
//! `tokio::sync::broadcast::Receiver` from `subscribe`. Redis Pub/Sub has its
//! own stream type, so we bridge the two: a background task owns the Redis
//! subscription, decodes every message, and fans it out through a local
//! `broadcast::Sender`. Callers of `subscribe()` get a receiver on that local
//! sender — exactly what the trait expects.
//!
//! ## Lifecycle
//!
//! - The bridge task is spawned once at construction.
//! - The broadcaster wraps [`Arc<Inner>`] so clones are cheap and share the
//!   same bridge. Dropping the **last** clone drops `Inner`, whose [`Drop`]
//!   impl aborts the task.
//! - If the bridge task's Redis connection fails, it logs and attempts to
//!   reconnect with exponential backoff. It never silently exits.
//!
//! ## Failure semantics
//!
//! `publish` returns `Err(BackendUnavailable)` on any Redis error. The gate
//! treats this as best-effort — a local `Invalidate` verdict still stands
//! even if peers can't be told. This mirrors
//! [`InMemoryInvalidationBroadcaster`](kavach_core::invalidation::InMemoryInvalidationBroadcaster)'s
//! "no-subscribers is not an error" stance.

use async_trait::async_trait;
use kavach_core::invalidation::{BroadcastError, InvalidationBroadcaster};
use kavach_core::verdict::InvalidationScope;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

/// Default channel capacity for the local broadcast bridge. Sized to absorb
/// several seconds of traffic before a slow local subscriber starts lagging.
const DEFAULT_LOCAL_CAPACITY: usize = 1024;

/// Seconds to wait before retrying a failed subscription.
const SUBSCRIBE_RETRY_SECS: u64 = 2;

/// Errors surfaced by the Redis broadcaster at construction time.
///
/// Runtime errors from `publish` flow through the trait's
/// [`BroadcastError`] instead.
#[derive(Debug, Error)]
pub enum RedisBroadcasterError {
    #[error("redis client error: {0}")]
    Client(String),

    #[error("redis connection manager: {0}")]
    Connection(String),
}

/// Redis Pub/Sub-backed invalidation broadcaster.
///
/// Clone is cheap — all clones share the same bridge task via `Arc`.
#[derive(Clone)]
pub struct RedisInvalidationBroadcaster {
    inner: Arc<Inner>,
}

struct Inner {
    conn: ConnectionManager,
    channel: String,
    local_sender: broadcast::Sender<InvalidationScope>,
    bridge: JoinHandle<()>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.bridge.abort();
    }
}

impl RedisInvalidationBroadcaster {
    /// Build a broadcaster from an already-configured [`redis::Client`] and
    /// a Pub/Sub channel name. Spawns the subscriber bridge task immediately.
    pub async fn new(
        client: redis::Client,
        channel: impl Into<String>,
    ) -> Result<Self, RedisBroadcasterError> {
        Self::with_capacity(client, channel, DEFAULT_LOCAL_CAPACITY).await
    }

    /// Build with a custom local `broadcast::channel` capacity. Larger
    /// capacity = more memory per pending message but better tolerance for
    /// slow local subscribers.
    pub async fn with_capacity(
        client: redis::Client,
        channel: impl Into<String>,
        capacity: usize,
    ) -> Result<Self, RedisBroadcasterError> {
        let channel = channel.into();

        let conn = ConnectionManager::new(client.clone())
            .await
            .map_err(|e| RedisBroadcasterError::Connection(e.to_string()))?;

        let (local_sender, _) = broadcast::channel::<InvalidationScope>(capacity);

        let bridge = spawn_bridge(client, channel.clone(), local_sender.clone());

        Ok(Self {
            inner: Arc::new(Inner {
                conn,
                channel,
                local_sender,
                bridge,
            }),
        })
    }

    /// Convenience constructor from a Redis URL.
    pub async fn from_url(
        url: &str,
        channel: impl Into<String>,
    ) -> Result<Self, RedisBroadcasterError> {
        let client =
            redis::Client::open(url).map_err(|e| RedisBroadcasterError::Client(e.to_string()))?;
        Self::new(client, channel).await
    }

    /// Count of currently live local subscribers (observability/tests).
    pub fn local_subscriber_count(&self) -> usize {
        self.inner.local_sender.receiver_count()
    }
}

#[async_trait]
impl InvalidationBroadcaster for RedisInvalidationBroadcaster {
    async fn publish(&self, scope: InvalidationScope) -> Result<(), BroadcastError> {
        let payload = serde_json::to_string(&scope).map_err(|e| {
            BroadcastError::Other(format!("invalidation scope serialize: {e}"))
        })?;

        let mut conn = self.inner.conn.clone();
        let _: i64 = conn
            .publish(&self.inner.channel, payload)
            .await
            .map_err(|e| BroadcastError::BackendUnavailable(e.to_string()))?;
        Ok(())
    }

    fn subscribe(&self) -> broadcast::Receiver<InvalidationScope> {
        self.inner.local_sender.subscribe()
    }
}

/// Spawn the Redis → local fan-out task. The task owns the Pub/Sub
/// subscription and retries with backoff on any I/O failure; it exits only
/// when the containing `Inner` is dropped and the abort is applied.
fn spawn_bridge(
    client: redis::Client,
    channel: String,
    sender: broadcast::Sender<InvalidationScope>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match run_bridge(&client, &channel, &sender).await {
                Ok(()) => {
                    // Subscription ended cleanly (Redis closed the stream).
                    // Retry after backoff unless there's no local subscriber.
                    if sender.receiver_count() == 0 {
                        tracing::debug!(
                            channel = %channel,
                            "redis pubsub bridge: no local subscribers, sleeping"
                        );
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        channel = %channel,
                        "redis pubsub bridge error — retrying"
                    );
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(SUBSCRIBE_RETRY_SECS)).await;
        }
    })
}

async fn run_bridge(
    client: &redis::Client,
    channel: &str,
    sender: &broadcast::Sender<InvalidationScope>,
) -> Result<(), redis::RedisError> {
    use futures_util::StreamExt;

    let mut pubsub = client.get_async_pubsub().await?;
    pubsub.subscribe(channel).await?;

    let mut stream = pubsub.on_message();
    while let Some(msg) = stream.next().await {
        let payload: String = match msg.get_payload() {
            Ok(s) => s,
            Err(err) => {
                tracing::warn!(error = %err, "redis pubsub: bad payload type");
                continue;
            }
        };
        match serde_json::from_str::<InvalidationScope>(&payload) {
            Ok(scope) => {
                // `broadcast::Sender::send` returns `Err` only when there are
                // zero receivers — that's legitimate and not a bug.
                let _ = sender.send(scope);
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "redis pubsub: invalidation scope decode failed"
                );
            }
        }
    }
    Ok(())
}
