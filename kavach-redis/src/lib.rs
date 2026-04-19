//! # Kavach, Redis backends
//!
//! Distributed implementations of the three pluggable traits from
//! `kavach-core`:
//!
//! - [`RedisRateLimitStore`], sliding-window rate limits via Redis sorted sets.
//! - [`RedisSessionStore`], session state as JSON blobs with Redis TTL.
//! - [`RedisInvalidationBroadcaster`], cross-node session invalidation via
//!   Redis Pub/Sub, bridged into a local `tokio::sync::broadcast` channel so
//!   it satisfies [`InvalidationBroadcaster::subscribe`](kavach_core::invalidation::InvalidationBroadcaster::subscribe).
//!
//! ## Failure semantics, fail closed
//!
//! Every Redis error path surfaces as an `Err` up through the trait. The gate
//! interprets this as fail-closed: rate-limit condition evaluates to `false`
//! (policy does not match, default-deny kicks in); session `get` failures
//! refuse the action upstream; broadcast `publish` failures **never** downgrade
//! the local verdict, `Invalidate` still stands on the node that issued it.
//!
//! ## Connection management
//!
//! All three types accept either an already-built [`redis::Client`] (via
//! `new`) or a URL string (via `from_url`). Internally they use
//! [`redis::aio::ConnectionManager`], which auto-reconnects on transient
//! failures.
//!
//! ## Scope
//!
//! - Single-node Redis only. No cluster-mode support.
//! - No Sentinel/replica-aware client.
//! - No Lua scripts for atomic record-and-check. The rate-limit store runs
//!   `record` and `count_in_window` as separate round-trips, matching the
//!   non-atomic semantics of [`InMemoryRateLimitStore`](kavach_core::rate_limit::InMemoryRateLimitStore).

mod broadcaster;
mod rate_limit;
mod session_store;

pub use broadcaster::{RedisBroadcasterError, RedisInvalidationBroadcaster};
pub use rate_limit::RedisRateLimitStore;
pub use session_store::RedisSessionStore;

/// Bounded wait on the initial [`redis::aio::ConnectionManager::new`] handshake.
///
/// `ConnectionManager` is designed to retry forever, great for long-lived
/// processes surviving transient Redis blips, catastrophic for start-up time
/// when the URL is just wrong. Every `from_url` / `new` here wraps the
/// handshake in a `tokio::time::timeout(CONNECT_TIMEOUT, ...)` so a bad URL
/// surfaces as `BackendUnavailable` within seconds instead of hanging the
/// caller (discovered during FIX-2 smoke testing when a typo'd URL froze a
/// Python process indefinitely).
pub(crate) const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
