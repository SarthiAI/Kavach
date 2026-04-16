//! # Kavach — Redis backends
//!
//! Distributed implementations of the three pluggable traits from
//! `kavach-core`:
//!
//! - [`RedisRateLimitStore`] — sliding-window rate limits via Redis sorted sets.
//! - [`RedisSessionStore`] — session state as JSON blobs with Redis TTL.
//! - [`RedisInvalidationBroadcaster`] — cross-node session invalidation via
//!   Redis Pub/Sub, bridged into a local `tokio::sync::broadcast` channel so
//!   it satisfies [`InvalidationBroadcaster::subscribe`](kavach_core::invalidation::InvalidationBroadcaster::subscribe).
//!
//! ## Failure semantics — fail closed
//!
//! Every Redis error path surfaces as an `Err` up through the trait. The gate
//! interprets this as fail-closed: rate-limit condition evaluates to `false`
//! (policy does not match, default-deny kicks in); session `get` failures
//! refuse the action upstream; broadcast `publish` failures **never** downgrade
//! the local verdict — `Invalidate` still stands on the node that issued it.
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
