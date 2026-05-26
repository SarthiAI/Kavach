# kavach-redis

Redis-backed implementations of [Kavach](https://github.com/SarthiAI/Kavach)'s distributed stores. Use this when running Kavach across multiple replicas that need to share rate-limit counters, session invalidations, and cross-replica revocation fanout.

## What this crate gives you

- `RedisRateLimitStore`: implements `kavach_core::RateLimitStore` against Redis with atomic counter operations.
- `RedisSessionStore`: implements `kavach_core::SessionStore`, used by the MCP middleware for cross-replica `is_invalidated` checks.
- `RedisInvalidationBroadcaster`: implements `kavach_core::InvalidationBroadcaster` using Redis Pub/Sub. Pair with `spawn_invalidation_listener` from `kavach-core` to drain events on each replica.

All three connect through `ConnectionManager` with a shared 5-second connect timeout. A bad Redis URL surfaces as `BackendUnavailable("redis connect timed out after 5s")` within seconds rather than retrying forever.

## Status

**Experimental. Not yet thoroughly validated.**

Crate-level integration tests pass, but the end-to-end multi-replica deployment story is not yet covered by the consumer-validation harness. Use it for distributed deployments, expect rough edges before 1.0, and please file issues you hit.

## Failure model

The crate inherits Kavach's fail-closed posture:

- Rate-limit `record` failure: the entire evaluation refuses.
- Rate-limit `count` failure: the `RateLimit` condition evaluates to false (policy does not match, default-deny kicks in).
- Broadcast failure: the local verdict stands; peers may simply not see the invalidation. Local-first, best-effort globally.

## Quick example

```rust
use std::sync::Arc;
use kavach_core::{Gate, PolicyEngine};
use kavach_redis::{RedisRateLimitStore, RedisInvalidationBroadcaster};

let rate_store = Arc::new(RedisRateLimitStore::connect("redis://127.0.0.1/").await?);
let policy_engine = PolicyEngine::with_rate_store(rate_store);

let broadcaster = Arc::new(RedisInvalidationBroadcaster::connect("redis://127.0.0.1/").await?);
let gate = Gate::new(policy_engine).with_broadcaster(broadcaster);
```

## License

[Elastic License 2.0](https://github.com/SarthiAI/Kavach/blob/main/LICENSE). Source-available: you may embed and modify Kavach freely, but may not repackage it as a competing hosted service.
