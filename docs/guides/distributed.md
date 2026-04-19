# Distributed deployments

> **Experimental. Not yet thoroughly validated.**
>
> The `kavach-redis` crate has Rust-level integration tests (run with `TEST_REDIS_URL=redis://... cargo test -p kavach-redis`) and the code has been exercised end to end by the authors, but the consumer-validation harness at `business-tests/` does not yet cover the multi-replica deployment story described below. The code is shipped on crates.io and the Python SDK exposes `RedisRateLimitStore` / `RedisSessionStore` / `RedisInvalidationBroadcaster` as classes, so nothing prevents an early adopter from wiring it up; just treat this guide as a reference rather than a production guarantee. Thorough end-to-end validation is tracked in the [roadmap](../roadmap.md).

Single-node Kavach uses three process-local stores: `InMemoryRateLimitStore`, `InMemorySessionStore`, `NoopInvalidationBroadcaster`. That's fine until one of these becomes true:

1. **You run more than one node.** Two replicas behind a load balancer, each with its own in-memory rate-limit counter, each letting the caller do 20 refunds per hour: the actual cap becomes `20 * replicas`. Rate limits only work if counters are shared.
2. **You need session invalidation to propagate.** `Verdict::Invalidate` on node A kills the session locally, but node B still honors it until it evaluates the same session and notices something is off. An attacker whose session was killed can hop to node B and keep operating.
3. **Process restart should preserve session state.** In-memory means "gone on restart." If you rolling-restart your fleet every deploy, every in-flight session dies.

The fix is to move the three plug points onto a shared backend. Today the supported backend is Redis, via the `kavach-redis` crate. This guide walks through the wiring.

If you haven't read it yet, [gate-and-verdicts.md](../concepts/gate-and-verdicts.md) covers what the three stores actually do inside the gate; this guide focuses on the operational wiring.

---

## What `kavach-redis` ships

Three types, one per pluggable trait:

| Type | Trait | What it stores |
|---|---|---|
| `RedisRateLimitStore` | `kavach_core::rate_limit::RateLimitStore` | Sliding-window counters in sorted sets. |
| `RedisSessionStore` | `kavach_core::session_store::SessionStore` | Session state as JSON blobs with TTL. |
| `RedisInvalidationBroadcaster` | `kavach_core::invalidation::InvalidationBroadcaster` | Pub/Sub to local `tokio::broadcast` bridge. |

All three are cheap to clone (they hold a `redis::aio::ConnectionManager` internally, which is reference-counted and auto-reconnects on transient failures). All three expose `new(client)` and `from_url(url)` constructors.

`Cargo.toml`:

```toml
[dependencies]
kavach-core  = "0.1"
kavach-redis = "0.1"
redis        = "0.26"
tokio        = { version = "1", features = ["full"] }
```

---

## `RedisRateLimitStore`: shared rate-limit counters

**Shape.** One Redis sorted set per rate-limit key, under `kavach:rl:{key}`. Members are `{timestamp}:{uuid}`: the UUID suffix is there so two `record()` calls with the same unix-second both land as distinct members (a timestamp collision otherwise silently drops one).

**`record(key, at)`.** Single atomic pipeline: `ZADD` the new member, `ZREMBYSCORE` anything older than `RETENTION_SECS` (24 hours), `EXPIRE` the whole set. Retention matches the in-memory default so the memory profile is identical across deployments.

**`count_in_window(key, now, window_secs)`.** `ZCOUNT` over `(now - window_secs, now]`. The lower bound is exclusive, the upper bound is inclusive: this matches the in-memory store so a rate-limit condition evaluates identically under either backend.

**Fail-closed.** Any Redis error from `record` propagates as `RateLimitStoreError::BackendUnavailable`. The gate interprets that as a fail-closed signal:

- `record` error causes the *entire* evaluation to Refuse (we couldn't record the action, so we refuse rather than permit without accounting).
- `count_in_window` error makes the `RateLimit` condition evaluate to `false`, meaning the policy doesn't match, meaning default-deny kicks in.

Either way, Redis down is never "free refunds."

### Wiring (Rust)

```rust
use kavach_core::{Gate, GateConfig, PolicyEngine, PolicySet};
use kavach_redis::RedisRateLimitStore;
use std::sync::Arc;

let policies = PolicySet::from_file("kavach.toml").expect("valid policy toml");
let rate_store = Arc::new(
    RedisRateLimitStore::from_url("redis://127.0.0.1:6379").await?,
);

// PolicyEngine::with_rate_store is the plug point. The default `new(...)`
// uses InMemoryRateLimitStore; swap for a distributed store here.
let policy_engine = Arc::new(PolicyEngine::with_rate_store(policies, rate_store));

let gate = Arc::new(Gate::new(
    vec![policy_engine],
    GateConfig::default(),
));
```

### Wiring (Python)

```python
from kavach import Gate, RedisRateLimitStore

POLICY = {"policies": [...]}

rate_store = RedisRateLimitStore("redis://127.0.0.1:6379")
gate = Gate.from_dict(POLICY, rate_store=rate_store)
```

### Verified behaviour (from kavach-redis integration tests)

```rust
use kavach_core::rate_limit::RateLimitStore;
use kavach_redis::RedisRateLimitStore;

let store = RedisRateLimitStore::from_url("redis://127.0.0.1:6379").await.unwrap();

// Two records at identical timestamps both count: the uuid suffix makes them distinct.
store.record("caller:agent-bot:issue_refund", 100).await.unwrap();
store.record("caller:agent-bot:issue_refund", 100).await.unwrap();
assert_eq!(
    store.count_in_window("caller:agent-bot:issue_refund", 100, 60).await.unwrap(),
    2,
);

// Sliding window evicts old entries.
store.record("caller:agent-bot:issue_refund", 150).await.unwrap();
store.record("caller:agent-bot:issue_refund", 200).await.unwrap();
// now=200, window=60s, cutoff=140, t=150 and t=200 qualify, t=100 does not.
assert_eq!(
    store.count_in_window("caller:agent-bot:issue_refund", 200, 60).await.unwrap(),
    2,
);
```

---

## `RedisSessionStore`: shared session state

**Shape.** One Redis key per session: `kavach:session:{session_id}` maps to a JSON-serialized `SessionState`. `SET EX` writes the blob with a TTL; the default TTL is 24 hours.

**Why TTL, not `cleanup`.** The `SessionStore` trait exposes a `cleanup(max_age_seconds)` method that deletes stale sessions. In the Redis backend this is a no-op that returns `Ok(0)`: Redis expires keys on its own schedule via the TTL set at `put` time, so there's no work for `cleanup` to do. If you want a different max-age, reconstruct the store with a new TTL; don't call `cleanup`.

**TTL = 0 is rejected.** Redis treats `SET EX 0` as "delete immediately," so `RedisSessionStore::with_ttl(client, 0)` returns an error at construction rather than handing you a useless store.

**Fail-closed.** `get` returning `Err` means the caller cannot verify the session; pair this with an integrator session check that refuses the action on lookup failure.

### Wiring (Rust)

```rust
use kavach_redis::RedisSessionStore;
use std::sync::Arc;

let session_store = Arc::new(
    RedisSessionStore::from_url("redis://127.0.0.1:6379").await?,
);
```

Use it from your integration layer to look up `SessionState` on each incoming request before handing the context to `Gate::evaluate`.

### Wiring (Python)

```python
from kavach import RedisSessionStore
session_store = RedisSessionStore("redis://127.0.0.1:6379")
```

---

## `RedisInvalidationBroadcaster`: cross-node invalidation

**Shape.** The `InvalidationBroadcaster::subscribe()` trait returns a concrete `tokio::sync::broadcast::Receiver`. Redis Pub/Sub has its own stream type, so the Redis implementation spawns a background task that owns the subscription, decodes each message as an `InvalidationScope`, and fans it out through a local `broadcast::Sender`. Callers of `subscribe()` get a receiver on that local sender, which is exactly the type the trait promised.

**Lifecycle.**

- The bridge task is spawned once at construction and lives as long as any `RedisInvalidationBroadcaster` clone exists.
- All clones share a single `Arc<Inner>`; dropping the last clone drops `Inner`, whose `Drop` impl aborts the bridge task.
- If the Pub/Sub stream fails mid-flight (Redis restart, network blip), the bridge logs and retries with a 2-second backoff. It never silently exits.

**Fail-closed semantics, but only locally.**

- `publish` error: logged by the gate, but the local `Invalidate` verdict still stands. You already decided to kill the session on this node; Redis being unreachable does not undo that. Invalidation is best-effort *across the fleet* but fail-closed *locally*.
- A subscribing node that is currently disconnected from Redis will miss the publish while disconnected. When it reconnects, it picks up the next publish, not the one it missed. This is why `InvalidationBroadcaster` is paired with session state in a shared store: a missed invalidation can still be caught when the node next reads the session and sees `invalidated = true`.

### Wiring (Rust)

```rust
use kavach_core::{Gate, GateConfig};
use kavach_redis::RedisInvalidationBroadcaster;
use std::sync::Arc;

let broadcaster = Arc::new(
    RedisInvalidationBroadcaster::from_url(
        "redis://127.0.0.1:6379",
        "kavach:invalidation",
    ).await?,
);

let gate = Gate::new(evaluators, GateConfig::default())
    .with_broadcaster(broadcaster.clone());
```

Every node in the fleet constructs its broadcaster pointing at the same channel name. Every `Verdict::Invalidate` on any node fans out to every other node's local `broadcast::Sender`, which anything calling `spawn_invalidation_listener` consumes.

### Wiring (Python)

```python
from kavach import Gate, RedisInvalidationBroadcaster, spawn_invalidation_listener

broadcaster = RedisInvalidationBroadcaster(
    "redis://127.0.0.1:6379",
    channel="kavach:invalidation",
)
gate = Gate.from_dict(POLICY, broadcaster=broadcaster)

handle = spawn_invalidation_listener(
    broadcaster,
    lambda scope: print(f"invalidated: {scope.target} ({scope.reason})"),
)
# handle.abort() on shutdown
```

### Running a listener (Rust)

The broadcaster by itself only delivers scopes; to actually flip the session state on receipt, spawn a listener:

```rust
use kavach_core::{invalidation::spawn_session_store_listener, SessionStore};
use std::sync::Arc;

// Same Redis session store the local gate already reads from. When a remote
// invalidation arrives, we flip `invalidated = true` on the local session
// row; next evaluation on *this* node will see it.
let listener_handle = spawn_session_store_listener(
    broadcaster.clone(),
    session_store.clone(),
);

// The handle is yours. Dropping it does NOT stop the task: call .abort()
// explicitly on shutdown if you want deterministic teardown.
tokio::spawn(async move {
    tokio::signal::ctrl_c().await.ok();
    listener_handle.abort();
});
```

For `InvalidationTarget::Principal` or `InvalidationTarget::Role` (where the store-based handler logs "unhandled") use `spawn_invalidation_listener` with a custom closure:

```rust
use kavach_core::invalidation::{spawn_invalidation_listener, InvalidationTarget};

let handle = spawn_invalidation_listener(broadcaster.clone(), move |scope| {
    let store = session_store.clone();
    async move {
        match scope.target {
            InvalidationTarget::Principal(id) => {
                revoke_all_sessions_for_principal(&store, &id).await;
            }
            InvalidationTarget::Role(role) => {
                revoke_all_sessions_with_role(&store, &role).await;
            }
            InvalidationTarget::Session(_) => {
                // Already handled by spawn_session_store_listener if you wire that too.
            }
        }
    }
});
# async fn revoke_all_sessions_for_principal(_: &std::sync::Arc<dyn kavach_core::SessionStore>, _: &str) {}
# async fn revoke_all_sessions_with_role(_: &std::sync::Arc<dyn kavach_core::SessionStore>, _: &str) {}
```

---

## Putting it all together (Rust)

A two-node fleet pointed at the same Redis:

```rust
use kavach_core::{
    Evaluator, Gate, GateConfig, PolicyEngine, PolicySet, SessionStore,
    invalidation::spawn_session_store_listener,
};
use kavach_redis::{
    RedisInvalidationBroadcaster, RedisRateLimitStore, RedisSessionStore,
};
use std::sync::Arc;

async fn build_node() -> anyhow::Result<Arc<Gate>> {
    let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());

    // Shared stores.
    let rate_store = Arc::new(RedisRateLimitStore::from_url(&url).await?);
    let session_store: Arc<dyn SessionStore> =
        Arc::new(RedisSessionStore::from_url(&url).await?);
    let broadcaster = Arc::new(
        RedisInvalidationBroadcaster::from_url(&url, "kavach:invalidation").await?,
    );

    // Policy engine wired to the shared rate store.
    let policies = PolicySet::from_file("kavach.toml")?;
    let policy_engine = Arc::new(PolicyEngine::with_rate_store(policies, rate_store));

    // Gate wired to the shared broadcaster. Every Verdict::Invalidate
    // fans out to every other node.
    let gate = Arc::new(
        Gate::new(vec![policy_engine as Arc<dyn Evaluator>], GateConfig::default())
            .with_broadcaster(broadcaster.clone()),
    );

    // Local listener that flips the shared session blob on remote invalidation.
    let _listener = spawn_session_store_listener(broadcaster.clone(), session_store.clone());

    Ok(gate)
}
```

Deploy that same binary twice behind a load balancer. The three stores do their jobs:

- Rate limits on `issue_refund` are counted across both nodes. A caller's 20/hour cap is actually 20/hour, not 40.
- Session state lives in Redis with a 24-hour TTL, so a rolling deploy doesn't lose in-flight sessions.
- `Verdict::Invalidate` on node A lands on node B via Pub/Sub; node B's listener flips the session's `invalidated` flag in the shared Redis blob.

---

## Cross-instance invalidation test

This is the canonical shape of the two-node test, lifted from [../../kavach-redis/tests/integration.rs](../../kavach-redis/tests/integration.rs) (`broadcaster_cross_instance_delivery`):

```rust
use kavach_core::invalidation::InvalidationBroadcaster;
use kavach_core::verdict::{InvalidationScope, InvalidationTarget};
use kavach_redis::RedisInvalidationBroadcaster;
use std::time::Duration;
use tokio::time::timeout;
use uuid::Uuid;

#[tokio::test]
async fn broadcaster_cross_instance_delivery() {
    let url = std::env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL");
    let channel = format!("test-inv-cross:{}", Uuid::new_v4());

    // Two broadcaster instances sharing a channel: the distributed scenario.
    // Node A publishes, node B receives.
    let publisher = RedisInvalidationBroadcaster::from_url(&url, channel.clone())
        .await.unwrap();
    let subscriber = RedisInvalidationBroadcaster::from_url(&url, channel.clone())
        .await.unwrap();

    let mut rx = subscriber.subscribe();

    // Give the bridge task a moment to SUBSCRIBE before we PUBLISH.
    // Redis drops messages published before the subscription is live.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let scope = InvalidationScope {
        target: InvalidationTarget::Session(Uuid::new_v4()),
        reason: "cross-node-test".into(),
        evaluator: "test".into(),
    };
    publisher.publish(scope.clone()).await.unwrap();

    let got = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("receive within timeout")
        .expect("channel open");
    assert_eq!(got.reason, "cross-node-test");
}
```

Run it:

```bash
docker run --rm -p 6379:6379 redis:7
TEST_REDIS_URL=redis://127.0.0.1:6379 \
  cargo test -p kavach-redis --test integration broadcaster_cross_instance_delivery
```

The 200 ms sleep before the publish is load-bearing: Redis Pub/Sub drops messages that arrive before any subscriber has confirmed its `SUBSCRIBE`. The bridge task needs a moment to complete the handshake. In production this is invisible (your subscribers stay up), but in a test you have to wait.

---

## Caveats

- **Single-node Redis only.** `kavach-redis` does not support Redis Cluster or Sentinel. One master, one connection URL.
- **Non-atomic record-then-check.** The rate-limit store runs `record` and `count_in_window` as separate round-trips, matching the in-memory store's non-atomic semantics. In a burst, you can momentarily overcount; the cap is approximate, not exact. If you need strict atomicity, implement a Lua-backed variant of `RateLimitStore` and plug it in via `PolicyEngine::with_rate_store`: the trait is pluggable.
- **Publish ordering is per-channel, not global.** Two invalidations on the same session from two different nodes arrive in whatever order Redis sees them. The invalidation is idempotent (a session is either invalid or not), so this doesn't matter for correctness.
- **Bridge reconnect is exponential backoff with a 2-second initial delay.** If your Redis is flapping, subscribers will be lossy during the flap: pair with shared session state (which is NOT lossy) so missed invalidations are still catchable when the session is next evaluated.

---

## Further reading

- [../concepts/gate-and-verdicts.md](../concepts/gate-and-verdicts.md): what an invalidation actually means.
- [../concepts/evaluators.md](../concepts/evaluators.md): which evaluators produce `Invalidate` vs. `Refuse`.
- [../operations/deployment-patterns.md](../operations/deployment-patterns.md): rolling-restart, blue-green, canary patterns with a shared Redis.
- [../operations/observability.md](../operations/observability.md): metrics to pull off each store (Redis latency, bridge reconnects, broadcaster lag).
