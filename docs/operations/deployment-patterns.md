# Deployment patterns

Kavach is a library, not a daemon. It runs inside the host service's process (one `Gate` instance per process, shared across request handlers). Pick a pattern based on how many processes need to agree.

Three patterns cover the majority of production deployments:

1. Single-node (everything in-memory).
2. Multi-node with shared Redis (rate-limit, sessions, invalidation broadcast).
3. Hub-and-spoke with a shared public-key directory (one signer, many verifiers).

Plus one rollout mode that composes with all of the above: observe-only.

Cross-links:

- [concepts/gate-and-verdicts.md](../concepts/gate-and-verdicts.md) for the evaluation pipeline the patterns wire up.
- [guides/distributed.md](../guides/distributed.md) for the fuller multi-node tour.
- [operations/observability.md](observability.md) for tracing and metrics once deployed.
- [operations/incident-response.md](incident-response.md) for the playbooks that lean on these patterns.

---

## Pattern 1: Single-node

One process, one `Gate`, all state in memory. Simplest thing that works.

```
          ┌─────────────────────────────────────┐
          │             host process             │
          │                                      │
          │   HTTP/MCP handler                   │
          │         │                            │
          │         ▼                            │
          │   ┌───────────┐                      │
          │   │   Gate    │                      │
          │   │  (Arc)    │                      │
          │   └─────┬─────┘                      │
          │         │                            │
          │  ┌──────┴────────────────────────┐   │
          │  │ InMemoryRateLimitStore        │   │
          │  │ InMemorySessionStore          │   │
          │  │ NoopInvalidationBroadcaster   │   │
          │  │ AuditLog (memory) | JSONL file│   │
          │  └───────────────────────────────┘   │
          └─────────────────────────────────────┘
```

Wiring, `Gate::new` defaults + whatever audit sink suits you:

```rust
use kavach_core::{
    DriftEvaluator, Gate, GateConfig, Invariant, InvariantSet,
    PolicyEngine, PolicySet,
};
use std::sync::Arc;

let policies = PolicySet::from_file("kavach.toml")?;
let policy_engine = Arc::new(PolicyEngine::new(policies));
let drift = Arc::new(DriftEvaluator::with_defaults());
let invariants = Arc::new(InvariantSet::new(vec![
    Invariant::param_max("max_refund", "amount", 50_000.0),
    Invariant::max_actions_per_session("session_limit", 500),
]));

let gate = Gate::new(
    vec![policy_engine, drift, invariants],
    GateConfig::default(),
);
```

What you get:

- Gate hot path is synchronous Rust with one async await (the rate-limit condition, against the in-memory store). In-memory store is constant-time hash-map work.
- No network round trips. No distributed consistency to think about.
- `NoopInvalidationBroadcaster` is the default. Local `Invalidate` verdicts are honored inside this process; there are no peers.
- Audit can be in-memory (`AuditLog`), written to JSONL via `SignedAuditChain::export_jsonl`, or plugged into your existing log sink.

What you give up:

- Rate-limit counters do not cross processes. If you run two copies of the service, a caller gets `2 * max` per window.
- Session invalidation is local-only. A session killed on node A is still live on node B.
- Losing the process loses the rate-limit counters and any in-memory audit buffer. Persist the audit chain to disk if you need forensics.

Use single-node when you have exactly one process (MCP server on one host, dev box, CI, a small control-plane service), or when "best-effort, per-process" rate limits and invalidations are what you actually want.

---

## Pattern 2: Multi-node with shared Redis

One Redis, N application processes. Every process runs its own `Gate`; they share rate-limit state, session state, and invalidation fan-out through Redis.

The three Redis-backed trait impls live in `kavach-redis`:

- `RedisRateLimitStore`: sliding-window counters via sorted sets (keys under `kavach:rl:*`).
- `RedisSessionStore`: JSON-encoded sessions with Redis-managed TTL (keys under `kavach:session:*`).
- `RedisInvalidationBroadcaster`: Redis Pub/Sub bridged into a local `tokio::broadcast` channel, so subscribers look identical to the in-memory broadcaster.

```
          ┌───────────────┐   ┌───────────────┐   ┌───────────────┐
          │  app node A   │   │  app node B   │   │  app node C   │
          │   Gate        │   │   Gate        │   │   Gate        │
          │               │   │               │   │               │
          │  RateStore──┐ │   │  RateStore──┐ │   │  RateStore──┐ │
          │  SessStore──┤ │   │  SessStore──┤ │   │  SessStore──┤ │
          │  Bcaster────┤ │   │  Bcaster────┤ │   │  Bcaster────┤ │
          └─────────────┼─┘   └─────────────┼─┘   └─────────────┼─┘
                        │                   │                   │
                        └───────────┐   ┌───┴───┐   ┌───────────┘
                                    ▼   ▼       ▼   ▼
                              ┌───────────────────────┐
                              │        Redis          │
                              │                       │
                              │  kavach:rl:*   (ZSET) │
                              │  kavach:session:*     │
                              │  Pub/Sub "kavach.inv" │
                              └───────────────────────┘
```

Wiring:

```rust
use kavach_core::{DriftEvaluator, Gate, GateConfig, PolicyEngine, PolicySet};
use kavach_redis::{
    RedisInvalidationBroadcaster, RedisRateLimitStore, RedisSessionStore,
};
use std::sync::Arc;

let client = redis::Client::open("redis://redis.internal:6379/0")?;

let rate_store = Arc::new(RedisRateLimitStore::new(client.clone()).await?);
let session_store = Arc::new(RedisSessionStore::new(client.clone()).await?);
let broadcaster = Arc::new(
    RedisInvalidationBroadcaster::new(client.clone(), "kavach.inv").await?,
);

let policies = PolicySet::from_file("kavach.toml")?;
let policy_engine = Arc::new(
    PolicyEngine::with_rate_store(policies, rate_store.clone()),
);
let drift = Arc::new(DriftEvaluator::with_defaults());

let gate = Gate::new(vec![policy_engine, drift], GateConfig::default())
    .with_broadcaster(broadcaster.clone());
```

Sessions are threaded through the store by the integrator (HTTP middleware, MCP session manager). See [guides/distributed.md](../guides/distributed.md) for the full wiring of a session-aware listener.

Failure semantics (pin these to muscle memory, they are the reason Kavach is safe):

- Redis unreachable on `RateLimitStore::record` → gate returns `Refuse`. Fail-closed.
- Redis unreachable on `RateLimitStore::count_in_window` → the `RateLimit` condition evaluates to `false`, the policy does not match, default-deny kicks in.
- Redis unreachable on `InvalidationBroadcaster::publish` → local `Invalidate` verdict still stands. Logged at `warn`. The peer notification is best-effort on purpose; see [kavach-core/src/gate.rs](../../kavach-core/src/gate.rs).

Cost per evaluation:

- Rate-limit `record` + `count_in_window`: two Redis round-trips per evaluation (sub-millisecond on a local Redis, a few ms over a region link). No Lua, no atomic compound ops, matching the in-memory semantics exactly.
- Session `get`/`put`: one round-trip each where the integrator touches the session.
- Broadcast `publish`: one Redis `PUBLISH` only on an `Invalidate` verdict.

Sizing: the gate itself is synchronous Rust with one async await per evaluator. Redis adds exactly one network round-trip per store call. Budget your p99 as `sum(evaluators' work) + 1 RTT * (rate-limit calls per evaluation)`.

---

## Pattern 3: Hub-and-spoke with a public-key directory

One (or a few) signer nodes issue signed `PermitToken`s. Many verifier nodes accept those tokens, using a shared `PublicKeyDirectory` to resolve `key_id → PublicKeyBundle`. This is the shape the e2e suite runs under: the support agent service signs; the payment service verifies.

```
             ┌─────────────────┐
             │  signer node    │
             │   Gate          │
             │   TokenSigner ──┼── signs PermitToken.signature with ML-DSA + Ed25519
             └────────┬────────┘
                      │  (PermitToken flows to the verifier)
                      ▼
             ┌─────────────────┐         ┌──────────────────────┐
             │ verifier node A │         │ verifier node B      │
             │ DirectoryToken  │────┐    │ DirectoryToken       │
             │   Verifier      │    │    │   Verifier           │
             └─────────────────┘    │    └──────────────────────┘
                                    │             │
                                    └──────┬──────┘
                                           ▼
                                ┌─────────────────────┐
                                │  PublicKeyDirectory │
                                │   (shared)          │
                                └─────────────────────┘
```

Three directory backends ship in `kavach-pq`:

- `InMemoryPublicKeyDirectory`: populated in code. Tests and deployments that build the directory at startup.
- `FilePublicKeyDirectory`: loads a signed manifest from disk. Good fit when a shared volume (NFS, object store with FUSE, baked-into-image) distributes the manifest. Call `reload()` to pick up a new file.
- `HttpPublicKeyDirectory` (`http_directory.rs`): fetches a signed manifest over HTTP with ETag caching. `If-None-Match` keeps warm-cache refreshes at zero-body cost; on HTTP failure with a warm cache, the verifier serves stale and logs a warning (on a cold cache, it fails closed).

Signed manifests are always verified against a pinned root ML-DSA-65 public key at load time. See [concepts/key-management.md](../concepts/key-management.md).

Wiring a verifier with a file-backed signed directory:

```rust
use kavach_pq::{DirectoryTokenVerifier, FilePublicKeyDirectory};
use std::sync::Arc;

let root_vk: Vec<u8> = std::fs::read("root.vk")?;
let directory = Arc::new(
    FilePublicKeyDirectory::load_signed("directory.signed.json", root_vk)?,
);

let verifier = DirectoryTokenVerifier::hybrid(directory.clone());
// use `verifier.verify(&token, &sig).await` in the verifier service
```

Algorithm mode is strict in both directions: a hybrid verifier refuses a PQ-only envelope (downgrade guard), a PQ-only verifier refuses a hybrid envelope. Every `KeyDirectoryError` variant (`NotFound`, `BackendUnavailable`, `RootSignatureInvalid`, `Corrupt`, `Other`) causes the verifier to reject the token. Fail-closed on every path.

When to pick which backend:

- `InMemory`: tests, dev, and processes that know the full set of keys at startup.
- `File`: most production deployments. Ship the manifest via your existing config-distribution pipeline (GitOps, config map, baked image). Reload on `SIGHUP` or on a file watcher.
- `HTTP`: when the signer node exposes the manifest itself and verifiers should poll. The ETag keeps refresh cost near-zero.

Key rotation is the operational lever here and is covered in [operations/incident-response.md](incident-response.md).

---

## Pattern 4: Observe-only rollout

Not a deployment topology, a phase. Compose this with any of the patterns above when you are introducing Kavach into an existing service.

`GateConfig::observe_only = true` in Rust (or `observe_only=True` / `observeOnly: true` as a `Gate.from_toml` option in the Python / Node SDKs) makes the gate run every evaluator, log the verdict it *would* have returned, and then return `Permit` unconditionally. Nothing is blocked. You learn what your live traffic looks like before enforcing.

```rust
use kavach_core::{Gate, GateConfig};

let gate = Gate::new(
    evaluators,
    GateConfig {
        observe_only: true,
        ..GateConfig::default()
    },
);
```

The code path (see [kavach-core/src/gate.rs](../../kavach-core/src/gate.rs), `evaluate_observe_only`):

1. Run every evaluator as normal.
2. If the real verdict is not `Permit`, log at `info` level: `"observe-only: would have blocked this action"`.
3. Issue a fresh `Permit` and return it.

The HTTP integration respects this flag since P1.7: `HttpGate` dispatches to `evaluate_observe_only` when `config.observe_only` is set, so you do not need a separate middleware for the observation phase.

Rollout sequence that actually works in practice:

1. Week 1: deploy with `observe_only = true`. Tracing goes to your normal log stack. Count `"would have blocked"` lines per policy, per endpoint, per principal. See [operations/observability.md](observability.md).
2. Week 2: tune policies based on the observation data. False positives become exceptions or policy adjustments.
3. Week 3: flip `observe_only = false` on a canary node. Watch refusal rates.
4. Week 4: roll out enforcement everywhere.

Observe-only is safe to ship immediately because nothing blocks. It is also safe to re-enable if enforcement causes an incident: flip the flag, redeploy, you are back to logging-only while you investigate.

---

## Sizing guidance

The gate hot path is synchronous Rust with one `await` per evaluator that touches a store. Most evaluators are pure CPU:

- `PolicyEngine`: one rate-limit `record` + up to one `count_in_window` per condition. All other conditions are sync branches on `ActionContext`.
- `DriftEvaluator`: sync, runs each configured detector (IP, geo, role, session-age).
- `InvariantSet`: sync, runs each invariant against the action's params and session.

Stores:

- `InMemoryRateLimitStore`: amortized O(1) per call (hash-map + small sorted vec, bounded by the window).
- `RedisRateLimitStore`: one round-trip per call. Co-locate the Redis with your app region.
- `InMemorySessionStore`: hash-map.
- `RedisSessionStore`: one round-trip per `get` / `put`.

Signing adds time on `Permit` only (the signer never runs on `Refuse` or `Invalidate`). An ML-DSA-65 signature plus Ed25519 in hybrid mode is on the order of a few milliseconds per signed permit on modern hardware. If every request is gated and every permit is signed, this is your p99 floor. If you gate mutations only (see `HttpMiddlewareConfig::gate_mutations_only`), reads pass through without any signing cost.

The audit chain writes happen out of band via `AuditSink::record`, behind the verdict path. Pick an implementation whose durability matches your forensics budget: in-memory is fine for reconstruction within a process lifetime; JSONL-on-disk or a `SignedAuditChain` exported periodically is what you want for real incident response.
