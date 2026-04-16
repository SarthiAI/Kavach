# Observability

Kavach is instrumented with the `tracing` crate end-to-end. Evaluators emit decisions, stores emit failures, broadcasters emit publish errors, the gate emits lifecycle events. The integrator decides where those events go by installing a `tracing_subscriber`.

Two separate things are worth distinguishing:

- **Application logs** (this doc): runtime observability. `tracing` events from the gate, evaluators, stores, broadcasters. Volatile; scoped to process lifetime. Use for dashboards, alerts, live debugging.
- **Signed audit chain** (see [concepts/audit.md](../concepts/audit.md)): durable, tamper-evident record of every verdict. Use for forensics and incident response, not for real-time monitoring.

Cross-links:

- [operations/deployment-patterns.md](deployment-patterns.md) for the topologies these logs describe.
- [operations/incident-response.md](incident-response.md) for what to do when alerts fire.

---

## Enabling tracing at startup

`tracing_subscriber` is the standard consumer. The example services under `kavach-http/examples/` do not install it (they use `println!` for readability), so here is the minimal snippet to drop into a real service's `main`:

```rust
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info,kavach_core=info,kavach_pq=info")))
        .with(fmt::layer().json())        // structured JSON for log shipping
        .init();

    // ... build the gate, start the server ...
}
```

`RUST_LOG` overrides the default filter. For verbose diagnosis of a specific evaluator:

```
RUST_LOG="info,kavach_core::policy=debug,kavach_core::drift=debug"
```

SDKs (Python, Node) do not manage tracing on the Rust side beyond what the bindings log. Bridge them to your language's logger via environment variables; the underlying events still flow through the Rust subscriber.

---

## What Kavach logs, where to find it

The target tree roughly mirrors the crate tree:

| Target prefix | What lives there |
|---|---|
| `kavach_core::gate` | evaluation started/completed, observe-only "would have blocked" |
| `kavach_core::policy` | policy hits, default-deny misses, rate-limit store failures |
| `kavach_core::drift` | drift detections |
| `kavach_core::invariant` | invariant violations |
| `kavach_core::invalidation` | listener attach/detach, lag warnings |
| `kavach_core::rate_limit` | store errors |
| `kavach_core::session_store` | store errors, remote-invalidate handling |
| `kavach_core::watcher` | policy file reload results |
| `kavach_pq::audit` | signing, chain append |
| `kavach_pq::directory` | key-directory fetch/reload, root-signature verify |
| `kavach_pq::http_directory` | ETag hits, stale-cache fallbacks |
| `kavach_redis::*` | Redis round-trip failures, bridge reconnects |
| `kavach_http` | HTTP middleware gating decisions, body-size skips |

Representative events (grep the source for the exact wording):

- `gate evaluation started` at `info`: start of every evaluation. Fields: `evaluation_id`, `principal`, `action`.
- `action refused` at `warn`: a `Refuse` verdict. Fields: `evaluator`, `reason`.
- `authority invalidated` at `error`: an `Invalidate` verdict. Field: `scope`.
- `invalidation broadcast failed` at `warn`: the local `Invalidate` still stands; peers were not notified.
- `token signing failed` at `error`: a `TokenSigner` error downgraded `Permit` to `Refuse`.
- `rate-limit store record failed` at `warn`: the rate-limit store could not write; gate refuses (fail-closed).
- `rate-limit store error` at `warn`: the `RateLimit` condition hit a store error; condition evaluates to `false`.
- `policies reloaded` at `info`: emitted by `PolicyEngine::reload`. Field: number of rules.
- `observe-only: would have blocked this action` at `info`: real verdict was non-Permit, observe-only let it through.
- `TimeWindow: malformed` at `warn`: fail-closed on a policy window that would not parse.
- `key directory refresh failed` at `warn`: `HttpPublicKeyDirectory` saw a transient fetch failure with a warm cache.

Every structured field above (`evaluation_id`, `principal`, `action`, `evaluator`, `scope`, `error`, etc.) is emitted via `tracing`'s field syntax, so a JSON layer will surface them as first-class keys. Use those fields for dashboards rather than regexing free-text messages.

---

## Structured logging patterns

Three things you will almost always want in production:

1. **`evaluation_id` in every verdict event.** Already emitted by `Gate::evaluate`. Propagate it up into your HTTP request logs so you can join a request to its gate evaluation.
2. **`principal_id` and `action_name` as indexed fields.** The gate emits them; your sink should index them so you can break down refusal rates per principal and per action.
3. **Per-target log levels.** Drop evaluator-level debug noise in production, keep it at `info`. Turn up `kavach_core::policy=debug` only when investigating a specific policy match failure.

Sample JSON layer event shape (from the `fmt::layer().json()` snippet above):

```json
{
  "timestamp": "2026-04-16T12:34:56.789Z",
  "level": "WARN",
  "target": "kavach_core::gate",
  "fields": {
    "message": "action refused",
    "evaluator": "policy",
    "reason": "denied by policy 'agent_refunds_tight'"
  }
}
```

---

## What to alert on

These are the events that matter for on-call. Everything else is informational.

### Page immediately

- **`token signing failed`** at `error`, target `kavach_core::gate`. The signer is down or the key is unavailable. Every request that would have received a `Permit` is being converted to `Refuse`. User impact is total for gated actions.
  - Check the `TokenSigner` implementation: key loaded? HSM reachable? See [operations/incident-response.md](incident-response.md) for the key-compromise playbook if the cause is rotation.
- **`authority invalidated`** at `error`, target `kavach_core::gate`, correlated across multiple sessions in a short window. One Invalidate is expected. A surge of them is either an attack (principal rotated keys after a leak) or a misbehaving evaluator.
- **`rate-limit store record failed`** at `warn`, target `kavach_core::policy`, sustained for more than a minute. The rate-limit backend is unavailable and every gated action is being refused.

### Page within business hours

- **`invalidation broadcast failed`** at `warn`, target `kavach_core::gate`. The local gate is fine, but peers are not hearing the invalidation. An attacker whose session was killed on this node can still use it on others. Investigate the broadcaster (Redis? NATS? custom?).
- **`key directory refresh failed`** at `warn`, target `kavach_pq::http_directory`. Verifiers are accepting keys from a potentially outdated snapshot. If a rotation is in flight, this is your problem; if not, get the signer's manifest server back online before the next planned rotation.
- **`invalidation subscriber lagged`** at `warn`, target `kavach_core::invalidation`. A subscriber fell behind; invalidations were dropped. Re-sync the affected listener from an authoritative source.

### Track but do not page

- **`"action refused"`** rate per evaluator. Spikes on `policy` mean either an attacker or a legitimate policy mismatch. Spikes on `invariants` mean a rogue policy is being caught by the invariant floor (see [operations/incident-response.md](incident-response.md) scenario 2).
- **`"TimeWindow: malformed"`** and friends. Policy parse errors that made it past review. A deployed policy is partially dead; fix and redeploy.
- **`"policies reloaded: N rules"`** on unexpected nodes. Confirms hot-reload is happening where you expect it and only there.

---

## Integrating with existing stacks

### stdout / journald

The fmt layer writes to stdout by default. If your deploy framework (systemd, Docker, k8s) captures stdout into the node-level logging agent, you are done.

### OpenTelemetry

Add `tracing-opentelemetry` and layer it alongside the fmt layer. Every evaluation's `evaluation_id` becomes a natural span id you can correlate with upstream request traces.

```rust
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{prelude::*, fmt, EnvFilter};

let tracer = /* your OTLP tracer setup */;
tracing_subscriber::registry()
    .with(EnvFilter::from_default_env())
    .with(fmt::layer())
    .with(OpenTelemetryLayer::new(tracer))
    .init();
```

### Prometheus / metrics

Kavach does not emit metrics directly. The common pattern is to install a `tracing_subscriber` layer that increments counters on specific events (the `tracing-subscriber` ecosystem has several helpers; `metrics` + `tracing` is a direct path). Three counters are worth exposing:

- `kavach_verdict_total{evaluator, kind=permit|refuse|invalidate}`.
- `kavach_store_error_total{store=rate_limit|session, op=record|count|get|put}`.
- `kavach_broadcast_error_total{broadcaster}`.

Everything else (latency, request volume) you already have at the HTTP layer.

### Python / Node SDK

Rust `tracing` events still flow through whatever subscriber the host process has installed. The SDKs themselves log in the host language's usual way for binding-level events (construction, FFI errors). Keep the Rust subscriber as the source of truth for gate behavior; use the language logger for integration errors.

---

## Relationship to the audit chain

The signed audit chain is a separate durability tier. Every `Gate::evaluate` call records a `SignedAuditEntry` through an `AuditSink` if one is attached. That chain is cryptographically linked, signed with ML-DSA-65 (optionally + Ed25519 in hybrid mode), and survives process restarts.

Use application logs for "what is the gate doing right now, is it healthy, which alert should fire." Use the audit chain for "reconstruct exactly what this principal did between 02:00 and 03:00 last Tuesday and prove the record has not been tampered with." The two are complementary; the application log is not a substitute for the audit chain, and the audit chain is not a substitute for live observability.
