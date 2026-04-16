# Gate and verdicts

The gate is the single enforcement point. It takes an `ActionContext`, runs every evaluator, and returns a `Verdict`. If (and only if) the verdict is `Permit`, the action may run.

## The evaluation pipeline

The gate holds `Vec<Arc<dyn Evaluator>>`, sorted by `evaluator.priority()` (lowest number first). On `Gate::evaluate(ctx)`:

1. **Session invalidation short-circuit.** If `ctx.session.invalidated == true`, the gate returns `Refuse` with code `SESSION_INVALID` immediately, before any evaluator runs.
2. **Evaluators run in order.** For each evaluator, the gate calls `evaluator.evaluate(ctx).await`.
   - `Permit`, continue to the next evaluator.
   - `Refuse`, stop and return that refusal.
   - `Invalidate`, stop, publish the scope to the `InvalidationBroadcaster`, and return the invalidation. The broadcast is best-effort; a broadcast failure is logged and does not change the local verdict.
3. **All evaluators permitted.** The gate mints a fresh `PermitToken`. If a `TokenSigner` is attached, the token is signed before it leaves the gate. If signing fails, the gate fails closed and returns `Refuse` with code `IDENTITY_FAILED`.

The suggested priority ranges are encoded in the `Evaluator` trait:

- `0`-`49`, identity resolution and session validation.
- `50`-`99`, policy evaluation (`PolicyEngine` is `50`).
- `100`-`149`, drift detection (`DriftEvaluator` is `100`).
- `150`-`199`, invariants (`InvariantSet` is `150`).
- `200`+, custom evaluators.

The order of the four built-in layers (identity, policy, drift, invariants) is enforced by these priorities, not by the gate hardcoding them. You compose the evaluators you want and the gate sorts them.

## The three verdict variants

```rust
// kavach-core/src/verdict.rs
pub enum Verdict {
    Permit(PermitToken),
    Refuse(RefuseReason),
    Invalidate(InvalidationScope),
}
```

There are exactly three outcomes. There is no "maybe" and there is no fallback path. Code that needs to act on a verdict uses `verdict.is_permit()`, `verdict.is_refuse()`, or `verdict.is_invalidate()`.

### `Permit(PermitToken)`

The action may proceed. The token is proof that the gate was consulted:

```rust
pub struct PermitToken {
    pub token_id: Uuid,
    pub evaluation_id: Uuid,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,   // default: issued_at + 30s
    pub action_name: String,
    pub signature: Option<Vec<u8>>,  // populated by TokenSigner if attached
}
```

Permits are **short-lived by design** (30-second default TTL) and **action-bound** (they cannot be replayed against a different action name). `PermitToken::canonical_bytes()` is the byte representation used for signing: `token_id (16B) || evaluation_id (16B) || issued_ts_le (8B) || expires_ts_le (8B) || action_name_utf8`. The signature itself is excluded so the verifier can reconstruct the signed bytes without knowing the signature.

When a `TokenSigner` (typically `kavach_pq::PqTokenSigner`) is attached, every permit is signed before it leaves the gate. See [post-quantum.md](post-quantum.md).

### `Refuse(RefuseReason)`

The action is blocked. The refusal carries a human-readable reason, the evaluator that refused, the evaluation id, and a machine-readable code:

```rust
pub enum RefuseCode {
    IdentityFailed,
    PolicyDenied,
    NoPolicyMatch,          // default-deny
    RateLimitExceeded,
    SessionInvalid,
    InvariantViolation,
    DriftDetected,
    PermitExpired,
}
```

Default-deny shows up as `NoPolicyMatch`. An explicit `effect = "refuse"` policy match shows up as `PolicyDenied`.

### `Invalidate(InvalidationScope)`

The action is blocked *and* prior authority is revoked. Only `DriftEvaluator` (and any custom evaluator you write) can produce this verdict. The scope describes what is being revoked:

```rust
pub struct InvalidationScope {
    pub target: InvalidationTarget,  // Session(Uuid) | Principal(String) | Role(String)
    pub reason: String,
    pub evaluator: String,
}
```

When the gate emits `Invalidate`, it calls `broadcaster.publish(scope).await` so peer nodes can drop the invalidated session from their caches. The default broadcaster is a no-op, suitable for single-node deployments. Plug in a real one via `Gate::with_broadcaster`. See [guides/distributed.md](../guides/distributed.md).

## The `Guarded<A>` proof type

`Gate::evaluate` returns a `Verdict` but does not wrap the action. The wrapping API is `Gate::guard`:

```rust
pub async fn guard<A: Action>(
    &self,
    ctx: &ActionContext,
    action: A,
) -> Result<Guarded<A>, Verdict>;
```

`Guarded<A>` has three properties that make it load-bearing:

1. **No public constructor.** Its fields are private (and include a `_private: ()` to close the struct-literal loophole). You cannot build a `Guarded<A>` outside this crate.
2. **Uncloneable.** It does not implement `Clone` or `Copy`. A permit cannot be duplicated.
3. **Consumed by execution.** `Guarded::execute` takes `self` by value. Once you have executed the action, the `Guarded` is gone.

```rust
impl<A: Action> Guarded<A> {
    pub async fn execute(self) -> Result<A::Output, KavachError> {
        if self.token.is_expired() { /* PERMIT_EXPIRED */ }
        if !self.token.matches_action(&self.action.descriptor().name) {
            /* reject: permit is for a different action */
        }
        self.action.execute().await
    }
}
```

This is the compile-time part of the default-deny story. A function that takes `Guarded<RefundAction>` cannot be called without first getting past the gate, and nothing else in the program can mint a `Guarded<RefundAction>`. A code path that forgets the check does not compile.

## Configuration

```rust
pub struct GateConfig {
    pub observe_only: bool,        // log verdicts but always Permit
    pub permit_ttl_seconds: u64,   // default 30
    pub fail_open: bool,           // default false; do not change without a reason
}
```

**Observe-only mode** (`observe_only = true`) is for rollout. The gate runs every evaluator, logs what it would have done, and always returns `Permit`. Use it to measure the blast radius of a new policy set before turning enforcement on. See [operations/deployment-patterns.md](../operations/deployment-patterns.md).

**Fail-open** is present for emergencies and off by default. Kavach is a fail-closed system: evaluator errors, broadcaster failures, rate-limit store failures, and token-signing failures all degrade to `Refuse`, not to `Permit`.

## Reading a verdict in practice

From the Rust README:

```rust
match gate.guard(&context, my_action).await {
    Ok(guarded) => {
        // The ONLY way to execute; consumes the permit.
        let result = guarded.execute().await?;
    }
    Err(Verdict::Refuse(reason)) => {
        println!("Blocked: {}", reason);   // reason formats as "[CODE] evaluator: message"
    }
    Err(Verdict::Invalidate(scope)) => {
        println!("Session revoked: {}", scope);
    }
    _ => unreachable!(),
}
```

From Python:

```python
verdict = gate.evaluate(ctx)
if verdict.is_permit:
    do_the_thing()
elif verdict.is_refuse:
    log.warn("blocked: [%s] %s: %s", verdict.code, verdict.evaluator, verdict.reason)
else:
    session_store.invalidate(ctx.session_id)
```

## Cross-references

- The trait that plugs into the gate: [evaluators.md](evaluators.md).
- The rules that drive the policy evaluator: [policies.md](policies.md).
- Signing the `PermitToken`: [post-quantum.md](post-quantum.md).
- Recording every verdict: [audit.md](audit.md).
