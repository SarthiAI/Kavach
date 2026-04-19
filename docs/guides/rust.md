# Rust integration guide

Kavach is a Rust-native library. `kavach-core` holds the gate, evaluators, policy engine, drift detectors, and invariants. `kavach-pq` layers post-quantum crypto (signed tokens, audit chains, secure channels). `kavach-redis` ships Redis-backed implementations of the distributed stores; see [distributed.md](distributed.md).

This guide covers the core integration surface in Rust. For the operator-edited TOML workflow, see [toml-policies.md](toml-policies.md).

> **Scope note.** `kavach-core` and `kavach-pq` have extensive Rust-level unit and integration tests (166 tests at last count, enforced with `RUSTFLAGS="-D warnings"` in CI). The authors' end-to-end consumer-validation harness at `business-tests/` runs through the Python SDK, so direct Rust integration does not share the same scenario-per-capability coverage the SDKs have. The code is production-quality from a core-library perspective; treat the specific integration patterns below as references validated by the Rust test suite and the examples under `Kavach/e2e-tests/`, not by the consumer harness. A Rust-level consumer catalogue is tracked in the [roadmap](../roadmap.md).

---

## Install

Kavach is published as a Cargo workspace. Pick the crates you need.

```toml
# Cargo.toml

[dependencies]
kavach-core = "0.1"               # gate, evaluators, policies
kavach-pq   = "0.1"               # signed tokens, audit chains, secure channel

tokio       = { version = "1", features = ["full"] }
serde_json  = "1"
```

While the crates are pre-release, reference them by local path or git:

```toml
kavach-core = { path = "../Kavach/kavach-core" }
kavach-pq   = { path = "../Kavach/kavach-pq" }
```

Optional features worth knowing:

- `kavach-core/watcher` enables `spawn_policy_watcher` (notify-based hot reload).
- `kavach-pq/http` enables `HttpPublicKeyDirectory` for pulling signed manifests over HTTP.

Building any crate that uses `kavach-py` transitively requires `PYO3_PYTHON` pointing at a compatible interpreter. See the project root's `CLAUDE.md` for the local dev recipe.

---

## First call: build a gate and evaluate

```rust
use kavach_core::{
    ActionContext, ActionDescriptor, EnvContext, Evaluator, Gate, GateConfig,
    PolicyEngine, PolicySet, Principal, PrincipalKind, SessionState, Verdict,
};
use chrono::Utc;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let policy_toml = r#"
[[policy]]
name = "permit_small_refunds"
effect = "permit"
conditions = [
    { identity_role = "support" },
    { action = "issue_refund" },
    { param_max = { field = "amount", max = 5000.0 } },
]
"#;

    let policy_engine = Arc::new(PolicyEngine::new(
        PolicySet::from_toml(policy_toml).expect("valid TOML"),
    ));
    let gate = Gate::new(
        vec![policy_engine as Arc<dyn Evaluator>],
        GateConfig::default(),
    );

    let ctx = ActionContext::new(
        Principal {
            id: "agent_priya".into(),
            kind: PrincipalKind::Agent,
            roles: vec!["support".into()],
            credentials_issued_at: Utc::now(),
            display_name: None,
        },
        ActionDescriptor::new("issue_refund")
            .with_resource("orders/ORD-42")
            .with_param("amount", serde_json::json!(1_500.0)),
        SessionState::new(),
        EnvContext::default(),
    );

    match gate.evaluate(&ctx).await {
        Verdict::Permit(token) => println!("permitted: {}", token.token_id),
        Verdict::Refuse(r)     => println!("refused:   {r}"),
        Verdict::Invalidate(s) => println!("invalidated: {s}"),
    }
}
```

An empty `PolicySet` is valid and default-denies every action. A matching `permit` policy is required before a permit is returned.

---

## Policy configuration

Policies are TOML. Every `[[policy]]` block has a `name`, `effect` (`permit` | `refuse`), optional `priority` (lower = evaluated first), and a list of `conditions` that must all match for the policy to apply.

```toml
[[policy]]
name = "agent_small_refunds"
effect = "permit"
priority = 10
conditions = [
    { identity_kind = "agent" },
    { action = "issue_refund" },
    { param_max = { field = "amount", max = 5_000.0 } },
    { rate_limit = { max = 50, window = "24h" } },
    { session_age_max = "4h" },
]
```

The complete condition reference lives in [../reference/policy-language.md](../reference/policy-language.md). A runnable kavach.toml with agent, support, service, and admin tiers is at `Kavach/examples/kavach.toml`.

---

## Building the evaluator chain

`Gate::new` takes any `Vec<Arc<dyn Evaluator>>`. The standard stack is policy, drift, invariants:

```rust
use kavach_core::{
    DriftEvaluator, Evaluator, Invariant, InvariantSet, PolicyEngine, PolicySet,
};
use std::sync::Arc;

let policy_engine = Arc::new(PolicyEngine::new(PolicySet::from_toml(policy_toml)?));
let drift         = Arc::new(DriftEvaluator::with_defaults());
let invariants    = Arc::new(InvariantSet::new(vec![
    Invariant::param_max("max_refund", "amount", 50_000.0),
    Invariant::max_actions_per_session("session_limit", 500),
    Invariant::blocked_actions(
        "no_destructive_sql",
        vec!["tables.delete".into(), "database.delete".into()],
    ),
]));

let evaluators: Vec<Arc<dyn Evaluator>> = vec![policy_engine, drift, invariants];
```

`Gate::new` sorts by `Evaluator::priority()` at construction time. First Refuse or Invalidate short-circuits the chain. Invariants always run, even if policy permits: the evaluator order is a sequence of vetoes, not a vote.

---

## Writing a custom evaluator

Implement `Evaluator`. Pick a priority range that places your check where it belongs in the chain (`50-99` policy, `100-149` drift, `150-199` invariants, `200+` custom).

```rust
use async_trait::async_trait;
use chrono::Timelike;
use kavach_core::{
    ActionContext, Evaluator, RefuseCode, RefuseReason, Verdict, PermitToken,
};

pub struct BusinessHoursOnly {
    pub start_hour: u32,
    pub end_hour: u32,
}

#[async_trait]
impl Evaluator for BusinessHoursOnly {
    fn name(&self) -> &str { "business_hours" }
    fn priority(&self) -> u32 { 200 }

    async fn evaluate(&self, ctx: &ActionContext) -> Verdict {
        let hour = ctx.evaluated_at.hour();
        if (self.start_hour..self.end_hour).contains(&hour) {
            // Permit tokens inside evaluators are placeholders; the gate
            // replaces them with a fresh one after the whole chain passes.
            Verdict::Permit(PermitToken::new(ctx.evaluation_id, ctx.action.name.clone()))
        } else {
            Verdict::Refuse(RefuseReason {
                evaluator: self.name().into(),
                reason: format!("action attempted outside {}:00-{}:00", self.start_hour, self.end_hour),
                code: RefuseCode::PolicyDenied,
                evaluation_id: ctx.evaluation_id,
            })
        }
    }
}
```

Add it to the chain like any other evaluator:

```rust
let gate = Gate::new(
    vec![policy_engine, drift, invariants, Arc::new(BusinessHoursOnly { start_hour: 9, end_hour: 18 })],
    GateConfig::default(),
);
```

---

## Wrapping actions with `Gate::guard`

The `Action` trait ties a concrete side effect to an `ActionDescriptor`. `Gate::guard` returns `Guarded<A>` only on Permit; `Guarded::execute` consumes the permit.

```rust
use async_trait::async_trait;
use kavach_core::{Action, ActionDescriptor, KavachError};

pub struct IssueRefund {
    pub order_id: String,
    pub amount: f64,
}

#[async_trait]
impl Action for IssueRefund {
    type Output = String;

    fn descriptor(&self) -> ActionDescriptor {
        ActionDescriptor::new("issue_refund")
            .with_resource(&self.order_id)
            .with_param("amount", serde_json::json!(self.amount))
    }

    async fn execute(self) -> Result<Self::Output, KavachError> {
        // Real work here. Network calls, DB writes, whatever.
        Ok(format!("refunded {} on {}", self.amount, self.order_id))
    }
}

async fn do_refund(gate: &Gate, ctx: &ActionContext) -> Result<String, Verdict> {
    let action = IssueRefund { order_id: "ORD-42".into(), amount: 1_500.0 };
    let guarded = gate.guard(ctx, action).await?; // Err on Refuse / Invalidate
    guarded.execute().await.map_err(|e| {
        // Execute may fail if the permit expired or the action name drifted.
        Verdict::Refuse(RefuseReason {
            evaluator: "execute".into(),
            reason: e.to_string(),
            code: RefuseCode::PermitExpired,
            evaluation_id: ctx.evaluation_id,
        })
    })
}
```

`Guarded<A>` has no public constructor. The only way to build one is through `Gate::guard`, so skipping the gate is a compile error in your codebase, not a runtime policy violation.

---

## Async evaluation details

- `Evaluator::evaluate` is `async`. The gate runs evaluators sequentially (short-circuit on first Refuse), not in parallel, because the semantics of "all must permit" are left-to-right.
- The `Condition::matches` surface became async in P0.2: `RateLimit` awaits a store; every other condition resolves synchronously inside the match arm.
- Locks are never held across an await. `find_matching_policy` clones the policy snapshot under the read lock, then drops the lock before awaiting any store.
- Store failures (rate-limit record / count) fail closed: the whole evaluation Refuses. Do not swap this for fail-open.

---

## Signed permit tokens with `PqTokenSigner`

`kavach-pq::PqTokenSigner` signs every permit with ML-DSA-65 (PQ-only) or ML-DSA-65 + Ed25519 (hybrid). Attach it with `Gate::with_token_signer`. If signing fails, the gate fails closed and converts the permit into a Refuse.

```rust
use kavach_core::{Gate, GateConfig};
use kavach_pq::{KavachKeyPair, PqTokenSigner};
use std::sync::Arc;

let kp = KavachKeyPair::generate().expect("keypair");
let signer: Arc<dyn kavach_core::TokenSigner> =
    Arc::new(PqTokenSigner::from_keypair_hybrid(&kp));

let gate = Gate::new(evaluators, GateConfig::default())
    .with_token_signer(signer);
```

Downstream verifiers reconstruct a `PermitToken` and call `PqTokenSigner::verify(token, signature)`. Hybrid verifiers reject PQ-only envelopes (signature-downgrade guard); PQ-only verifiers reject hybrid envelopes. See [../concepts/post-quantum.md](../concepts/post-quantum.md).

---

## Auditing

`AuditSink` is the trait. `AuditLog` is the in-memory default. `SignedAuditChain` (in `kavach-pq`) produces ML-DSA-signed JSONL that survives off-node storage.

```rust
use kavach_core::{AuditLog, AuditSink};
use std::sync::Arc;

let audit = Arc::new(AuditLog::new(1_000));
let gate  = Gate::new(evaluators, GateConfig::default())
    .with_audit(audit.clone() as Arc<dyn AuditSink>);
```

For tamper-evident audit backed by PQ signatures, see [../concepts/audit.md](../concepts/audit.md).

---

## Observe-only rollout

Flip `GateConfig::observe_only = true` to log verdicts without blocking. Useful for Phase 1 rollout (see [../operations/deployment-patterns.md](../operations/deployment-patterns.md)).

```rust
let gate = Gate::new(evaluators, GateConfig { observe_only: true, ..Default::default() });
```

`Gate::evaluate_observe_only` always returns Permit but still runs every evaluator and logs the would-have-been-blocked verdict.

---

## Hot-reloading policies

```rust
// Swap policies at runtime. The old set stays live until the new one parses.
policy_engine.reload(PolicySet::from_toml(new_toml)?);
```

Enable the `watcher` feature on `kavach-core` and use `spawn_policy_watcher` for file-based live reload. Parse errors never wipe the running set.

```rust
#[cfg(feature = "watcher")]
{
    use kavach_core::spawn_policy_watcher;
    use std::time::Duration;

    let handle = spawn_policy_watcher(
        policy_engine.clone(),
        "kavach.toml",
        Duration::from_millis(250),
    );
    // Drop-in to keep the watcher alive; call handle.abort() to stop.
}
```

---

## Complete working example

A standalone binary that builds the evaluator chain, evaluates a permit path and a refuse path, and prints the audit tail. Uses only `kavach-core` plus the async runtime.

```rust
// examples/rust_guide.rs
use chrono::Utc;
use kavach_core::{
    ActionContext, ActionDescriptor, AuditLog, AuditSink, DriftEvaluator,
    EnvContext, Evaluator, Gate, GateConfig, Invariant, InvariantSet,
    PolicyEngine, PolicySet, Principal, PrincipalKind, SessionState, Verdict,
};
use std::sync::Arc;

const POLICY_TOML: &str = r#"
[[policy]]
name = "support_create_refund"
effect = "permit"
priority = 10
conditions = [
    { identity_role = "support" },
    { action = "refunds.create" },
    { param_max = { field = "amount", max = 50000.0 } },
    { rate_limit = { max = 50, window = "1h" } },
]

[[policy]]
name = "admin_delete_business_hours"
effect = "permit"
priority = 20
conditions = [
    { identity_role = "admin" },
    { action = "orders.delete" },
    { time_window = "09:00-18:00" },
]
"#;

fn build_gate() -> (Gate, Arc<AuditLog>) {
    let policy_engine = Arc::new(PolicyEngine::new(
        PolicySet::from_toml(POLICY_TOML).expect("valid policy"),
    ));
    let drift = Arc::new(DriftEvaluator::with_defaults());
    let invariants = Arc::new(InvariantSet::new(vec![
        Invariant::param_max("max_refund_amount", "amount", 100_000.0),
        Invariant::blocked_actions(
            "no_drop_tables",
            vec!["tables.delete".into(), "database.delete".into()],
        ),
    ]));

    let audit = Arc::new(AuditLog::new(1_000));
    let evaluators: Vec<Arc<dyn Evaluator>> = vec![policy_engine, drift, invariants];

    let gate = Gate::new(evaluators, GateConfig::default())
        .with_audit(audit.clone() as Arc<dyn AuditSink>);
    (gate, audit)
}

fn ctx(principal_id: &str, role: &str, action: &str, amount: f64) -> ActionContext {
    ActionContext::new(
        Principal {
            id: principal_id.into(),
            kind: PrincipalKind::Agent,
            roles: vec![role.into()],
            credentials_issued_at: Utc::now(),
            display_name: None,
        },
        ActionDescriptor::new(action)
            .with_param("amount", serde_json::json!(amount)),
        SessionState::new(),
        EnvContext::default(),
    )
}

#[tokio::main]
async fn main() {
    let (gate, audit) = build_gate();

    // Small refund, permitted.
    match gate.evaluate(&ctx("agent_priya", "support", "refunds.create", 2_000.0)).await {
        Verdict::Permit(tok) => println!("permit token {}", tok.token_id),
        Verdict::Refuse(r) => println!("refuse: {r}"),
        Verdict::Invalidate(s) => println!("invalidate: {s}"),
    }

    // Over the invariant cap, refused even though the support policy would permit.
    if let Verdict::Refuse(r) = gate
        .evaluate(&ctx("agent_priya", "support", "refunds.create", 999_999.0))
        .await
    {
        println!("refused: {r}");
    }

    // Audit tail.
    for entry in audit.entries().iter().rev().take(5) {
        println!(
            "[{}] {} -> {} :: {}",
            entry.verdict.to_uppercase(),
            entry.principal_id,
            entry.action_name,
            entry.verdict_detail,
        );
    }
}
```

Run with `cargo run --example rust_guide`.

---

## Next

- [../concepts/gate-and-verdicts.md](../concepts/gate-and-verdicts.md): semantics of Permit / Refuse / Invalidate.
- [../concepts/evaluators.md](../concepts/evaluators.md): the evaluator chain in depth.
- [toml-policies.md](toml-policies.md): operator-edited TOML workflow.
- [distributed.md](distributed.md): multi-node invalidation broadcast, Redis-backed stores.
- [../reference/api-surface.md](../reference/api-surface.md): full type listing.
