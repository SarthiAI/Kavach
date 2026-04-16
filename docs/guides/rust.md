# Rust integration guide

Kavach is a Rust-native library. `kavach-core` holds the gate, evaluators, policy engine, drift detectors, and invariants. `kavach-pq` layers post-quantum crypto (signed tokens, audit chains, secure channels). `kavach-http` and `kavach-mcp` add framework adapters.

This guide covers the core integration surface. For framework glue, see [http.md](http.md) and [mcp.md](mcp.md).

---

## Install

Kavach is published as a Cargo workspace. Pick the crates you need.

```toml
# Cargo.toml

[dependencies]
kavach-core = "0.1"               # gate, evaluators, policies
kavach-pq   = "0.1"               # signed tokens, audit chains, secure channel
kavach-http = "0.1"               # HTTP middleware
kavach-mcp  = "0.1"               # MCP tool gating

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
- `kavach-http/tower` enables `KavachLayer` for Axum / Tower stacks.
- `kavach-http/actix` enables the Actix-web transform.

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

Simulated REST API with Kavach gating mutations. This is a condensed form of `kavach-http/examples/http_api.rs` focused on the core crate plus `kavach-http`.

```rust
// examples/rust_guide.rs
use kavach_core::{
    AuditLog, AuditSink, DriftEvaluator, Evaluator, Gate, GateConfig,
    Invariant, InvariantSet, PolicyEngine, PolicySet, SessionState, Verdict,
};
use kavach_http::{HttpGate, HttpMiddlewareConfig, HttpRequest};
use std::collections::HashMap;
use std::sync::Arc;

fn build_gate(observe_only: bool) -> (HttpGate, Arc<AuditLog>) {
    let policy_toml = r#"
        [[policy]]
        name = "user_read_anything"
        effect = "permit"
        priority = 10
        conditions = [
            { identity_kind = "user" },
            { action = "orders.read" },
        ]

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

    let policy_engine = Arc::new(PolicyEngine::new(
        PolicySet::from_toml(policy_toml).expect("valid policy"),
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

    let gate = Gate::new(
        evaluators,
        GateConfig { observe_only, ..Default::default() },
    )
    .with_audit(audit.clone() as Arc<dyn AuditSink>);

    let http = HttpGate::new(
        Arc::new(gate),
        HttpMiddlewareConfig {
            gate_mutations_only: true,
            excluded_paths: vec!["/health".into(), "/metrics".into()],
            ..Default::default()
        },
    );
    (http, audit)
}

fn request(method: &str, path: &str, principal: &str, roles: &str, body: Option<serde_json::Value>) -> HttpRequest {
    let mut headers = HashMap::new();
    headers.insert("X-Principal-Id".into(), principal.into());
    headers.insert("X-Roles".into(), roles.into());
    HttpRequest {
        method: method.into(),
        path: path.into(),
        path_params: HashMap::new(),
        query_params: HashMap::new(),
        body,
        headers,
        remote_ip: Some("10.0.1.50".parse().unwrap()),
    }
}

#[tokio::main]
async fn main() {
    let (http_gate, audit) = build_gate(false);
    let session = SessionState::new();

    // Small refund, permitted.
    let req = request(
        "POST", "/api/v1/refunds", "agent_priya", "support",
        Some(serde_json::json!({ "amount": 2_000.0, "order_id": "ORD-5678" })),
    );
    if http_gate.should_gate(&req) {
        match http_gate.evaluate(&req, &session).await {
            Verdict::Permit(tok)     => println!("permit token {}", tok.token_id),
            Verdict::Refuse(r)       => println!("refuse: {r}"),
            Verdict::Invalidate(s)   => println!("invalidate: {s}"),
        }
    }

    // Over-limit, refused by the invariant even though the support policy would permit.
    let req = request(
        "POST", "/api/v1/refunds", "agent_priya", "support",
        Some(serde_json::json!({ "amount": 999_999.0 })),
    );
    if http_gate.should_gate(&req) {
        if let Verdict::Refuse(r) = http_gate.evaluate(&req, &session).await {
            println!("refused: {r}");
        }
    }

    // Audit tail.
    for entry in audit.entries().iter().rev().take(5) {
        println!(
            "[{}] {} -> {} :: {}",
            entry.verdict.to_uppercase(), entry.principal_id,
            entry.action_name, entry.verdict_detail,
        );
    }
}
```

Run with `cargo run --example rust_guide`. The canonical working examples live under `Kavach/kavach-http/examples/` (`http_api.rs`, `axum_layer.rs`, `actix_middleware.rs`).

---

## Next

- [concepts/gate-and-verdicts.md](../concepts/gate-and-verdicts.md), semantics of Permit / Refuse / Invalidate.
- [concepts/evaluators.md](../concepts/evaluators.md), the evaluator chain in depth.
- [guides/http.md](http.md), Axum / Tower / Actix integration.
- [guides/mcp.md](mcp.md), gating MCP tool calls.
- [guides/distributed.md](distributed.md), multi-node invalidation broadcast, Redis-backed stores.
- [reference/api-surface.md](../reference/api-surface.md), full type listing.
