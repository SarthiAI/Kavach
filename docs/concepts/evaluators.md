# Evaluators

An evaluator is one step in the gate's pipeline. It inspects an `ActionContext` and returns a `Verdict`. The gate runs evaluators in priority order and short-circuits on the first `Refuse` or `Invalidate`. See [gate-and-verdicts.md](gate-and-verdicts.md) for the pipeline semantics.

## The `Evaluator` trait

```rust
// kavach-core/src/evaluator.rs
#[async_trait]
pub trait Evaluator: Send + Sync {
    /// Short, unique name. Appears in audit logs and RefuseReason.evaluator.
    fn name(&self) -> &str;

    /// Evaluate the context and return a verdict.
    async fn evaluate(&self, ctx: &ActionContext) -> Verdict;

    /// Priority order (lower runs first). Default is 100.
    ///
    /// Suggested ranges:
    /// - 0-49: identity resolution and session validation
    /// - 50-99: policy evaluation
    /// - 100-149: drift detection
    /// - 150-199: invariant enforcement
    /// - 200+: custom evaluators
    fn priority(&self) -> u32 { 100 }
}
```

Three rules for any evaluator:

1. **`Send + Sync`.** The gate holds evaluators as `Arc<dyn Evaluator>` and may call them concurrently.
2. **`evaluate` is `async`.** The policy and drift evaluators talk to pluggable stores that may be network-backed (Redis rate-limit store, remote session store). Keep `evaluate` cheap and do not block inside it; use `.await` for I/O.
3. **Unique `name()`.** It shows up in `RefuseReason.evaluator`, audit entries, and traces. Make it greppable.

## Built-in evaluators

### `PolicyEngine` (priority 50)

Evaluates TOML policies against the context. First matching policy wins; its `effect` (`permit` or `refuse`) becomes the verdict. If no policy matches, the verdict is `Refuse` with code `NO_POLICY_MATCH` (default-deny).

```rust
use kavach_core::{PolicyEngine, PolicySet};

let policies = PolicySet::from_file("kavach.toml")?;
let policy_engine = Arc::new(PolicyEngine::new(policies));
```

`PolicyEngine` records the current call in its `RateLimitStore` before evaluating conditions, so a `rate_limit` condition sees itself. Record failure fails the entire evaluation closed (returns `Refuse` with `POLICY_DENIED`). Details in [policies.md](policies.md).

For a distributed rate-limit backend, inject a store:

```rust
let policy_engine = Arc::new(
    PolicyEngine::with_rate_store(policies, Arc::new(my_redis_store)),
);
```

Hot reload:

```rust
policy_engine.reload(new_policy_set);  // takes &self, shareable through Arc
```

### `DriftEvaluator` (priority 100)

Wraps a vector of `DriftDetector`s. Runs every detector. `Violation` → `Invalidate`. Three or more simultaneous `Warning`s → `Refuse` with code `DRIFT_DETECTED`. Otherwise `Permit`.

Built-in detectors:

- `GeoLocationDrift`, flags IP changes mid-session. Default strict: any change is a violation. Tolerant mode via `GeoLocationDrift::with_max_distance_km(km)` downgrades changes within `km` to warnings (requires both `origin_geo` and current `geo` with lat/lon; missing geo still fails closed).
- `SessionAgeDrift`, flags sessions older than `max_age_seconds` (default 4 hours). Warns at 75% of the limit.
- `DeviceDrift`, flags a change in device fingerprint between `session.origin_device` and `environment.device`.
- `BehaviorDrift`, flags action rates above `warn_threshold` / `violation_threshold` actions per minute.

```rust
use kavach_core::{BehaviorDrift, DeviceDrift, DriftEvaluator, GeoLocationDrift, SessionAgeDrift};

let drift = Arc::new(DriftEvaluator::with_defaults());

// or pick your own:
let drift = Arc::new(DriftEvaluator::new(vec![
    Box::new(GeoLocationDrift::with_max_distance_km(500.0)),
    Box::new(SessionAgeDrift { max_age_seconds: 8 * 3600 }),
    Box::new(DeviceDrift),
    Box::new(BehaviorDrift::default()),
]));
```

### `InvariantSet` (priority 150)

A flat list of hard structural constraints. Any violation → `Refuse` with code `INVARIANT_VIOLATION`. Invariants cannot be overridden by a permit policy. If policy says yes and an invariant says no, the answer is no.

```rust
use kavach_core::{Invariant, InvariantSet};

let invariants = Arc::new(InvariantSet::new(vec![
    Invariant::param_max("max_refund", "amount", 50_000.0),
    Invariant::max_actions_per_session("session_limit", 500),
    Invariant::max_session_age("session_age", 4 * 3600),
    Invariant::blocked_actions("no_deletes", vec!["delete_user".to_string()]),
]));
```

Supported kinds: `param_max`, `param_min`, `max_actions_per_session`, `max_session_age`, `allowed_actions`, `blocked_actions`, and `Invariant::custom(name, description, |ctx| -> bool)` for arbitrary checks.

## Composing the gate

You hand the gate a `Vec<Arc<dyn Evaluator>>`. The gate sorts by priority. The canonical wiring is the three built-ins:

```rust
// from Kavach/README.md
use kavach_core::*;
use std::sync::Arc;

let policies      = PolicySet::from_file("kavach.toml")?;
let policy_engine = Arc::new(PolicyEngine::new(policies));
let drift         = Arc::new(DriftEvaluator::with_defaults());
let invariants    = Arc::new(InvariantSet::new(vec![
    Invariant::param_max("max_refund", "amount", 50_000.0),
    Invariant::max_actions_per_session("session_limit", 500),
]));

let gate = Gate::new(
    vec![policy_engine, drift, invariants],
    GateConfig::default(),
);
```

You can drop any of them (e.g. don't pass `drift` in test setups) and you can add more.

## Writing a custom evaluator

Any `Send + Sync` struct that implements `Evaluator` plugs into the gate:

```rust
use async_trait::async_trait;
use kavach_core::{ActionContext, Evaluator, PermitToken, RefuseCode, RefuseReason, Verdict};
use chrono::Timelike;

/// Only permit actions between 09:00 and 18:00 UTC.
pub struct BusinessHoursOnly;

#[async_trait]
impl Evaluator for BusinessHoursOnly {
    fn name(&self) -> &str { "business_hours" }

    // Runs after invariants (150) unless you override priority().
    fn priority(&self) -> u32 { 200 }

    async fn evaluate(&self, ctx: &ActionContext) -> Verdict {
        let hour = ctx.evaluated_at.hour();
        if (9..18).contains(&hour) {
            Verdict::Permit(PermitToken::new(ctx.evaluation_id, ctx.action.name.clone()))
        } else {
            Verdict::Refuse(RefuseReason {
                evaluator: self.name().to_string(),
                reason: format!("outside business hours ({hour}:00 UTC)"),
                code: RefuseCode::PolicyDenied,
                evaluation_id: ctx.evaluation_id,
            })
        }
    }
}

let gate = Gate::new(
    vec![
        Arc::new(PolicyEngine::new(policies)),
        Arc::new(BusinessHoursOnly),
    ],
    GateConfig::default(),
);
```

Guidance:

- **Return `Permit` when you have no objection.** An evaluator that does not apply to a given context (e.g. a geography check when no IP is known) should return `Permit`, not `Refuse`. Default-deny lives in `PolicyEngine::NoPolicyMatch`, not in every evaluator.
- **Use `Invalidate` sparingly.** `Invalidate` revokes authority beyond the current action. It belongs in drift-like detectors that have evidence the session itself is compromised.
- **Pick a `RefuseCode` from the existing enum** (see [gate-and-verdicts.md](gate-and-verdicts.md)) so downstream tooling can group refusals by reason. `PolicyDenied` is a reasonable default for custom business-logic blocks.
- **Keep it cheap.** Every action in your system runs through the full pipeline. Cache remote lookups, pre-compute what you can in the constructor, and never block the async runtime.
- **Fail closed on internal errors.** If your evaluator cannot reach a required service, return `Refuse`, not `Permit`. This is the whole point of Kavach.

## Cross-references

- Verdict variants and `PermitToken` shape: [gate-and-verdicts.md](gate-and-verdicts.md).
- The built-in policy language: [policies.md](policies.md), full grammar at [reference/policy-language.md](../reference/policy-language.md).
- Using Kavach from Python / Node (where evaluator composition is pre-baked into every `Gate.from_*` factory): [guides/python.md](../guides/python.md), [guides/typescript.md](../guides/typescript.md).
