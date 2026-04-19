# TOML policies

TOML is Kavach's file format for policies that operators hand-edit, check into
git, and ship alongside the service binary. It is the format the Rust core
accepts natively, and the format both SDKs accept through `Gate.from_toml` /
`Gate.fromToml` and `Gate.from_file` / `Gate.fromFile`.

If you are authoring policies programmatically from Python or Node (admin UI
submissions, database rows, feature flags), use the dict / object loader
instead, see [python.md](python.md) and [typescript.md](typescript.md). TOML
is the operator workflow; dict / object is the programmatic workflow. The
policy vocabulary is identical; only the surface differs.

For the complete grammar (every condition, every field, every error mode) see
[../reference/policy-language.md](../reference/policy-language.md).

---

## One canonical policy, three languages

The same file, loaded from all three SDKs. Every code block below is exercised
by the `business-tests/tier6_docs/` harness, so what you see works verbatim.

```toml
# kavach.toml
[[policy]]
name = "support_small_refunds"
effect = "permit"
priority = 10
conditions = [
    { identity_role = "support" },
    { action = "issue_refund" },
    { param_max = { field = "amount", max = 5000.0 } },
    { rate_limit = { max = 50, window = "24h" } },
]

[[policy]]
name = "allow_fetch_report"
effect = "permit"
priority = 20
conditions = [
    { action = "fetch_report" },
]
```

### Rust

```rust
use kavach_core::{
    ActionContext, ActionDescriptor, EnvContext, Evaluator, Gate, GateConfig,
    PolicyEngine, PolicySet, Principal, PrincipalKind, SessionState, Verdict,
};
use chrono::Utc;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let policies = PolicySet::from_file("kavach.toml").expect("valid TOML");
    let policy_engine = Arc::new(PolicyEngine::new(policies));
    let gate = Gate::new(
        vec![policy_engine as Arc<dyn Evaluator>],
        GateConfig::default(),
    );

    let ctx = ActionContext::new(
        Principal {
            id: "agent-priya".into(),
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
        Verdict::Permit(tok) => println!("permit {}", tok.token_id),
        Verdict::Refuse(r) => println!("refused: {r}"),
        Verdict::Invalidate(s) => println!("invalidated: {s}"),
    }
}
```

### Python

```python
from kavach import ActionContext, Gate

gate = Gate.from_file(
    "kavach.toml",
    invariants=[("hard_cap", "amount", 50_000.0)],
)

ctx = ActionContext(
    principal_id="agent-priya",
    principal_kind="agent",
    action_name="issue_refund",
    roles=["support"],
    params={"amount": 1_500.0},
)

verdict = gate.evaluate(ctx)
if verdict.is_permit:
    print("permit", verdict.token_id)
else:
    print(f"blocked: [{verdict.code}] {verdict.evaluator}: {verdict.reason}")
```

`Gate.from_file` is the filesystem variant of `Gate.from_toml`. If you already
have the TOML text in memory, pass it directly:

```python
toml_text = open("kavach.toml").read()
gate = Gate.from_toml(toml_text)
```

### TypeScript / Node

```typescript
import { Gate } from 'kavach';

const gate = Gate.fromFile('kavach.toml', {
  invariants: [{ name: 'hard_cap', field: 'amount', maxValue: 50_000 }],
});

const verdict = gate.evaluate({
  principalId: 'agent-priya',
  principalKind: 'agent',
  actionName: 'issue_refund',
  roles: ['support'],
  params: { amount: 1_500 },
});

if (verdict.isPermit) {
  console.log('permit', verdict.tokenId);
} else {
  console.log(`blocked: [${verdict.code}] ${verdict.evaluator}: ${verdict.reason}`);
}
```

`Gate.fromFile` is the filesystem variant of `Gate.fromToml`. If you already
have the TOML text in memory, pass it directly:

```typescript
import { readFileSync } from 'fs';
const tomlText = readFileSync('kavach.toml', 'utf-8');
const gate = Gate.fromToml(tomlText);
```

---

## File shape

Every `[[policy]]` table is one rule. Policies are evaluated in priority
order; first match wins. See
[../reference/policy-language.md](../reference/policy-language.md) for the
full field reference.

```toml
[[policy]]
name = "rule_name"            # required, appears in refuse reasons
effect = "permit"             # required, "permit" or "refuse"
priority = 10                 # optional, default 100, lower = earlier
description = "free text"     # optional, not used at evaluation time
conditions = [                # required, all conditions AND together
    { identity_kind = "agent" },
    { action = "issue_refund" },
    { param_max = { field = "amount", max = 5000.0 } },
]
```

An empty file is valid and default-denies every action, which is useful as a
kill-switch via hot reload.

---

## Hot reload

All three SDKs swap the policy set live without dropping in-flight
evaluations. Parse errors leave the previous good set in place.

### Rust

```rust
use kavach_core::PolicySet;

let new_policies = PolicySet::from_file("kavach.toml")?;
policy_engine.reload(new_policies);
```

With the `watcher` feature enabled on `kavach-core`:

```rust
use kavach_core::spawn_policy_watcher;
use std::time::Duration;

let handle = spawn_policy_watcher(
    policy_engine.clone(),
    "kavach.toml",
    Duration::from_millis(250),
);
```

The watcher debounces editor bursts and never wipes the running policy set on
parse error.

### Python

```python
gate.reload(open("kavach.toml").read())   # raises ValueError on parse error
```

### Node

```typescript
import { readFileSync } from 'fs';
gate.reload(readFileSync('kavach.toml', 'utf-8'));  // throws on parse error
```

---

## Kill switch

An empty TOML string is the recommended kill switch. Every action past the
reload default-denies.

### Python

```python
gate.reload("")                      # or "# emergency kill switch"
```

### Node

```typescript
gate.reload('');
```

### Rust

```rust
policy_engine.reload(PolicySet::default());  // equivalent to from_toml("")
```

The HTTP integration tests for Kavach pin the worst case at under 200 ms
between reload completion and the first refuse on the kill-switched node; in
practice the next evaluation that picks up the new snapshot is refused.

---

## Choosing between TOML and dict / object

| Situation | Use |
|---|---|
| Operator hand-edits policies in git, single source of truth | TOML |
| Policy ships as a config file baked into a container image | TOML |
| File watcher auto-reloads on change (Rust `watcher` feature) | TOML |
| Admin UI form submits a policy from a browser | dict (Python) / object (Node) |
| Policies live in a database row or feature flag service | dict / object |
| Tooling that already emits JSON (Kubernetes, REST APIs) | JSON (see [reference](../reference/policy-language.md#json-file)) |

The semantics are identical across all loaders. A misspelled field name
(`{ idnetity_kind = "agent" }`) raises a clear error in every format; there
is no format where a typo silently weakens a policy.

---

## See also

- [../reference/policy-language.md](../reference/policy-language.md): the
  complete grammar reference (every condition, every field, fail-closed
  semantics, duration format, time-window format).
- [../concepts/policies.md](../concepts/policies.md): the conceptual model
  (effect, priority, conditions, default deny).
- [python.md](python.md): Python SDK, dict-first examples.
- [typescript.md](typescript.md): Node SDK, object-first examples.
- [rust.md](rust.md): Rust integration guide.
