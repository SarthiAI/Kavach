# Policies

Kavach policies are a small, fixed condition vocabulary. The policy engine evaluates them in priority order and the first matching policy determines the verdict. If no policy matches, the gate refuses with code `NO_POLICY_MATCH` (default-deny).

Policies can be authored in three interchangeable formats (TOML, native dict / object, JSON). Pick whichever fits your workflow; you can switch between them without changing how the gate behaves. The condition vocabulary, defaults, and fail-closed semantics are identical across formats.

This document covers the model and the common cases. For the complete condition-by-condition grammar, see [reference/policy-language.md](../reference/policy-language.md). For the TOML-specific workflow with Rust / Python / Node examples side by side, see [guides/toml-policies.md](../guides/toml-policies.md).

## Structure

A policy is a named rule with an `effect`, a `priority`, and an AND-combined list of `conditions`.

**As a Python dict** (the idiomatic Python loader):

```python
policy = {
    "policies": [
        {
            "name": "agent_small_refunds",
            "description": "AI agents can issue refunds up to 5,000",
            "effect": "permit",
            "priority": 10,
            "conditions": [
                {"identity_kind": "agent"},
                {"action": "issue_refund"},
                {"param_max": {"field": "amount", "max": 5000.0}},
                {"rate_limit": {"max": 50, "window": "24h"}},
                {"session_age_max": "4h"},
            ],
        },
    ],
}
```

**As a JS object** (the idiomatic Node loader):

```typescript
const policy = {
  policies: [
    {
      name: 'agent_small_refunds',
      description: 'AI agents can issue refunds up to 5,000',
      effect: 'permit',
      priority: 10,
      conditions: [
        { identity_kind: 'agent' },
        { action: 'issue_refund' },
        { param_max: { field: 'amount', max: 5000.0 } },
        { rate_limit: { max: 50, window: '24h' } },
        { session_age_max: '4h' },
      ],
    },
  ],
};
```

**As TOML** (the operator workflow):

```toml
[[policy]]
name = "agent_small_refunds"
description = "AI agents can issue refunds up to 5,000"
effect = "permit"
priority = 10
conditions = [
    { identity_kind = "agent" },
    { action = "issue_refund" },
    { param_max = { field = "amount", max = 5000.0 } },
    { rate_limit = { max = 50, window = "24h" } },
    { session_age_max = "4h" },
]
```

Per-policy fields:

- `name` (required), human-readable identifier. Appears in refuse reasons.
- `effect` (required), `"permit"` or `"refuse"`.
- `conditions` (required), an array of condition objects. **All** conditions must match for the policy to apply.
- `priority` (optional, default `100`), lower numbers run first.
- `description` (optional), free-form.

An empty policy set is valid; it refuses every action (kill-switch shape).

## Loading policies

Each SDK exposes loaders for every format so you can pick based on workflow.

```rust
// Rust (kavach-core): TOML only at the core level.
let policies = PolicySet::from_file("kavach.toml")?;
let policies = PolicySet::from_toml(toml_string)?;
```

```python
# Python: dict is the recommended programmatic surface.
from kavach import Gate

gate = Gate.from_dict(policy_dict)              # native Python dict (recommended)
gate = Gate.from_json_string(json_string)       # JSON over the wire
gate = Gate.from_json_file("kavach.json")       # JSON file
gate = Gate.from_toml(toml_string)              # operator-edited TOML
gate = Gate.from_file("kavach.toml")            # TOML file
```

```typescript
// Node: object is the recommended programmatic surface.
import { Gate } from 'kavach';

const gate = Gate.fromObject(policyObject);     // native JS object (recommended)
const gate = Gate.fromJsonString(jsonString);
const gate = Gate.fromJsonFile('kavach.json');
const gate = Gate.fromToml(tomlString);
const gate = Gate.fromFile('kavach.toml');
```

Typo'd field names raise a clear error in every loader (`unknown field 'idnetity_kind', expected one of ...`) so a misspelled condition can never silently weaken a policy.

## Effect

```toml
effect = "permit"  # this policy permits an action that matches every condition
effect = "refuse"  # this policy blocks an action that matches every condition
```

A `refuse` policy with higher priority than a matching `permit` policy wins, because priority is "run first" and the first match decides. Use `refuse` + low priority number to encode explicit blocks like "nobody deletes production outside business hours":

```toml
[[policy]]
name = "block_delete_production"
effect = "refuse"
priority = 1
conditions = [
    { action = "delete.*" },
    { resource = "production/*" },
    { time_window = "18:00-09:00" },
]
```

## Priority

```toml
priority = 10   # runs before the default (100)
priority = 200  # runs after the default
```

Lower is earlier. Ties are broken by the order in the file. Use priorities to layer specific `refuse` rules over broader `permit` rules. A common convention:

- `1`-`9`, explicit denies ("nobody can do X").
- `10`-`29`, narrow permits by identity kind ("agents can do Y").
- `30`-`99`, role-based permits ("support_agent can do Z").
- `100`-`199`, broader catch-all permits.

## Conditions

Every condition is an object in the `conditions` array. All of a policy's conditions must be true for the policy to match (conjunctive; there is no `or` at the condition level, use two policies).

Reference table, shortest description per condition:

| Condition | Example | What it checks |
|---|---|---|
| `identity_kind` | `{ identity_kind = "agent" }` | Principal kind: `user`, `agent`, `service`, `scheduler`, `external`. |
| `identity_role` | `{ identity_role = "support_agent" }` | Principal has this role in `principal.roles`. |
| `identity_id` | `{ identity_id = "payment-service" }` | Principal id equals this string. |
| `action` | `{ action = "issue_refund" }` or `{ action = "refund.*" }` | Action name exact or trailing-wildcard match. |
| `param_max` | `{ param_max = { field = "amount", max = 5000.0 } }` | Numeric param is `<= max`. Missing or non-numeric param fails closed (condition is false). |
| `param_min` | `{ param_min = { field = "amount", min = 100.0 } }` | Numeric param is `>= min`. Missing or non-numeric param fails closed. |
| `param_in` | `{ param_in = { field = "region", values = ["us", "eu"] } }` | String param is one of `values`. Missing param fails. |
| `rate_limit` | `{ rate_limit = { max = 50, window = "24h" } }` | This `principal + action` has been called at most `max` times in the window. Fail-closed on store errors. |
| `session_age_max` | `{ session_age_max = "4h" }` | Session younger than this duration. |
| `resource` | `{ resource = "production/*" }` | Action's resource matches (trailing-wildcard). Missing resource fails. |
| `time_window` | `{ time_window = "09:00-18:00" }` or `"22:00-06:00 Asia/Kolkata"` | Evaluation time is inside the window. Overnight windows wrap. Optional IANA timezone. Malformed windows fail closed. |

Durations in `rate_limit.window` and `session_age_max` use the suffixes `s`, `m`, `h`, `d`: `30s`, `5m`, `1h`, `24h`, `1d`.

Complete grammar, edge cases, and every field: [reference/policy-language.md](../reference/policy-language.md).

## Worked examples

### Agents get a small blast radius; humans get more

```toml
[[policy]]
name = "agent_small_refunds"
effect = "permit"
priority = 10
conditions = [
    { identity_kind = "agent" },
    { action = "issue_refund" },
    { param_max = { field = "amount", max = 5000.0 } },
    { rate_limit = { max = 50, window = "24h" } },
]

[[policy]]
name = "support_refunds"
effect = "permit"
priority = 20
conditions = [
    { identity_role = "support_agent" },
    { action = "issue_refund" },
    { param_max = { field = "amount", max = 50000.0 } },
]
```

### Explicit refuse for large agent refunds

The `agent_small_refunds` permit above stops matching at `amount > 5000` (so an agent trying a 10,000 refund falls through to default-deny). If you want a clearer refuse-with-reason for that case, add a lower-priority `refuse` policy:

```toml
[[policy]]
name = "agent_block_large_refunds"
effect = "refuse"
priority = 5
conditions = [
    { identity_kind = "agent" },
    { action = "issue_refund" },
    { param_min = { field = "amount", min = 5000.01 } },
]
```

Now the refusal says "denied by policy 'agent_block_large_refunds'" with code `POLICY_DENIED`, instead of the less specific `NO_POLICY_MATCH`.

### Admin override

```toml
[[policy]]
name = "admin_all_actions"
effect = "permit"
priority = 100
conditions = [
    { identity_role = "admin" },
]
```

### Time-windowed refuse

```toml
[[policy]]
name = "no_deploys_overnight"
effect = "refuse"
priority = 1
conditions = [
    { action = "deploy.*" },
    { time_window = "22:00-06:00 America/Los_Angeles" },
]
```

## Interaction with invariants

Policies say "is this allowed?" Invariants say "is this inside the system's hard limits?" Both must pass. A policy that permits an 80,000 refund is still blocked by a `param_max` invariant of 50,000. Use invariants for limits that *no* policy, role, or admin can override. See [evaluators.md](evaluators.md#invariantset-priority-150).

## Hot reload

```rust
// Rust
policy_engine.reload(new_policy_set);
```

```python
# Python: reload accepts a TOML string.
gate.reload(new_policy_toml)
```

```typescript
// Node: reload accepts a TOML string.
gate.reload(newPolicyToml);
```

Reload takes `&self`, so it works through an `Arc<PolicyEngine>` shared with the gate. In-flight evaluations keep using the old set until they finish; subsequent calls pick up the new set. Parse errors raise (Python) or throw (Node) or return `Err` (Rust); the previous good set is preserved.

Pair `reload` with the `watcher` feature on `kavach-core` to auto-reload from disk on change; see [guides/rust.md](../guides/rust.md), [guides/toml-policies.md](../guides/toml-policies.md), and [operations/deployment-patterns.md](../operations/deployment-patterns.md).

## Cross-references

- Full grammar: [reference/policy-language.md](../reference/policy-language.md).
- Hard limits that cannot be overridden: [evaluators.md](evaluators.md).
- What a `Refuse` looks like downstream: [gate-and-verdicts.md](gate-and-verdicts.md).
