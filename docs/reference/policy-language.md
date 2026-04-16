# Policy Language Reference

This is the exhaustive grammar reference for the TOML policy language consumed by [`PolicySet::from_toml`](../../kavach-core/src/policy.rs) and exposed through every SDK (Rust, Python, TypeScript). For conceptual background see [concepts/policies.md](../concepts/policies.md) and [concepts/gate-and-verdicts.md](../concepts/gate-and-verdicts.md).

Everything in this document is pinned to the real parser. If syntax here does not appear in [kavach-core/src/policy.rs](../../kavach-core/src/policy.rs), it does not exist.

---

## File shape

A policy file is a TOML document containing zero or more `[[policy]]` array-of-tables entries:

```toml
[[policy]]
name = "..."
effect = "permit"
conditions = [ ... ]

[[policy]]
name = "..."
effect = "refuse"
conditions = [ ... ]
```

An empty file parses to an empty `PolicySet`. This is valid and means default-deny everything (useful as a kill-switch via hot-reload).

---

## `[[policy]]` fields

| Field         | Type             | Required | Default | Description                                                                                                     |
| ------------- | ---------------- | -------- | ------- | --------------------------------------------------------------------------------------------------------------- |
| `name`        | string           | yes      | ,       | Human-readable identifier. Appears in refusal reasons (`denied by policy '<name>'`) and in tracing logs.        |
| `effect`      | enum             | yes      | ,       | One of `"permit"` or `"refuse"`. Serialized in snake_case; any other value is a parse error.                    |
| `conditions`  | array of tables  | yes      | `[]`    | AND-combined list of conditions. An empty list matches every context, so an unconditional permit uses `[]`.     |
| `description` | string           | no       | unset   | Free-form documentation. Not used during evaluation.                                                            |
| `priority`    | unsigned integer | no       | `100`   | Lower number = higher priority = evaluated first. Ties are broken by declaration order (stable sort by `u32`).  |

### `effect` values

| TOML value   | Rust `Effect` | Meaning                                                              |
| ------------ | ------------- | -------------------------------------------------------------------- |
| `"permit"`   | `Effect::Permit` | First matching policy allows the action.                          |
| `"refuse"`   | `Effect::Refuse` | First matching policy blocks the action with `RefuseCode::PolicyDenied`. |

---

## Condition grammar

Conditions are specified as TOML inline tables inside the `conditions` array. Each table has exactly one key, which is the snake_case name of a [`Condition`](../../kavach-core/src/policy.rs) variant. Multi-field variants use a nested inline table for the value.

The canonical mapping (from the `#[serde(rename_all = "snake_case")]` attribute on the `Condition` enum):

| TOML key         | Rust variant                                 | Arity              |
| ---------------- | -------------------------------------------- | ------------------ |
| `identity_kind`  | `Condition::IdentityKind(PrincipalKind)`     | scalar             |
| `identity_role`  | `Condition::IdentityRole(String)`            | scalar             |
| `identity_id`    | `Condition::IdentityId(String)`              | scalar             |
| `action`         | `Condition::Action(String)`                  | scalar (pattern)   |
| `resource`       | `Condition::Resource(String)`                | scalar (pattern)   |
| `param_max`      | `Condition::ParamMax { field, max }`         | inline table       |
| `param_min`      | `Condition::ParamMin { field, min }`         | inline table       |
| `param_in`       | `Condition::ParamIn { field, values }`       | inline table       |
| `rate_limit`     | `Condition::RateLimit { max, window }`       | inline table       |
| `session_age_max`| `Condition::SessionAgeMax(String)`           | scalar (duration)  |
| `time_window`    | `Condition::TimeWindow(String)`              | scalar (window)    |

Every condition in a policy must evaluate to true for the policy to match. Evaluation short-circuits on the first `false` condition.

### `identity_kind`

Principal classification. The `PrincipalKind` enum is serialized in snake_case.

| TOML value     | Rust                      | Meaning                                                 |
| -------------- | ------------------------- | ------------------------------------------------------- |
| `"user"`       | `PrincipalKind::User`     | Human user.                                             |
| `"agent"`      | `PrincipalKind::Agent`    | AI agent (LLM, autonomous system).                      |
| `"service"`    | `PrincipalKind::Service`  | Backend service or microservice.                        |
| `"scheduler"`  | `PrincipalKind::Scheduler`| Scheduled job or cron task.                             |
| `"external"`   | `PrincipalKind::External` | Webhook or external caller.                             |

Match rule: true iff `ctx.principal.kind == <value>`.

```toml
{ identity_kind = "agent" }
```

### `identity_role`

Case-sensitive role membership. Matches iff `ctx.principal.roles` contains the exact string.

```toml
{ identity_role = "support_agent" }
```

To require multiple roles, add one condition per role (AND semantics). There is no `identity_roles` variant and no OR-within-one-condition.

### `identity_id`

Exact match against the principal's `id` field.

```toml
{ identity_id = "payment-service" }
```

### `action`

Matches the action name. Supports trailing wildcards only, via `match_pattern` in [policy.rs](../../kavach-core/src/policy.rs):

| Pattern form     | Matches                                    | Example                                                  |
| ---------------- | ------------------------------------------ | -------------------------------------------------------- |
| `"foo"`          | Exact: `ctx.action.name == "foo"`          | `"issue_refund"` matches `issue_refund` and nothing else |
| `"foo.*"`        | Prefix before a dot: `starts_with("foo")`  | `"refund.*"` matches `refund.create`, `refund.cancel`    |
| `"foo*"`         | Bare trailing `*`: `starts_with("foo")`    | `"refund*"` matches `refund`, `refunds`, `refunded`      |

Other glob metacharacters (`?`, `[abc]`, leading `*`, middle `*`) are **not** supported; they match as literal characters.

```toml
{ action = "issue_refund" }
{ action = "delete.*" }
```

### `resource`

Same wildcard grammar as `action`, but matched against `ctx.action.resource`. If the action has no resource set, this condition is **false** (fails closed).

```toml
{ resource = "production/*" }
```

### `param_max` and `param_min`

Numeric guards. The `field` is a key into `ctx.action.params`; the value is coerced to `f64` via `ActionDescriptor::param_as_f64`.

| Key          | Rust type   | Match rule                                                                                |
| ------------ | ----------- | ----------------------------------------------------------------------------------------- |
| `param_max`  | `{ field: String, max: f64 }` | `params[field] <= max` when present; **true when field missing** (doesn't fail the check). |
| `param_min`  | `{ field: String, min: f64 }` | `params[field] >= min` when present; **true when field missing**.                          |

Missing-param semantics are deliberate: these are bounds checks, not existence checks. To require a parameter be present, combine with `param_in` or an invariant outside the policy layer.

```toml
{ param_max = { field = "amount", max = 50000.0 } }
{ param_min = { field = "amount", min = 5000.01 } }
```

### `param_in`

String-valued allow-list. `field` is the parameter key; `values` is a list of allowed string values. Matches iff the parameter exists **and** equals one of the values (case-sensitive).

Unlike `param_max` / `param_min`, a missing parameter evaluates to **false**.

```toml
{ param_in = { field = "currency", values = ["INR", "USD", "EUR"] } }
```

### `rate_limit`

Sliding-window request count. The gate's [`RateLimitStore`](../../kavach-core/src/rate_limit.rs) (in-memory by default, Redis via [`RedisRateLimitStore`](../../kavach-redis/src/rate_limit.rs) in distributed deployments) records every evaluation before policies are checked, so `count` is inclusive of the current call. The comparison is `count <= max`, meaning `max = N` allows exactly N calls per window.

| Key          | Type               | Meaning                                                                                      |
| ------------ | ------------------ | -------------------------------------------------------------------------------------------- |
| `max`        | unsigned integer   | Maximum number of matching actions permitted per window.                                     |
| `window`     | duration string    | Size of the sliding window. Parsed by `parse_duration_secs` (see [Duration format](#duration-format)). |

The rate-limit key is `"{principal.id}:{action.name}"`, so counters are scoped per principal per action.

**Fail-closed behavior:** if the store returns an error when counting, the condition evaluates to false (the policy does not match, default-deny kicks in). If the store's `record` call fails earlier in evaluation, the entire evaluation refuses with `RefuseCode::PolicyDenied`.

```toml
{ rate_limit = { max = 50, window = "24h" } }
```

### `session_age_max`

Maximum session age at evaluation time. The value is a duration string parsed by `parse_duration_secs`. A session older than this fails the condition; an exactly-equal age passes (`<=`).

Malformed durations silently fall back to **86 400 seconds** (24 hours). To avoid surprises, use the explicit forms documented below.

```toml
{ session_age_max = "4h" }
{ session_age_max = "30m" }
```

### `time_window`

Wall-clock gate. The value is a time-of-day window, optionally suffixed by an IANA timezone name. See [Time-window format](#time-window-format) for the full grammar and failure modes.

```toml
{ time_window = "09:00-18:00" }
{ time_window = "09:00-18:00 Asia/Kolkata" }
{ time_window = "22:00-06:00" }
```

---

## Duration format

`parse_duration_secs` in [policy.rs](../../kavach-core/src/policy.rs) accepts:

| Suffix | Unit    | Example | Seconds |
| ------ | ------- | ------- | ------- |
| `s`    | seconds | `"30s"` | 30      |
| `m`    | minutes | `"5m"`  | 300     |
| `h`    | hours   | `"24h"` | 86 400  |
| `d`    | days    | `"1d"`  | 86 400  |
| (none) | seconds | `"90"`  | 90      |

Rules:

- The numeric portion must parse as a `u64`. Negatives, decimals, and scientific notation are rejected.
- Compound durations like `"1h30m"`, `"2d12h"`, or `"90s 30m"` are **not** supported; they fail to parse and trigger the fallback.
- Leading / trailing whitespace is trimmed.
- On parse failure, `Condition::RateLimit` falls back to 3 600 seconds (1 hour) and `Condition::SessionAgeMax` falls back to 86 400 seconds (24 hours). Always use explicit, valid durations.

Minimal forms that round-trip through the tests in [policy.rs](../../kavach-core/src/policy.rs): `"30s"`, `"5m"`, `"1h"`, `"24h"`, `"1d"`.

---

## Time-window format

Handled by `evaluate_time_window` in [policy.rs](../../kavach-core/src/policy.rs).

### Grammar

```
window  := "HH:MM-HH:MM" [ WS tz ]
HH      := 00..23
MM      := 00..59
tz      := a chrono-tz IANA identifier, e.g. "Asia/Kolkata", "US/Eastern", "Europe/London"
WS      := any whitespace character
```

The window separator is a literal hyphen. Hours and minutes are parsed with `chrono::NaiveTime::parse_from_str(..., "%H:%M")`, so single-digit hours (`"9:00"`) will **not** parse; always zero-pad.

### Semantics

| Case                                      | Behavior                                                                                             |
| ----------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| No tz suffix (`"09:00-18:00"`)            | Compared against `evaluated_at` in UTC.                                                              |
| With tz suffix (`"09:00-18:00 Asia/Kolkata"`) | `evaluated_at` is converted to the named timezone before comparison.                              |
| Same-day window (`start <= end`)          | Matches iff `start <= now <= end` (both endpoints inclusive).                                        |
| Overnight window (`start > end`)          | Wraps midnight: matches iff `now >= start` OR `now <= end`.                                          |

Examples:

| Window                        | UTC time       | Matches |
| ----------------------------- | -------------- | ------- |
| `"09:00-18:00"`               | `12:00`        | yes     |
| `"09:00-18:00"`               | `09:00`        | yes (endpoint inclusive) |
| `"09:00-18:00"`               | `18:00`        | yes (endpoint inclusive) |
| `"09:00-18:00"`               | `19:00`        | no      |
| `"22:00-06:00"`               | `23:30`        | yes     |
| `"22:00-06:00"`               | `01:00`        | yes     |
| `"22:00-06:00"`               | `12:00`        | no      |
| `"09:00-18:00 Asia/Kolkata"`  | `12:00 UTC` = `17:30 IST` | yes   |
| `"09:00-18:00 US/Eastern"`    | `22:00 UTC` = `18:00 EDT` | yes (endpoint inclusive) |

### Fail-closed on malformed input

Since P1.6 the function returns `false` (policy does not match) on any of the following:

- Missing `-` separator (`"nonsense"`).
- Unparseable start or end time (`"nope-18:00"`, `"09:00-lolwut"`).
- Unknown timezone identifier (`"09:00-18:00 Not/Real"`).
- Empty string.

Earlier behavior returned `true` (fail-open) on malformed windows; that was a bug and has been fixed. All of these cases are pinned by tests in the `time_window` module of [policy.rs](../../kavach-core/src/policy.rs).

---

## Evaluation semantics

### Default deny

[`PolicyEngine::evaluate`](../../kavach-core/src/policy.rs) walks policies in priority order and returns the first match. If no policy matches, the verdict is `Refuse` with `RefuseCode::NoPolicyMatch` and the reason `no policy permits '<action>' for principal '<id>'`. There is no implicit allow: a permit requires a `[[policy]]` with `effect = "permit"` whose conditions all match.

### Priority order

Policies are sorted by `priority` ascending at load time (`PolicySet::from_toml` → `PolicyEngine::new` / `reload`). Lower numbers evaluate first. This lets you place narrow `refuse` rules (e.g., "block delete on production") ahead of broad `permit` rules (e.g., "admins can do anything"). Priority ties fall back to the declaration order the TOML file produces.

### First match wins

Once the engine finds a policy whose every condition evaluates to true, it returns that policy's effect and stops. Later policies are not consulted.

### Condition AND

All conditions inside a policy are ANDed. To express OR, split the rule into multiple `[[policy]]` entries at the same priority.

### Missing optional fields

- `description` is never read during evaluation.
- `priority` defaults to `100`.
- An empty `conditions = []` is permitted (and matches every context unconditionally).

### Hot-reload

[`PolicyEngine::reload`](../../kavach-core/src/policy.rs) takes `&self` (not `&mut self`) and accepts a fresh `PolicySet`. Under the hood:

1. The new policies are sorted by priority.
2. The engine takes a write lock on its `RwLock<Vec<Policy>>`.
3. The old vector is replaced atomically.
4. In-flight evaluations finish with whichever snapshot they cloned; subsequent evaluations pick up the new set.

For file-backed hot-reload, enable the `watcher` feature and use [`spawn_policy_watcher`](../../kavach-core/src/watcher.rs). The watcher only calls `reload` on **successful** parse. A typo in your TOML logs a warning and keeps the previous good set in place. The default debounce is 250ms, which collapses the 3 to 5 filesystem events most editors produce per save.

From the Python SDK, `Gate.reload(policy_toml)` exposes the same semantics; from the TypeScript SDK, `Gate.reload(policyToml)`. Both throw on parse errors without disturbing the current policy set.

---

## Kitchen-sink example

A single file exercising every condition variant. Derived from [examples/kavach.toml](../../examples/kavach.toml) and extended for completeness.

```toml
# ───────────────────────────────────────────────────────────────
# Priority 1: narrowest refusal. Nobody deletes production data
# outside business hours (IST), no matter who they are.
# ───────────────────────────────────────────────────────────────
[[policy]]
name = "block_delete_production_after_hours"
description = "Hard gate on destructive prod ops outside 09:00-18:00 IST."
effect = "refuse"
priority = 1
conditions = [
    { action = "delete.*" },
    { resource = "production/*" },
    { time_window = "18:00-09:00 Asia/Kolkata" },
]

# ───────────────────────────────────────────────────────────────
# Priority 5: refuse oversized agent refunds before any
# permit rule can see them.
# ───────────────────────────────────────────────────────────────
[[policy]]
name = "agent_block_large_refunds"
effect = "refuse"
priority = 5
conditions = [
    { identity_kind = "agent" },
    { action = "issue_refund" },
    { param_min = { field = "amount", min = 5000.01 } },
]

# ───────────────────────────────────────────────────────────────
# Priority 10: small agent refunds, rate-limited, session-capped.
# ───────────────────────────────────────────────────────────────
[[policy]]
name = "agent_small_refunds"
description = "AI agents can issue refunds up to INR 5,000."
effect = "permit"
priority = 10
conditions = [
    { identity_kind = "agent" },
    { action = "issue_refund" },
    { param_max = { field = "amount", max = 5000.0 } },
    { param_in = { field = "currency", values = ["INR"] } },
    { rate_limit = { max = 50, window = "24h" } },
    { session_age_max = "4h" },
]

# ───────────────────────────────────────────────────────────────
# Priority 20: human support agents, broader limits.
# ───────────────────────────────────────────────────────────────
[[policy]]
name = "support_refunds"
effect = "permit"
priority = 20
conditions = [
    { identity_role = "support_agent" },
    { action = "issue_refund" },
    { param_max = { field = "amount", max = 50000.0 } },
    { rate_limit = { max = 100, window = "24h" } },
    { time_window = "09:00-18:00 Asia/Kolkata" },
]

# ───────────────────────────────────────────────────────────────
# Priority 30: payment-service backend, unbounded (trusted).
# ───────────────────────────────────────────────────────────────
[[policy]]
name = "payment_service_refunds"
effect = "permit"
priority = 30
conditions = [
    { identity_kind = "service" },
    { identity_id = "payment-service" },
    { action = "issue_refund" },
]

# ───────────────────────────────────────────────────────────────
# Priority 100: catch-all admin allow.
# ───────────────────────────────────────────────────────────────
[[policy]]
name = "admin_all_actions"
effect = "permit"
priority = 100
conditions = [
    { identity_role = "admin" },
]
```

Any request that matches none of these five policies is refused by default-deny with `RefuseCode::NoPolicyMatch`.

---

## See also

- [concepts/policies.md](../concepts/policies.md), conceptual model.
- [reference/api-surface.md](api-surface.md), type index across all crates.
- [guides/rust.md](../guides/rust.md), [guides/python.md](../guides/python.md), [guides/typescript.md](../guides/typescript.md), SDK usage.
- [operations/deployment-patterns.md](../operations/deployment-patterns.md), hot-reload and multi-node rate-limit setups.
