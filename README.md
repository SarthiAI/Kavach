# Kavach कवच

**Post-quantum execution boundary enforcement for AI agents, APIs, and distributed systems.**

Kavach separates *possession of credentials* from *permission to act*. Every action passes through a gate that evaluates identity, policy, drift, and invariants before producing a verdict. Rust's type system makes it a compile error to skip the gate.

---

## The problem

Most systems treat a valid credential as permission to act. If you have the API key, you can do anything that key allows. This is the wrong model because:

- **Keys leak.** A developer commits a key to GitHub, and within minutes bots are spinning up resources.
- **AI agents get tool access.** An LLM with a valid API key can call tools it was never meant to use — via hallucination, prompt injection, or simple misconfiguration.
- **Sessions drift.** A session starts legitimately and silently becomes something else — the user's IP changes, their role is revoked, the context shifts.
- **Quantum threatens transport.** Post-quantum computing may break the cryptography protecting keys in transit.

Kavach fixes this at the architecture level: **having a key is not enough. Every action is evaluated in context, every time.**

---

## How it works

```
Action attempted
       │
       ▼
┌─────────────────────────────────────┐
│           Kavach Gate               │
│                                     │
│  1. Identity — who + context        │
│  2. Policy — is this allowed?       │
│  3. Drift — has context shifted?    │
│  4. Invariants — hard limits        │
│                                     │
│  Verdict: Permit / Refuse / Inval.  │
└─────────────────────────────────────┘
       │
       ▼
  Permit? ──→ Execute
  Refuse? ──→ Blocked (no fallback)
  Invalidate? ──→ Session revoked
```

The `Guarded<A>` type wraps your action. It has **no public constructor** — the only way to get one is through the gate. Rust's type system means your code won't compile if you try to skip it.

---

## Quick start

```rust
use kavach_core::*;
use std::sync::Arc;

// 1. Load policies from config
let policies = PolicySet::from_file("kavach.toml").unwrap();

// 2. Build evaluators
let policy_engine = Arc::new(PolicyEngine::new(policies));
let drift = Arc::new(DriftEvaluator::with_defaults());
let invariants = Arc::new(InvariantSet::new(vec![
    Invariant::param_max("max_refund", "amount", 50_000.0),
    Invariant::max_actions_per_session("session_limit", 500),
]));

// 3. Create the gate
let gate = Gate::new(
    vec![policy_engine, drift, invariants],
    GateConfig::default(),
);

// 4. Every action goes through the gate
let context = ActionContext::new(principal, action, session, env);

match gate.guard(&context, my_action).await {
    Ok(guarded) => {
        // The ONLY way to execute — consumes the permit
        let result = guarded.execute().await?;
    }
    Err(Verdict::Refuse(reason)) => {
        println!("Blocked: {}", reason);
    }
    Err(Verdict::Invalidate(scope)) => {
        println!("Session revoked: {}", scope);
    }
    _ => unreachable!(),
}
```

---

## Policy configuration

Policies are defined in TOML — no code changes needed:

```toml
[[policy]]
name = "agent_small_refunds"
effect = "permit"
conditions = [
    { identity_kind = "agent" },
    { action = "issue_refund" },
    { param_max = { field = "amount", max = 5000.0 } },
    { rate_limit = { max = 50, window = "24h" } },
]
```

See `examples/kavach.toml` for a complete example.

---

## Crate structure

| Crate | Purpose |
|-------|---------|
| `kavach-core` | Gate, verdicts, evaluators, policy engine, drift detection, invariants |
| `kavach-pq` | Post-quantum transport: ML-KEM, ML-DSA, hybrid TLS, signed audit |
| `kavach-mcp` | MCP server middleware for AI agent tool gating (Rust) |
| `kavach-http` | Axum/Tower HTTP middleware (Rust) |
| `kavach-py` | Python SDK — PyO3 bindings to Rust engine + idiomatic wrappers |
| `kavach-node` | TypeScript SDK — napi-rs bindings to Rust engine + framework middleware |

---

## Architecture

All evaluation runs in compiled Rust. Python and TypeScript SDKs are thin
wrappers that cross FFI into the Rust engine for every `evaluate()` call.

```
┌─────────────────────────────────────────────┐
│           kavach-core (Rust)                 │
│  Gate · Policy · Drift · Invariants · Audit │
└──────┬──────────────┬──────────────┬────────┘
       │              │              │
  PyO3 bridge    napi-rs bridge   Rust crates
       │              │              │
  kavach (pip)   kavach (npm)    kavach-mcp
  Python SDK     TypeScript SDK  kavach-http
```

---

## Python SDK

```bash
pip install kavach
```

```python
from kavach import Gate, McpKavachMiddleware

gate = Gate.from_file("kavach.toml",
    invariants=[("max_refund", "amount", 50_000)],
)
kavach = McpKavachMiddleware(gate)

# In your MCP tool handler:
kavach.check_tool_call(
    tool_name="issue_refund",
    params={"amount": 500, "order_id": "ORD-123"},
    caller_id="agent-bot",
    caller_kind="agent",
)
# Raises kavach.Refused if blocked. Otherwise, proceed.
```

**Decorator pattern:**
```python
from kavach import guarded

@guarded(gate, action="issue_refund", param_fields={"amount": "amount"})
async def issue_refund(order_id: str, amount: float):
    return process_refund(order_id, amount)

# Kavach evaluates automatically before execution
result = await issue_refund("ORD-123", 500.0, _principal_id="bot", _principal_kind="agent")
```

**FastAPI middleware:**
```python
from kavach import HttpKavachMiddleware

kavach_http = HttpKavachMiddleware(gate)

@app.middleware("http")
async def kavach_gate(request, call_next):
    verdict = kavach_http.evaluate_fastapi(request)
    if not verdict.is_permit:
        return JSONResponse(status_code=403, content={"error": verdict.reason})
    return await call_next(request)
```

---

## TypeScript SDK

```bash
npm install kavach
```

```typescript
import { Gate, McpKavachMiddleware } from 'kavach';

const gate = Gate.fromFile('kavach.toml', {
  invariants: [{ name: 'max_refund', field: 'amount', maxValue: 50_000 }],
});
const kavach = new McpKavachMiddleware(gate);

// In your MCP tool handler:
kavach.checkToolCall('issue_refund', { amount: 500, orderId: 'ORD-123' }, {
  callerId: 'agent-bot',
  callerKind: 'agent',
});
// Throws KavachRefused if blocked. Otherwise, proceed.
```

**Express middleware:**
```typescript
import { createExpressMiddleware } from 'kavach/http';

app.use(createExpressMiddleware(gate, { gateMutationsOnly: true }));
```

**guardTool wrapper:**
```typescript
const guardedRefund = kavach.guardTool(
  'issue_refund',
  async (params) => processRefund(params),
  { callerId: 'agent-bot', callerKind: 'agent' },
);

const result = await guardedRefund({ amount: 500, orderId: 'ORD-123' });
```

---

## Rollout strategy

Kavach is designed for incremental adoption:

1. **Observe mode** — Gate logs verdicts but never blocks. See what *would* be blocked.
2. **Enforce new services** — New endpoints/tools built with Kavach from day one.
3. **Wrap critical paths** — Payment, data access, admin tools.
4. **Enable drift detection** — Watch for sessions that have gone stale.

```rust
// Phase 1: observe only
let gate = Gate::new(evaluators, GateConfig { observe_only: true, ..Default::default() });
```

---

## License

Apache-2.0
