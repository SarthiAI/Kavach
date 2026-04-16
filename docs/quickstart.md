# Quickstart

A runnable 5-minute walkthrough using the Python SDK. You will install Kavach, write a tiny policy, evaluate two actions against it, and see both a `Permit` and a `Refuse` in the console.

If you prefer Rust or TypeScript, start with [guides/rust.md](guides/rust.md) or [guides/typescript.md](guides/typescript.md). The model is identical across SDKs.

## 1. Install

```bash
pip install kavach
```

Wheels ship as `abi3`, one wheel per platform covers CPython 3.10 and newer. Linux x86_64/aarch64, macOS x86_64/arm64, and Windows x64 are supported.

## 2. Write the script

Create `quickstart.py`:

```python
from kavach import ActionContext, Gate

POLICY = """
[[policy]]
name = "agent_small_refunds"
effect = "permit"
conditions = [
    { identity_kind = "agent" },
    { action = "issue_refund" },
    { param_max = { field = "amount", max = 1000.0 } },
]
"""

# Build the gate. Any action with no matching permit is refused (default-deny).
# The hard_cap invariant blocks refunds over 50_000 regardless of policy.
gate = Gate.from_toml(
    POLICY,
    invariants=[("hard_cap", "amount", 50_000.0)],
)

def describe(verdict):
    if verdict.is_permit:
        return f"PERMIT token_id={verdict.token_id}"
    if verdict.is_refuse:
        return f"REFUSE [{verdict.code}] {verdict.evaluator}: {verdict.reason}"
    return f"INVALIDATE {verdict.evaluator}: {verdict.reason}"

# --- action 1: a 500 refund from an agent, should PERMIT --------------
ctx_ok = ActionContext(
    principal_id="agent-bot",
    principal_kind="agent",
    action_name="issue_refund",
    params={"amount": 500.0},
)
print("small refund:", describe(gate.evaluate(ctx_ok)))

# --- action 2: a 5_000 refund from an agent, should REFUSE ------------
# The policy only permits amount <= 1000, so no policy matches: default-deny.
ctx_too_big = ActionContext(
    principal_id="agent-bot",
    principal_kind="agent",
    action_name="issue_refund",
    params={"amount": 5_000.0},
)
print("big refund:  ", describe(gate.evaluate(ctx_too_big)))

# --- action 3: an unrelated action, should REFUSE ---------------------
# There is no policy for "delete_user" at all. Default-deny.
ctx_unknown = ActionContext(
    principal_id="agent-bot",
    principal_kind="agent",
    action_name="delete_user",
)
print("delete user: ", describe(gate.evaluate(ctx_unknown)))
```

## 3. Run it

```bash
python quickstart.py
```

Expected output (the `token_id` will be a fresh UUID on your machine):

```
small refund: PERMIT token_id=...
big refund:   REFUSE [NO_POLICY_MATCH] policy: no policy permits 'issue_refund' for principal 'agent-bot'
delete user:  REFUSE [NO_POLICY_MATCH] policy: no policy permits 'delete_user' for principal 'agent-bot'
```

## What just happened

- `Gate.from_toml(POLICY, invariants=...)` built a gate with a policy evaluator, a drift evaluator, and an invariant evaluator. All evaluation ran in compiled Rust; the Python layer is a thin PyO3 wrapper.
- The first call matched `agent_small_refunds`: `identity_kind=agent`, `action=issue_refund`, `amount <= 1000`. All conditions held, so the policy permitted. No invariant tripped. The verdict is `Permit` with a fresh `PermitToken`.
- The second call did not match the policy (`amount=5000` exceeds the `param_max` of `1000`), and no other policy applied. Default-deny triggered with the code `NO_POLICY_MATCH`.
- The third call asked for an action the policy file never mentions. Default-deny again.

## Treat refusals as exceptions

For call sites where a `Refuse` is fatal and should short-circuit normal control flow, use `Gate.check(ctx)` instead of `Gate.evaluate(ctx)`. It raises `kavach.Refused` (or `kavach.Invalidated`) instead of returning a verdict:

```python
from kavach import Gate
from kavach.wrappers import Refused

try:
    gate.check(ctx_too_big)
    process_refund()
except Refused as e:
    # e.code, e.evaluator, e.reason are populated.
    return {"error": e.reason}, 403
```

## Next steps

- Understand the pipeline: [concepts/gate-and-verdicts.md](concepts/gate-and-verdicts.md).
- Write richer policies: [concepts/policies.md](concepts/policies.md).
- Sign permit tokens with post-quantum crypto: [concepts/post-quantum.md](concepts/post-quantum.md).
- Plug Kavach into FastAPI, MCP, Axum: [guides/http.md](guides/http.md), [guides/mcp.md](guides/mcp.md).
