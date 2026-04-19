# Overview

## What Kavach is

Kavach is a library that separates *possession of credentials* from *permission to act*. Every action your system is about to take (an API call, an MCP tool invocation, a database write, an LLM function call) passes through a gate. The gate evaluates the action in context and returns one of three verdicts: `Permit`, `Refuse`, or `Invalidate`. The action cannot run unless the gate produced a `Permit`.

In Rust, the type system enforces this. The only type that can be executed is `Guarded<A>`, and `Guarded<A>` has no public constructor: the sole way to build one is to hand `Gate::guard` an action and have every evaluator permit. Code that forgets the gate does not compile. The Python and Node SDKs preserve the same contract at runtime: a `Verdict` only becomes a `Permit` when every evaluator agreed, and `Gate.check` raises `Refused` or `Invalidated` if not.

Kavach ships in seven crates:

- `kavach-core`, the gate, evaluators, policy engine, drift detection, invariants.
- `kavach-pq`, post-quantum crypto (ML-DSA-65, ML-KEM-768, Ed25519, X25519, ChaCha20-Poly1305), signed permit tokens, signed audit chains, secure channel.
- `kavach-http`, Axum / Tower middleware and an Actix adapter.
- `kavach-mcp`, MCP tool-call gating.
- `kavach-py`, the Python SDK (PyO3).
- `kavach-node`, the TypeScript SDK (napi-rs).
- `kavach-redis`, Redis-backed stores for rate limits, sessions, and cross-node invalidation broadcast.

## The problem

Most systems treat a valid credential as permission to act. Possession of an API key is treated as authorisation to do anything that key can do. That model breaks down in three ways:

1. **AI agents have credentials but no permission boundary.** An LLM handed a valid API key can call tools it was never meant to call: via hallucination, prompt injection, or a misconfigured tool registry. The key is valid. The action is not.
2. **Sessions drift.** A session that starts legitimately from an office IP silently continues from a different country an hour later, or from a different device, or at a rate no human could produce. The credential is unchanged; the context has changed.
3. **Quantum threatens the transport.** The classical signatures protecting permits and audit chains today (Ed25519, ECDSA) will not survive a large-scale quantum attacker. Long-lived audit logs signed only with classical crypto become forgeable in retrospect.

Kavach addresses all three at the architecture level. Having a key is not enough: every action is evaluated, every time, with the full context, and every resulting permit is signed with post-quantum crypto.

## The two halves

### 1. The gate

Four evaluators run in priority order:

1. **Identity**, who is acting and is the session still trusted.
2. **Policy**, is this action allowed for this principal under these parameters.
3. **Drift**, has the context shifted since the session started (IP, device, behaviour, age).
4. **Invariants**, hard structural limits that cannot be overridden by policy.

The chain short-circuits on the first `Refuse` or `Invalidate`. All evaluators must `Permit` for the action to proceed. An action with no matching policy is refused (default-deny).

See [concepts/gate-and-verdicts.md](concepts/gate-and-verdicts.md) and [concepts/evaluators.md](concepts/evaluators.md).

### 2. The crypto envelope

Every `Permit` verdict can carry a cryptographic signature over the permit token. The signature is ML-DSA-65 (PQ-only) or ML-DSA-65 + Ed25519 (hybrid). Downstream services verify the permit without trusting the network path that delivered it.

The same keys drive:

- **Signed audit chains**, append-only JSONL with per-entry signatures and chain-of-hash, verifiable off-node.
- **Secure channel**, an ML-KEM-768 + X25519 hybrid KEM with ChaCha20-Poly1305 AEAD plus ML-DSA signatures over the sealed payload, for peer-to-peer transport between Kavach nodes.
- **Public-key directories**, root-signed manifests of per-node public keys for multi-node deployments.

See [concepts/post-quantum.md](concepts/post-quantum.md), [concepts/audit.md](concepts/audit.md), [concepts/key-management.md](concepts/key-management.md).

## When to use Kavach

Reach for Kavach when:

- You are giving an AI agent the ability to call tools or write to downstream systems.
- You are building an MCP server or tool server that fronts sensitive operations (refunds, deploys, data exports, customer-facing writes).
- You operate distributed services that need cryptographically verifiable permits at the boundary between services.
- You need a tamper-evident audit trail that survives the post-quantum transition.
- You want compile-time guarantees that a permission check cannot be skipped on a code path.

## When not to use Kavach

Do not reach for Kavach when:

- You need a full-blown IAM system with user management, SSO, and password resets. Kavach is the enforcement layer, not the identity provider. Plug Kavach behind your existing identity system.
- Your actions do not cross a trust boundary worth defending. A monolith where every call path is equally trusted gains little.
- You need an ABAC or Rego-style decision engine with arbitrary expression trees. Kavach policies are intentionally narrow: a small, fixed vocabulary of conditions designed so a security reviewer can read the full ruleset in an afternoon. See [concepts/policies.md](concepts/policies.md).
- You cannot tolerate a small amount of evaluation latency per action. Kavach evaluates in compiled Rust, but the gate still runs (and will do network I/O if you plug in a distributed rate-limit or session store).

## What to read next

- If you want to see it run: [quickstart.md](quickstart.md).
- If you want the model: [concepts/gate-and-verdicts.md](concepts/gate-and-verdicts.md).
- If you want the crypto: [concepts/post-quantum.md](concepts/post-quantum.md).
