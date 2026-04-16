<h1 align="center">Kavach कवच</h1>

<p align="center">
  <strong>A default-deny execution boundary for AI agents, APIs, and distributed systems.</strong><br>
  <em>Post-quantum signed. Written in Rust. Says no unless policy says yes.</em>
</p>

<p align="center">
  <a href="https://github.com/SarthiAI/Kavach/actions"><img src="https://img.shields.io/github/actions/workflow/status/SarthiAI/Kavach/ci.yml?label=CI&style=flat-square" alt="CI"></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-Elastic--2.0-blue?style=flat-square" alt="License"></a>
  <a href="./docs/README.md"><img src="https://img.shields.io/badge/docs-read-informational?style=flat-square" alt="Docs"></a>
  <a href="./SECURITY.md"><img src="https://img.shields.io/badge/security-PQ%20ready-brightgreen?style=flat-square" alt="Security: PQ"></a>
  <img src="https://img.shields.io/badge/rust-1.75%2B-orange?style=flat-square" alt="Rust 1.75+">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/node-20%2B-green?style=flat-square" alt="Node 20+">
</p>

---

> *Kavach* (कवच) means **armor** in Sanskrit. It sits between the world and your service, turning every action request into a decision made in context and sealed in cryptography.

## The problem

Most systems confuse two things:

> **Having a credential is not the same as having permission.**

- An API key leaks to GitHub. Within minutes, bots spin up cloud resources on your account.
- An LLM with tool access is asked to "also refund the last 100 orders." It does.
- A mobile session started in Bangalore at 9 AM is now hitting your admin API from Eastern Europe at 2 AM.
- An internal service was authorized to issue refunds up to ₹5,000. A config change made it unlimited. Nobody caught it for six weeks.

Each of these is a system that asked *"can this request be authenticated?"* and never asked *"should this request be permitted, right now, in this context?"*

## The idea

Kavach is a **default-deny execution gate**. Every action, before it runs, passes through four evaluators in order:

```
  Action attempted
         │
         ▼
   ┌───────────────────────────────────────┐
   │           KAVACH GATE                 │
   │                                       │
   │  1. Identity    (who, role, session)  │
   │  2. Policy      (is this allowed?)    │
   │  3. Drift       (has context shifted?)│
   │  4. Invariants  (hard, unoverridable) │
   │                                       │
   │  Verdict: Permit · Refuse · Invalidate│
   └───────────────────────────────────────┘
         │
         ▼
  Permit?      ▶  execute (with signed proof)
  Refuse?      ▶  blocked
  Invalidate?  ▶  session revoked, propagated
```

A single **Refuse** or **Invalidate** short-circuits the chain. An action matching no policy is refused. Kavach is the inverse of a blacklist.

On top of the gate, a **post-quantum cryptographic envelope** signs permits, chains every decision into a tamper-evident audit log, and secures channels between nodes. A permit issued on node A can be verified on node B, months later, without trusting the network and without shared secrets.

## Two capabilities, one library

|  | The Gate | The PQ Envelope |
|---|---|---|
| **Decides** | Whether an action is permitted in its full context. | (nothing; consumes the gate's output) |
| **Protects against** | Credential leaks, permissive defaults, session drift, compliance drift, policy regressions. | Signature forgery, replay attacks, silent algorithm downgrade, audit tamper, cross-node trust gaps. |
| **Output** | `Verdict::Permit(PermitToken)`, `Verdict::Refuse(reason)`, `Verdict::Invalidate(scope)` | Signed `PermitToken`, `SignedAuditChain`, `SecureChannel` sealed payloads. |
| **Algorithms** | Rust type system. `Guarded<A>` has no public constructor, so skipping the gate is a *compile error*. | ML-DSA-65 and Ed25519 (signatures), ML-KEM-768 and X25519 (key exchange), ChaCha20-Poly1305 (AEAD), all hybrid-mode. |

You get both, together. Every gate decision lands in the audit chain. Every permit carries a signature a downstream service can verify independently.

## See it in action

An AI support agent trying to issue refunds. The gate does the deciding.

```python
from kavach import Gate

policy = """
[[policy]]
name = "agent_small_refunds"
effect = "permit"
conditions = [
    { identity_kind = "agent" },
    { action = "issue_refund" },
    { param_max = { field = "amount", max = 5000.0 } },
    { rate_limit = { max = 50, window = "24h" } },
]
"""

gate = Gate.from_toml(
    policy,
    invariants=[("compliance_cap", "amount", 50_000.0)],  # immutable, even by policy
)

# Within policy: permit.
v = gate.evaluate(
    principal_id="bot-1", principal_kind="agent",
    action_name="issue_refund", params={"amount": 500},
)
assert v.is_permit

# Exceeds the ₹5,000 policy cap: refuse.
v = gate.evaluate(
    principal_id="bot-1", principal_kind="agent",
    action_name="issue_refund", params={"amount": 10_000},
)
assert v.is_refuse
print(v.code)       # "POLICY_NO_MATCH"

# Rogue admin ships a policy that permits ₹1,00,000. Invariant still refuses.
gate.reload(policy.replace("5000.0", "100000.0"))
v = gate.evaluate(
    principal_id="bot-1", principal_kind="agent",
    action_name="issue_refund", params={"amount": 60_000},
)
assert v.is_refuse
print(v.evaluator)  # "invariants", because policies cannot override this
```

Same semantics from TypeScript, Rust, or an MCP tool call.

## What you can build with it

- **AI agent tool gating.** Give an LLM tool access; Kavach guards every tool call. A prompt-injected agent cannot escalate beyond what policy permits.
- **Refund, payment, and admin APIs** with per-role caps plus hard compliance invariants that a misconfigured policy cannot bypass.
- **Multi-tenant SaaS.** Each tenant gets a different policy set, hot-reloadable, default-deny.
- **Cross-service authorization.** Node A issues a signed permit. Node B verifies independently, no shared secrets.
- **Tamper-evident audit logs** for SOC 2, ISO 27001, financial compliance. A regulator runs `verify_jsonl(blob, root_public_key)` and gets a cryptographic yes or no.
- **Incident-grade kill-switch.** Ship an empty policy TOML, every action past that point is refused within 100 ms. Tested, not hypothetical.

## Get started

| Language / Runtime | Install | Guide |
|--------------------|---------|-------|
| **Rust** | `kavach-core = "0.1"` in your `Cargo.toml` | [docs/guides/rust.md](./docs/guides/rust.md) |
| **Python** | `pip install kavach` (one abi3 wheel per platform, covers 3.10+) | [docs/guides/python.md](./docs/guides/python.md) |
| **TypeScript / Node** | `npm install kavach` | [docs/guides/typescript.md](./docs/guides/typescript.md) |
| **MCP tool gating** | via Python or TypeScript SDK | [docs/guides/mcp.md](./docs/guides/mcp.md) |
| **HTTP (Axum / Tower / Actix)** | `kavach-http` with the `tower` or `actix` feature | [docs/guides/http.md](./docs/guides/http.md) |
| **Multi-node (Redis)** | `kavach-redis` | [docs/guides/distributed.md](./docs/guides/distributed.md) |

Or start with the [five-minute quickstart](./docs/quickstart.md).

## How it works, a layer deeper

Every evaluation builds an `ActionContext` (principal, action, session state, environment) and hands it to the Gate. The Gate iterates a `Vec<Arc<dyn Evaluator>>` in order:

1. **PolicyEngine** matches TOML rules. Conditions include `identity_kind`, `identity_role`, `action`, `param_max`, `param_min`, `param_in`, `rate_limit`, `session_age_max`, `resource` (glob), and `time_window` (with optional timezone, for example `"09:00-18:00 Asia/Kolkata"`). No matching permit rule means default-deny Refuse.
2. **DriftEvaluator** runs IP drift, geo drift (tolerant mode with a kilometre threshold), session-age drift, device-fingerprint drift. A Violation produces **Invalidate**, not Refuse. Subsequent requests on the same session are rejected across every node.
3. **InvariantSet** enforces hard, code-level limits such as "no refund ever exceeds ₹50,000." Invariants run *after* policy, so a permissive policy cannot route around them.
4. If every evaluator permits, the Gate optionally attaches an ML-DSA-65 (or hybrid ML-DSA-65 + Ed25519) signed `PermitToken` and wraps the action in `Guarded<A>`. There is no public constructor for `Guarded<A>`; the only way to get one is through the gate. The Rust type system makes skipping the gate a compile error.

Every decision (Permit, Refuse, or Invalidate) is appended to an optional `SignedAuditChain`. Entries are SHA-256 chained and ML-DSA signed. A single bit flip anywhere in the log, a deletion, a reorder, a forged entry, or a mode splice (mixing PQ-only entries into a hybrid chain) is detected by `verify_chain` with a specific error pointing at the offending entry index.

For multi-node deployments, pluggable `RateLimitStore`, `SessionStore`, and `InvalidationBroadcaster` traits swap in Redis-backed implementations. An Invalidate verdict on one node propagates to every other node that holds the same session, via Redis pub/sub. Store errors fail **closed**; broadcast errors never downgrade the local verdict.

## What lives where

```
.
├── kavach-core/      Gate, verdicts, evaluators, traits. The brain.
├── kavach-pq/        Post-quantum crypto. Signatures, encryption, audit chain, secure channel.
├── kavach-http/      Tower Layer, Actix adapter, framework-agnostic HttpGate.
├── kavach-mcp/       Model Context Protocol tool gating (Rust).
├── kavach-py/        Python SDK via PyO3. Ships as abi3 wheels.
├── kavach-node/      Node / TypeScript SDK via napi-rs.
├── kavach-redis/     Redis-backed distributed stores and invalidation broadcaster.
├── docs/             Full documentation, organized by concept, guide, operations, reference.
├── examples/         Reference policy files.
└── e2e-tests/        End-to-end harnesses. 21 realistic scenarios, including a wire-trace runner.
```

## Project status

**Pre-1.0 (`0.1.x`).** Feature-complete against spec. API may shift before `1.0`. Suitable for pilots, internal services, and staged rollouts behind observe-only mode.

- **Tests:** 163 Rust, 139 Python SDK, 133 Node SDK, 21 end-to-end scenarios. All green under `RUSTFLAGS="-D warnings"` and `cargo clippy -- -D warnings`.
- **CI:** GitHub Actions, 5-OS matrix (Linux x64 and arm64, macOS x64 and arm64, Windows x64). Wheel and native-addon builds per platform.
- **Crypto primitives** are on release candidates of `ml-dsa` (`0.1.0-rc.8`) and `ml-kem` (`0.3.0-rc.2`). This matches the Rust PQ ecosystem; every PQ library is on pinned RC until RustCrypto ships 1.0. See [SECURITY.md](./SECURITY.md) for threat model, disclosure, and scope.
- **Observe mode:** set `GateConfig::observe_only = true` to log every would-be verdict without blocking. The recommended first-week rollout path.

## Documentation

Full docs live in [docs/](./docs/README.md). Starting points:

- **New to Kavach?** [docs/overview.md](./docs/overview.md), then [docs/quickstart.md](./docs/quickstart.md).
- **Writing policies?** [docs/concepts/policies.md](./docs/concepts/policies.md), complete grammar at [docs/reference/policy-language.md](./docs/reference/policy-language.md).
- **Integrating with a framework?** [docs/guides/](./docs/guides/) has one file per runtime.
- **Running in production?** [docs/operations/](./docs/operations/) covers deployment patterns, observability, and incident response playbooks.
- **Curious about the crypto?** [docs/concepts/post-quantum.md](./docs/concepts/post-quantum.md) and [docs/concepts/audit.md](./docs/concepts/audit.md).

## Security

Report vulnerabilities privately to **`support@sarthiai.com`** with subject `[kavach-security] <short description>`. Do not open a public issue. See [SECURITY.md](./SECURITY.md) for the full policy, threat model, and in-scope / out-of-scope details.

## Contributing

Bug reports, feature requests, and pull requests are welcome. Open an issue on GitHub.

Security issues go to `support@sarthiai.com`, not the public tracker.

## License

[Elastic License 2.0](./LICENSE). Source-available. You are free to use, embed, modify, and redistribute Kavach for any purpose, including commercial use inside your products. You may **not** offer Kavach itself as a hosted or managed service that substitutes for the features of this software, and you may not remove or obscure the license notices.

In plain language: build on top of Kavach, ship it inside your products, modify it for your own use. Do not repackage it and sell it as "MyGate."

---

<p align="center"><em>Built with Rust. Runs post-quantum. Says no by default.</em></p>
