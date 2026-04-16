# Kavach documentation

Kavach is a default-deny execution gate: every action is evaluated in context (identity, policy, drift, invariants) before it is allowed to run, and every permit is a post-quantum signed token.

## Suggested learning path

1. [overview.md](overview.md), the problem and the two halves (gate + crypto envelope).
2. [quickstart.md](quickstart.md), a runnable 5-minute walkthrough in Python.
3. [concepts/gate-and-verdicts.md](concepts/gate-and-verdicts.md) and [concepts/evaluators.md](concepts/evaluators.md), the evaluation pipeline and the trait that plugs into it.
4. [concepts/policies.md](concepts/policies.md), then [reference/policy-language.md](reference/policy-language.md) when you need the full grammar.
5. [concepts/post-quantum.md](concepts/post-quantum.md), [concepts/audit.md](concepts/audit.md), [concepts/key-management.md](concepts/key-management.md), the crypto envelope around a verdict.
6. The guide for your runtime under [guides/](guides/), then the deployment docs under [operations/](operations/).

## Concepts

- [overview.md](overview.md), what Kavach is and when to use it.
- [concepts/gate-and-verdicts.md](concepts/gate-and-verdicts.md), evaluation pipeline, `Verdict` variants, and the `Guarded<A>` compile-time proof.
- [concepts/evaluators.md](concepts/evaluators.md), the `Evaluator` trait, built-ins, custom evaluators.
- [concepts/policies.md](concepts/policies.md), TOML policy structure, effects, priorities, conditions.
- [concepts/post-quantum.md](concepts/post-quantum.md), ML-DSA / ML-KEM / hybrid algorithms and where they apply.
- [concepts/audit.md](concepts/audit.md), signed audit chains and JSONL export.
- [concepts/key-management.md](concepts/key-management.md), key pairs, public-key bundles, signed directories.

## Guides

- [guides/rust.md](guides/rust.md), wiring a gate in Rust.
- [guides/python.md](guides/python.md), the PyO3 SDK.
- [guides/typescript.md](guides/typescript.md), the napi-rs SDK.
- [guides/http.md](guides/http.md), HTTP and Tower middleware.
- [guides/mcp.md](guides/mcp.md), gating MCP tool calls.
- [guides/distributed.md](guides/distributed.md), multi-node deployments, pluggable stores, invalidation broadcast.

## Operations

- [operations/deployment-patterns.md](operations/deployment-patterns.md), rollout phases, observe-only to enforce.
- [operations/observability.md](operations/observability.md), tracing, metrics, audit sinks.
- [operations/incident-response.md](operations/incident-response.md), invalidation, key rotation, kill-switches.

## Reference

- [reference/policy-language.md](reference/policy-language.md), complete TOML grammar, every condition, every field.
- [reference/api-surface.md](reference/api-surface.md), public types and functions by crate and SDK.

## Source of truth

Runtime behaviour is defined by the crates under `kavach-core/`, `kavach-pq/`, `kavach-http/`, `kavach-mcp/`, `kavach-py/`, and `kavach-node/`. When in doubt, read the source. These docs describe the intended use of that source.
