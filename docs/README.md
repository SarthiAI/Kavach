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
- [concepts/policies.md](concepts/policies.md), policy structure, effects, priorities, conditions.
- [concepts/post-quantum.md](concepts/post-quantum.md), ML-DSA / ML-KEM / hybrid algorithms and where they apply.
- [concepts/audit.md](concepts/audit.md), signed audit chains and JSONL export.
- [concepts/key-management.md](concepts/key-management.md), key pairs, public-key bundles, signed directories.

## Guides

- [guides/rust.md](guides/rust.md), wiring a gate in Rust.
- [guides/python.md](guides/python.md), the PyO3 SDK.
- [guides/typescript.md](guides/typescript.md), the napi-rs SDK.
- [guides/toml-policies.md](guides/toml-policies.md), the operator-edited TOML workflow, with Rust / Python / Node examples.
- [guides/distributed.md](guides/distributed.md), multi-node deployments, pluggable stores, invalidation broadcast. *(Experimental: `kavach-redis` has Rust-level integration tests but is not yet covered by the SDK-consumer harness.)*

## Operations

- [operations/deployment-patterns.md](operations/deployment-patterns.md), rollout phases, observe-only to enforce.
- [operations/observability.md](operations/observability.md), tracing, metrics, audit sinks.
- [operations/incident-response.md](operations/incident-response.md), invalidation, key rotation, kill-switches.

## Reference

- [reference/policy-language.md](reference/policy-language.md), complete policy grammar across all loaders.
- [reference/api-surface.md](reference/api-surface.md), public types and functions by crate and SDK.

## Roadmap

- [roadmap.md](roadmap.md), what is shipped today, what is planned (HTTP middleware, MCP tool gating), and what we are tracking.

## Source of truth

Runtime behaviour is defined by the crates under `kavach-core/`, `kavach-pq/`, `kavach-py/`, `kavach-node/`, and `kavach-redis/`. When in doubt, read the source. These docs describe the intended use of that source.

## Validation scope

What the consumer-validation harness at `business-tests/` covers today: the Python SDK (`kavach-py`), across 41 scenarios and multiple hundred assertions. The Node SDK (`kavach-node`) is covered by a parallel smoke catalogue at `Kavach/kavach-node/npm/tests/smoke_test.ts` (221 checks).

Everything else in the workspace (`kavach-core` direct usage, `kavach-pq` direct usage, `kavach-redis`, `HttpPublicKeyDirectory`, `kavach-http`, `kavach-mcp`) has its own Rust-level test coverage but is not yet exercised through the consumer-validation harness. Sections of these docs that describe those surfaces carry an experimental banner. See [roadmap.md](roadmap.md) for the validation plan.
