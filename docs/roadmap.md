# Roadmap

What Kavach supports today, and what is on the way. Version `0.1.x`.

## Today: consumer-validated surface

The two surfaces that have passed the end-to-end consumer-validation
harness:

- **`kavach-py`** (Python SDK, PyO3): exercised by 41 scenarios across
  `business-tests/` tiers 1 to 6, covering every documented SDK surface with
  several hundred assertions.
- **`kavach-node`** (Node / TypeScript SDK, napi-rs): exercised by 221
  checks across `Kavach/kavach-node/npm/tests/smoke_test.ts`, covering the
  same API surface as the Python SDK.

The Rust crates `kavach-core` and `kavach-pq` sit underneath both SDKs and
have extensive Rust-level test coverage (166 tests enforced with
`RUSTFLAGS="-D warnings"` in CI). The Rust crates are production-quality as
library code; what is not yet in place is a consumer-facing Rust scenario
catalogue analogous to `business-tests/`. That is tracked below.

The full feature list lives in the per-language guides:
[python.md](guides/python.md), [typescript.md](guides/typescript.md),
[rust.md](guides/rust.md).

## Planned: Redis distributed deployments

- **`kavach-redis`** (Rust): Redis-backed implementations of
  `RateLimitStore`, `SessionStore`, `InvalidationBroadcaster`. The crate
  has Rust-level integration tests (run with `TEST_REDIS_URL=redis://...
  cargo test -p kavach-redis`) that pin the trait-impl contracts. The
  Python SDK exposes `RedisRateLimitStore`, `RedisSessionStore`, and
  `RedisInvalidationBroadcaster` as classes. **What is not yet validated
  through the consumer harness:** the multi-replica wiring end to end
  (rate-limit consistency across replicas, session state shared under a
  rolling deploy, cross-node invalidation fan-out). The code is shipped
  and the pattern documented in [guides/distributed.md](guides/distributed.md)
  carries an "experimental" banner for that reason.

When this comes out of planned:

1. A dedicated `business-tests/tier7_redis/` (or similar) with one scenario
   per capability, following the tier 1 to 6 pattern. Redis runs as a side
   container; scenarios skip cleanly when `TEST_REDIS_URL` is unset.
2. The "Experimental" banners disappear from `guides/distributed.md`,
   `deployment-patterns.md` Pattern 2, `kavach-py/README.md`, the top-level
   README Multi-node row, and the `kavach_redis::*` tracing target row in
   `observability.md`.
3. An e2e run that exercises a real multi-replica deployment through the
   existing agent + payment harness.

## Planned: HTTP and MCP integrations

The repository contains two additional crates that are **published but not
yet documented for production use**:

- `kavach-http`: a Tower Layer for Axum, a framework-agnostic `HttpGate`
  core, and an Actix adapter, all behind opt-in Cargo features.
- `kavach-mcp`: a layer for Model Context Protocol servers that gates every
  tool call through a Kavach gate and an `McpSessionManager`.

Both crates compile and have internal tests, but they have not yet been
exercised by the consumer-validation harness the SDKs have passed through.
Until that coverage lands they are treated as experimental. The
documentation site intentionally omits them so readers do not wire them
into production services ahead of the validation work.

### What "thoroughly tested" will mean for each

When the HTTP and MCP layers come out of planned, they will have:

1. A dedicated business-tests tier (one runnable scenario per capability,
   same pattern as tiers 1 through 6) covering the HTTP middleware (Tower,
   Actix, framework-agnostic) and the MCP layer end to end.
2. A per-language usage guide (Rust, Python, Node) with verbatim runnable
   examples covered by the same doc-examples harness that pins the rest of
   the documentation (`business-tests/tier6_docs/`).
3. A real HTTP service and a real MCP server in the end-to-end suite
   (`e2e-tests/`) driving both positive and adversarial scenarios against
   the gate in those transports.

Until all three are in place, the HTTP and MCP integrations stay out of
the documented surface.

### Where the code lives today

If you are comfortable reading source and want to see what exists, the
crates ship with their own integration tests and examples:

- `Kavach/kavach-http/tests/` and `Kavach/kavach-http/examples/`
- `Kavach/kavach-mcp/examples/`

They are published on crates.io so nothing prevents an early adopter from
vendoring them in. The public project does not support that usage yet.

## Planned: HttpPublicKeyDirectory

- **`HttpPublicKeyDirectory`** (`kavach-pq` feature `http`): fetches a
  signed manifest over HTTP with ETag-aware caching. Rust-level unit tests
  cover the happy path, ETag reuse, 304 round-trip, cold-cache fail-closed,
  and warm-cache survive-transient-outage. The consumer-validation harness
  does not yet cover this path end to end. Treated as experimental in the
  docs (see [concepts/key-management.md](concepts/key-management.md)).

## Planned: Rust-level consumer catalogue

- A Rust analogue of `business-tests/` so the direct-Rust integration
  surface (embedding `kavach-core` + `kavach-pq` in-process without going
  through an SDK) is exercised scenario-by-scenario instead of only by the
  core crate's unit tests plus the `e2e-tests/` Python harness.

## Other items under consideration

These are ideas we are tracking but have not committed to:

- Redis-backed stores exposed through the Node SDK (Python already has
  them).
- A Node-side business-tests catalogue mirroring the Python tier 1 through
  6 scenarios.
- A first-class `GeoCountry` policy condition (today the same effect is
  achieved through `param_in` with a `country_code` field).
- A `cargo audit` job in CI.
- A Minimum Supported Rust Version pin (currently tracks `stable`).

None of these block `0.1.x` adoption. They will be scheduled into the
existing phase structure as the validation work for each completes.

## Feedback

The roadmap above is ordered by what we believe is most useful to ship next,
not by implementation complexity. If your use case hinges on one of these
items, open an issue so we can sequence it accordingly.
