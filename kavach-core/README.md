# kavach-core

Core execution boundary engine for [Kavach](https://github.com/SarthiAI/Kavach). Provides the gate, verdicts, the four-stage evaluator chain (identity, policy, drift, invariants), and the audit trait.

## What this crate gives you

- `Gate` and `Guarded<A>`: uncloneable proof that the boundary actually ran before an action executed.
- Evaluator pipeline with four built-in evaluators and a pluggable trait for adding your own.
- Async policy evaluation with pluggable `RateLimitStore` and `SessionStore` (in-memory by default, swap in Redis via [`kavach-redis`](https://crates.io/crates/kavach-redis)).
- `spawn_invalidation_listener` for cross-replica revocation fanout.
- Optional file watcher for hot-reloading `policies.toml` (enable the `watcher` feature).

## Status

**Experimental. Not yet thoroughly validated.**

The crate has its own cargo-level test coverage, but the end-to-end consumer-validation harness only exercises the Python and Node SDKs today. Direct-Rust integration through this crate works but does not yet have a published scenario catalogue. Use it, file issues, expect rough edges before 1.0.

Most consumers should adopt Kavach through the [Python SDK (`kavach-sdk` on PyPI)](https://pypi.org/project/kavach-sdk/) or the Node SDK. This crate is for integrators who want to embed the engine directly in a Rust service.

## Quick example

```rust
use kavach_core::{Gate, ActionContext, Verdict};

let gate = Gate::with_defaults();
let ctx = ActionContext::new("send_email", "user-42");

match gate.evaluate(&ctx).await {
    Verdict::Allow(guarded) => {
        // guarded carries proof the gate ran; pass it to whatever performs the action
    }
    Verdict::Refuse(reason) => eprintln!("refused: {reason}"),
    Verdict::Invalidate(reason) => eprintln!("invalidated: {reason}"),
}
```

See the [main repository](https://github.com/SarthiAI/Kavach) for the full architecture, policy language reference, and integration guides.

## License

[Elastic License 2.0](https://github.com/SarthiAI/Kavach/blob/main/LICENSE). Source-available: you may embed and modify Kavach freely, but may not repackage it as a competing hosted service.
