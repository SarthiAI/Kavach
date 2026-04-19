# kavach-mcp

**Experimental. Not yet part of the documented Kavach surface.**

`kavach-mcp` contains an `McpKavachLayer` that wraps a `kavach-core::Gate` around Model Context Protocol tool calls, plus an `McpSessionManager` backed by a pluggable `SessionStore`. The crate compiles and has internal tests, but it has not yet been exercised by the consumer-validation harness the rest of the Kavach surface has passed through.

Until that coverage lands, the public project does not support this crate as part of the documented integration path. The published Kavach surface for `0.1.x` is:

- [`kavach-core`](https://crates.io/crates/kavach-core): the gate, evaluators, policy engine.
- [`kavach-pq`](https://crates.io/crates/kavach-pq): post-quantum signatures, audit chains, secure channel.
- [`kavach`](https://pypi.org/project/kavach/): the Python SDK.
- [`kavach`](https://www.npmjs.com/package/kavach): the Node SDK.
- [`kavach-redis`](https://crates.io/crates/kavach-redis): Redis-backed distributed stores.

For the sequencing, see the roadmap: <https://github.com/SarthiAI/Kavach/blob/main/docs/roadmap.md>.

For policy authoring and SDK usage today, start at <https://github.com/SarthiAI/Kavach>.

Bug reports, including reports of breakage in this crate, are welcome at <https://github.com/SarthiAI/Kavach/issues>.
