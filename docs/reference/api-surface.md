# API Surface

A navigable index of the public types Kavach exposes, organized per crate and per SDK. This is not a substitute for rustdoc; it is a one-sentence-per-type roadmap you can scan before diving into the source. For the full policy grammar see [policy-language.md](policy-language.md).

Every path in this document is relative to the repo root, so `[Gate](../../kavach-core/src/gate.rs)` resolves from this file's location.

This index covers the documented surface: `kavach-core`, `kavach-pq`, `kavach-py`, `kavach-node`, and `kavach-redis`. Two additional crates (`kavach-http`, `kavach-mcp`) live in the workspace and are held as experimental until their validation harness lands; see [../roadmap.md](../roadmap.md).

---

## `kavach-core`

Re-exported from [kavach-core/src/lib.rs](../../kavach-core/src/lib.rs). The crate is the default-deny execution gate and its plug points.

### Gate and verdicts

| Type                                                                              | Purpose                                                                                                     |
| --------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| [`Gate`](../../kavach-core/src/gate.rs)                                           | The evaluation pipeline; runs evaluators in order and collapses their outputs into a single `Verdict`.      |
| [`GateConfig`](../../kavach-core/src/gate.rs)                                     | Tuning knobs: `observe_only` (log-only rollout), `permit_ttl_seconds`, `fail_open`.                         |
| [`Verdict`](../../kavach-core/src/verdict.rs)                                     | Three-way outcome: `Permit(PermitToken)`, `Refuse(RefuseReason)`, `Invalidate(InvalidationScope)`.          |
| [`PermitToken`](../../kavach-core/src/verdict.rs)                                 | Cryptographically attributable proof that the gate permitted a specific action; carries evaluation id, TTL, signature. |
| [`RefuseReason`](../../kavach-core/src/verdict.rs)                                | Evaluator-scoped refusal payload: which evaluator, why, `RefuseCode`, evaluation id.                        |
| [`RefuseCode`](../../kavach-core/src/verdict.rs)                                  | Machine-readable refusal enum: `IdentityFailed`, `PolicyDenied`, `NoPolicyMatch`, `RateLimitExceeded`, `SessionInvalid`, `InvariantViolation`, and friends. |
| [`InvalidationScope`](../../kavach-core/src/verdict.rs)                           | Payload for `Verdict::Invalidate`: target, reason, triggering evaluator.                                    |
| [`InvalidationTarget`](../../kavach-core/src/verdict.rs)                          | What the invalidation covers: `Session(Uuid)`, `Principal(String)`, `Role(String)`.                         |
| [`Guarded<A>`](../../kavach-core/src/gate.rs)                                     | Uncloneable proof wrapper; an action can only be built this way by the gate, enforcing "no bypass" at compile time. |
| [`TokenSigner`](../../kavach-core/src/verdict.rs)                                 | Trait for signing permit tokens; the gate fails closed if `sign` errors.                                    |

### Action context

| Type                                                                    | Purpose                                                                                               |
| ----------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| [`ActionContext`](../../kavach-core/src/context.rs)                     | The input to every evaluator: principal + action + session + env + metadata + evaluation id.          |
| [`Principal`](../../kavach-core/src/context.rs)                         | Who is acting: id, kind, roles, credential issue time, optional display name.                         |
| [`PrincipalKind`](../../kavach-core/src/context.rs)                     | `User`, `Agent`, `Service`, `Scheduler`, `External`.                                                   |
| [`ActionDescriptor`](../../kavach-core/src/context.rs)                  | What is being attempted: name, optional resource, typed parameters (JSON values).                     |
| [`EnvContext`](../../kavach-core/src/context.rs)                        | Request-environment metadata: IP, device fingerprint, geo, user-agent.                                |
| [`SessionState`](../../kavach-core/src/context.rs)                      | Per-session state: id, start time, recorded actions, origin IP / geo, invalidation flag.              |
| [`GeoLocation`](../../kavach-core/src/context.rs)                       | Geographic coordinates: `country_code`, optional `region`, `city`, `latitude`, `longitude`.           |
| [`DeviceFingerprint`](../../kavach-core/src/context.rs)                 | Opaque device hash used by the drift evaluator.                                                        |
| [`Action`](../../kavach-core/src/action.rs)                             | The executable-side trait every protected action implements; `Guarded<A>` consumes it on execute.     |

### Evaluators

| Type                                                                    | Purpose                                                                                               |
| ----------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| [`Evaluator`](../../kavach-core/src/evaluator.rs)                       | Core async trait; every check the gate runs implements this.                                          |
| [`Policy`](../../kavach-core/src/policy.rs)                             | One parsed rule: name, effect, conditions, description, priority.                                     |
| [`Effect`](../../kavach-core/src/policy.rs)                             | `Permit` or `Refuse`.                                                                                 |
| [`Condition`](../../kavach-core/src/policy.rs)                          | The 11-variant enum driving policy matching (see [policy-language.md](policy-language.md)).            |
| [`PolicySet`](../../kavach-core/src/policy.rs)                          | Deserialized `[[policy]]` collection; built via `from_toml` or `from_file`.                           |
| [`PolicyEngine`](../../kavach-core/src/policy.rs)                       | `Evaluator` implementation that applies `PolicySet` in priority order; holds an `Arc<dyn RateLimitStore>` and supports hot-reload. |
| [`DriftEvaluator`](../../kavach-core/src/drift.rs)                      | Evaluator composed of pluggable drift detectors (geo, device, session-age, behavioral).               |
| [`DriftDetector`](../../kavach-core/src/drift.rs)                       | Trait; each concrete detector looks for one class of anomaly.                                         |
| [`GeoLocationDrift`](../../kavach-core/src/drift.rs)                    | Strict or tolerant detector for mid-session geography change; distance threshold via `max_distance_km`. |
| [`DeviceDrift`](../../kavach-core/src/drift.rs)                         | Detector for fingerprint mismatch mid-session.                                                         |
| [`SessionAgeDrift`](../../kavach-core/src/drift.rs)                     | Detector for over-aged sessions.                                                                       |
| [`BehaviorDrift`](../../kavach-core/src/drift.rs)                       | Detector for action-rate or pattern deviation.                                                         |
| [`DriftSignal`](../../kavach-core/src/drift.rs)                         | What a detector can emit; aggregated by `DriftEvaluator`.                                              |
| [`DriftViolation`](../../kavach-core/src/drift.rs)                      | Hard drift (refuses / invalidates depending on severity).                                              |
| [`DriftWarning`](../../kavach-core/src/drift.rs)                        | Soft drift (logged, still permits).                                                                     |
| [`InvariantSet`](../../kavach-core/src/invariant.rs)                    | `Evaluator` implementation that checks numeric parameter bounds.                                       |
| [`Invariant`](../../kavach-core/src/invariant.rs)                       | One rule: name, field, max value.                                                                      |

### Pluggable stores

| Type                                                                    | Purpose                                                                                                |
| ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| [`RateLimitStore`](../../kavach-core/src/rate_limit.rs)                 | Async trait for recording actions and counting within a sliding window; `record` errors fail closed (refuse), `count` errors fail the condition. |
| [`InMemoryRateLimitStore`](../../kavach-core/src/rate_limit.rs)         | Default single-node implementation.                                                                    |
| [`RateLimitStoreError`](../../kavach-core/src/rate_limit.rs)            | Error type surfaced from distributed backends.                                                          |
| [`SessionStore`](../../kavach-core/src/session_store.rs)                | Async trait for session persistence and cleanup.                                                        |
| [`InMemorySessionStore`](../../kavach-core/src/session_store.rs)        | Default single-node implementation.                                                                     |
| [`SessionStoreError`](../../kavach-core/src/session_store.rs)           | Error type surfaced from distributed backends.                                                          |
| [`InvalidationBroadcaster`](../../kavach-core/src/invalidation.rs)      | Async trait for cross-node session invalidation; `publish` failures never downgrade the local verdict. |
| [`NoopInvalidationBroadcaster`](../../kavach-core/src/invalidation.rs)  | Default no-broadcast implementation.                                                                    |
| [`InMemoryInvalidationBroadcaster`](../../kavach-core/src/invalidation.rs) | Single-process broadcast channel; useful for tests.                                                  |
| [`BroadcastError`](../../kavach-core/src/invalidation.rs)               | Error type from the broadcaster trait.                                                                  |
| [`spawn_invalidation_listener`](../../kavach-core/src/invalidation.rs)  | Starts a background task that forwards inbound invalidations to a handler closure; returns `JoinHandle`. |
| [`spawn_session_store_listener`](../../kavach-core/src/invalidation.rs) | Starts a task that applies inbound invalidations directly to a `SessionStore`.                          |

### Audit

| Type                                                                    | Purpose                                                                                                |
| ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| [`AuditEntry`](../../kavach-core/src/audit.rs)                          | A single tamper-evidently-chained event record.                                                         |
| [`AuditLog`](../../kavach-core/src/audit.rs)                            | In-process log of entries plus a sink for shipping them out.                                            |
| [`AuditSink`](../../kavach-core/src/audit.rs)                           | Trait; where entries go (stdout, file, shipped to kavach-pq signer, etc.).                              |

### Errors

| Type                                                                    | Purpose                                                                                                |
| ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| [`KavachError`](../../kavach-core/src/error.rs)                         | Top-level error union for the core crate.                                                               |
| [`PolicyError`](../../kavach-core/src/error.rs)                         | TOML parse errors from `PolicySet::from_toml`.                                                          |

### Watcher (feature = "watcher")

| Type                                                                    | Purpose                                                                                                |
| ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| [`spawn_policy_watcher`](../../kavach-core/src/watcher.rs)              | Spawns a `notify`-backed task that hot-reloads a TOML policy file; parse errors keep the previous good set. |
| [`WatcherError`](../../kavach-core/src/watcher.rs)                      | Error type for the watcher.                                                                             |

---

## `kavach-pq`

Re-exported from [kavach-pq/src/lib.rs](../../kavach-pq/src/lib.rs). Post-quantum transport, signing, and key management.

### Keys

| Type                                                                    | Purpose                                                                                                |
| ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| [`KavachKeyPair`](../../kavach-pq/src/keys.rs)                          | Full PQ + classical keypair: ML-DSA-65 + ML-KEM-768 + Ed25519 + X25519; supports PQ-only or hybrid modes. |
| [`PublicKeyBundle`](../../kavach-pq/src/keys.rs)                        | Publishable half of a `KavachKeyPair`; what recipients need to verify signatures and encapsulate KEMs.  |
| [`KeyStore`](../../kavach-pq/src/keys.rs)                               | Storage abstraction for keypairs.                                                                       |

### Signing

| Type                                                                    | Purpose                                                                                                |
| ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| [`Signer`](../../kavach-pq/src/sign.rs)                                 | Produces detached signatures; `from_keypair(kp, hybrid)` is the factory, `is_hybrid()` exposes the mode. |
| [`Verifier`](../../kavach-pq/src/sign.rs)                               | Verifies detached signatures; `from_bundle(bundle, hybrid)` factory; strict mode enforcement.           |
| [`SignedPayload`](../../kavach-pq/src/sign.rs)                          | A bytes + signature pair.                                                                               |
| [`PqTokenSigner`](../../kavach-pq/src/token.rs)                         | `TokenSigner` implementation that emits `SignedTokenEnvelope` on `sign()`; used to sign permit tokens.  |
| [`SignedTokenEnvelope`](../../kavach-pq/src/token.rs)                   | Wire format for signed permit tokens: key id + signature + algorithm tag.                               |
| [`DirectoryTokenVerifier`](../../kavach-pq/src/token.rs)                | Async verifier that resolves the signer's public key from a `PublicKeyDirectory`; fails closed on any directory error. |
| [`DirectoryVerifyError`](../../kavach-pq/src/token.rs)                  | Verification-error enum: `NotFound`, `BackendUnavailable`, `AlgorithmMismatch`, `SignatureInvalid`, etc. |
| [`VerdictSigner`](../../kavach-pq/src/verdict.rs)                       | Signs full `Verdict` structs (not just tokens) with ML-DSA.                                             |
| [`VerdictVerifier`](../../kavach-pq/src/verdict.rs)                     | Verifies signed verdicts and raw signed bytes through a shared replay cache.                            |
| [`SignedVerdict`](../../kavach-pq/src/verdict.rs)                       | Wire format for signed verdicts.                                                                        |

### Directory

| Type                                                                    | Purpose                                                                                                |
| ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| [`PublicKeyDirectory`](../../kavach-pq/src/directory.rs)                | Trait for looking up `PublicKeyBundle` by key id.                                                       |
| [`InMemoryPublicKeyDirectory`](../../kavach-pq/src/directory.rs)        | Process-local implementation with mutable `insert`/`remove`.                                            |
| [`FilePublicKeyDirectory`](../../kavach-pq/src/directory.rs)            | File-backed implementation; supports plain-JSON and root-signed-manifest variants.                      |
| [`HttpPublicKeyDirectory`](../../kavach-pq/src/http_directory.rs) (feature = "http") | HTTP-backed implementation; fetches bundles from a remote manifest endpoint.                |
| [`SignedDirectoryManifest`](../../kavach-pq/src/directory.rs)           | Root-signed bundle list; `bundles_json: String` holds the exact bytes that were signed (no JSON canonicalization). |
| [`KeyDirectoryError`](../../kavach-pq/src/directory.rs)                 | Lookup / verification error enum; every variant is fail-closed.                                         |

### Channel and encryption

| Type                                                                    | Purpose                                                                                                |
| ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| [`SecureChannel`](../../kavach-pq/src/channel.rs)                       | Authenticated, encrypted, replay-resistant duplex between two peers; `establish_from_bundle` is the recommended constructor. |
| [`Encryptor`](../../kavach-pq/src/encrypt.rs)                           | One end of the channel's encryption path; exposes `recipient_key_id()`.                                 |
| [`Decryptor`](../../kavach-pq/src/encrypt.rs)                           | Opposite end; `recipient_key_id()` is also bound as AEAD AAD so wrong-recipient fails at decrypt time.  |
| [`EncryptedPayload`](../../kavach-pq/src/encrypt.rs)                    | Wire format for ChaCha20-Poly1305 sealed bytes: ciphertext + nonce + ML-KEM ciphertext + AAD.           |
| [`SealedVerdict`](../../kavach-pq/src/channel.rs)                       | Signed + encrypted `Verdict` produced by `send_verdict`; binds action name into the signature AAD.      |
| [`SignedBytes`](../../kavach-pq/src/channel.rs)                         | Signed + encrypted raw bytes produced by `send_signed`; binds context id.                               |

### Hybrid mode

| Type                                                                    | Purpose                                                                                                |
| ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| [`HybridKeyPair`](../../kavach-pq/src/hybrid.rs)                        | Classical + PQ keypair used by the legacy `SecureChannel::establish(...)` path; prefer `KavachKeyPair`. |
| [`HybridChannel`](../../kavach-pq/src/hybrid.rs)                        | Legacy channel type; superseded by `SecureChannel` built from bundles.                                  |

### Audit chain

| Type                                                                    | Purpose                                                                                                |
| ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| [`SignedAuditEntry`](../../kavach-pq/src/audit.rs)                      | Per-event signed record with `mode()` for mode detection.                                               |
| [`SignedAuditChain`](../../kavach-pq/src/audit.rs)                      | Chained sequence; `verify_chain` is strictly mode-enforcing (no silent PQ-downgrade).                   |
| [`ChainMode`](../../kavach-pq/src/audit.rs)                             | `PqOnly` or `Hybrid`; detected per-entry and asserted chain-wide.                                       |
| `audit::{export_jsonl, parse_jsonl, detect_mode}` in [audit.rs](../../kavach-pq/src/audit.rs) | Shared JSONL helpers; `parse_jsonl` reports errors by entry index, not raw line number. |

### Errors

| Type                                                                    | Purpose                                                                                                |
| ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| [`PqError`](../../kavach-pq/src/error.rs)                               | Top-level error for the crate.                                                                          |

---

## `kavach-py`

Python package entry point is [kavach-py/python/kavach/\_\_init\_\_.py](../../kavach-py/python/kavach/__init__.py). Everything compiled lives in the `_kavach_engine` native module; these are the user-facing symbols.

| Symbol                                                                                    | Purpose                                                                                                 |
| ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| [`Gate`](../../kavach-py/python/kavach/wrappers.py)                                       | High-level Python gate wrapper; `from_toml`, `from_file`, `evaluate`, `check`, `reload`.               |
| [`ActionContext`](../../kavach-py/src/lib.rs)                                             | PyO3-backed struct; principal, action, session, env fields for `Gate.evaluate`.                         |
| [`Verdict`](../../kavach-py/src/lib.rs)                                                   | PyO3 verdict; `is_permit`, `is_refuse`, `is_invalidate`, `reason`, `evaluator`, `code`, `permit_token`. |
| [`PermitToken`](../../kavach-py/src/lib.rs)                                               | Reconstructed permit token: `token_id`, `evaluation_id`, `issued_at`, `expires_at`, `action_name`, `signature`. |
| [`KavachKeyPair`](../../kavach-py/src/lib.rs)                                             | PQ keypair; `generate`, `public_keys`, `build_signed_manifest`; seed never crosses FFI.                 |
| [`PqTokenSigner`](../../kavach-py/src/lib.rs)                                             | Token signer; `pq_only`, `hybrid` constructors, `generate_pq_only`, `generate_hybrid` helpers, `sign`, `verify`, `is_hybrid`. |
| [`PublicKeyBundle`](../../kavach-py/src/lib.rs)                                           | Publishable PQ public-key bundle.                                                                       |
| [`PublicKeyDirectory`](../../kavach-py/src/lib.rs)                                        | Unified class with `in_memory` / `from_file` / `from_signed_file` factories; polymorphic `reload`.      |
| [`DirectoryTokenVerifier`](../../kavach-py/src/lib.rs)                                    | Async-backed verifier; wraps `Arc<Inner>` so `verify()` can use `runtime().block_on(...)`.              |
| [`AuditEntry`](../../kavach-py/src/lib.rs)                                                | Single signed audit record.                                                                              |
| [`SignedAuditChain`](../../kavach-py/src/lib.rs)                                          | Chained audit log; `verify_jsonl(data, public_keys, hybrid=None)` infers mode by default.               |
| [`SecureChannel`](../../kavach-py/src/lib.rs)                                             | PQ secure channel; exposes `send_signed`/`receive_signed`, `send_data`/`receive_data` bytes flow.       |
| [`GeoLocation`](../../kavach-py/src/lib.rs)                                               | Pyclass; `country_code` required, `latitude`/`longitude` unlock tolerant `GeoLocationDrift`.            |
| [`DeviceFingerprint`](../../kavach-py/src/lib.rs)                                         | Pyclass for the device-drift detector; opaque fingerprint hash plus optional user-agent / platform.     |
| [`InvalidationScope`](../../kavach-py/src/lib.rs)                                         | Pyclass surfaced to listener callbacks; carries `target`, `reason`, `evaluator`.                         |
| [`InMemorySessionStore`](../../kavach-py/src/lib.rs)                                      | In-process session store; usable directly when an integrator needs local session state.                  |
| [`InMemoryInvalidationBroadcaster`](../../kavach-py/src/lib.rs)                           | In-process broadcaster; pairs with `spawn_invalidation_listener` for single-node fan-out.               |
| [`RedisRateLimitStore`](../../kavach-py/src/lib.rs)                                       | Redis-backed rate-limit store; passed as `rate_store=` to `Gate.from_toml/from_file`.                   |
| [`RedisSessionStore`](../../kavach-py/src/lib.rs)                                         | Redis-backed session store; shared across replicas.                                                      |
| [`RedisInvalidationBroadcaster`](../../kavach-py/src/lib.rs)                              | Redis Pub/Sub broadcaster; passed as `broadcaster=` to `Gate.from_toml/from_file`.                       |
| [`spawn_invalidation_listener`](../../kavach-py/src/lib.rs)                               | Spawns a task that invokes a callback on every `Invalidate` verdict; returns `InvalidationListenerHandle`. |
| [`InvalidationListenerHandle`](../../kavach-py/src/lib.rs)                                | Handle with `.abort()` to stop the listener; dropping does not auto-stop.                                |
| [`Refused`](../../kavach-py/python/kavach/wrappers.py)                                    | Exception raised by `Gate.check` when the verdict is Refuse.                                             |
| [`Invalidated`](../../kavach-py/python/kavach/wrappers.py)                                | Exception raised by `Gate.check` when the verdict is Invalidate.                                         |
| [`guarded`](../../kavach-py/python/kavach/decorators.py)                                  | Decorator that wraps a function call in a Kavach `check`.                                                |

---

## `kavach-node`

TypeScript entry point is [kavach-node/npm/src/index.ts](../../kavach-node/npm/src/index.ts). The native addon is re-exported from `kavach-engine`; these are the TS-level symbols.

| Symbol                                                                                     | Purpose                                                                                                 |
| ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------- |
| [`Gate`](../../kavach-node/npm/src/index.ts)                                               | Idiomatic TS gate; `Gate.fromToml`, `Gate.fromFile`, `evaluate`, `check`, `reload`, `evaluatorCount`.   |
| [`EvaluateOptions`](../../kavach-node/npm/src/index.ts)                                    | Input shape for `Gate.evaluate`: principal, action, roles, resource, params, IP, session, geo.          |
| [`GateOptions`](../../kavach-node/npm/src/index.ts)                                        | Construction options: `invariants`, `observeOnly`, `maxSessionActions`, `enableDrift`, `tokenSigner`, `geoDriftMaxKm`, `broadcaster`. |
| [`Invariant`](../../kavach-node/npm/src/index.ts)                                          | `{ name, field, maxValue }` for the core invariant evaluator.                                           |
| [`PrincipalKind`](../../kavach-node/npm/src/index.ts)                                      | String union `'user' \| 'agent' \| 'service' \| 'scheduler' \| 'external'`.                               |
| [`Verdict`](../../kavach-node/npm/src/index.ts)                                            | Re-export of `VerdictResult` from the native engine.                                                     |
| [`PqTokenSigner`](../../kavach-node/npm/src/index.ts)                                      | Native token signer; `pqOnly` / `hybrid` factories, `sign`, `verify`, `isHybrid`.                        |
| [`KavachKeyPair`](../../kavach-node/npm/src/index.ts)                                      | Native PQ keypair; `generate`, `publicKeys`, `buildSignedManifest`.                                     |
| [`AuditEntry`](../../kavach-node/npm/src/index.ts)                                         | Native audit entry class.                                                                                 |
| [`SignedAuditChain`](../../kavach-node/npm/src/index.ts)                                   | Native chained audit log; `verifyJsonl(data, publicKeys, hybrid?)`.                                       |
| [`SecureChannel`](../../kavach-node/npm/src/index.ts)                                      | Native PQ secure channel; bytes-flow `sendSigned` / `receiveSigned`, `sendData` / `receiveData`.         |
| [`PublicKeyDirectory`](../../kavach-node/npm/src/index.ts)                                 | Unified directory class; `inMemory`, `fromFile`, `fromSignedFile`, `buildSignedManifest` factories.      |
| [`DirectoryTokenVerifier`](../../kavach-node/npm/src/index.ts)                             | Async verifier wrapping `Arc<Inner>`.                                                                     |
| [`KavachRefused`](../../kavach-node/npm/src/index.ts)                                      | Error thrown by `Gate.check` on Refuse; carries `reason`, `evaluator`, `code`.                           |
| [`KavachInvalidated`](../../kavach-node/npm/src/index.ts)                                  | Error thrown by `Gate.check` on Invalidate.                                                               |
| [`InMemoryInvalidationBroadcaster`](../../kavach-node/npm/src/index.ts)                    | In-process broadcaster; pass to `GateOptions.broadcaster` and pair with `spawnInvalidationListener`.       |
| [`spawnInvalidationListener`](../../kavach-node/npm/src/index.ts)                          | Spawns a listener that invokes a callback on every `InvalidationScopeView`; returns `InvalidationListenerHandle`. |
| [`InvalidationListenerHandle`](../../kavach-node/npm/src/index.ts)                         | Handle with `.abort()` to stop the listener.                                                              |

Note: the native-engine type aliases `AuditEntryOptions`, `GeoLocationInput`, `PermitTokenInput`, `PermitTokenView`, `PublicKeyBundleView`, `VerdictResult`, `ActionContextInput` are also re-exported (or consumed internally) from [kavach-node/npm/src/index.ts](../../kavach-node/npm/src/index.ts).

---

## `kavach-redis`

Re-exported from [kavach-redis/src/lib.rs](../../kavach-redis/src/lib.rs). Single-node Redis backends for the three pluggable traits in `kavach-core`.

| Type                                                                    | Purpose                                                                                                |
| ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| [`RedisRateLimitStore`](../../kavach-redis/src/rate_limit.rs)           | `RateLimitStore` backed by Redis sorted sets for sliding-window counts; non-atomic record+count (matches in-memory semantics). |
| [`RedisSessionStore`](../../kavach-redis/src/session_store.rs)          | `SessionStore` that serializes sessions as JSON with Redis TTL.                                         |
| [`RedisInvalidationBroadcaster`](../../kavach-redis/src/broadcaster.rs) | `InvalidationBroadcaster` over Redis Pub/Sub, bridged into a local `tokio::sync::broadcast`.            |
| [`RedisBroadcasterError`](../../kavach-redis/src/broadcaster.rs)        | Error type emitted by the broadcaster.                                                                  |

All three accept either a pre-built `redis::Client` (via `new`) or a URL string (via `from_url`); internally they use `redis::aio::ConnectionManager` for auto-reconnect. No cluster-mode, Sentinel, or Lua-script support.

---

## See also

- [policy-language.md](policy-language.md), complete TOML grammar reference.
- [concepts/gate-and-verdicts.md](../concepts/gate-and-verdicts.md), how `Gate` turns context into `Verdict`.
- [concepts/evaluators.md](../concepts/evaluators.md), how custom evaluators slot in.
- [concepts/post-quantum.md](../concepts/post-quantum.md), the PQ primitives behind `kavach-pq`.
- [concepts/audit.md](../concepts/audit.md), chained audit logs.
- [concepts/key-management.md](../concepts/key-management.md), `PublicKeyDirectory` and `KavachKeyPair`.
- [guides/distributed.md](../guides/distributed.md), wiring `kavach-redis` into a multi-node deployment.
