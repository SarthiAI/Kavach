# Security Policy

## Reporting a vulnerability

Please report security issues privately. **Do not open a public issue.**

**Email:** `support@sarthiai.com` with subject `[kavach-security] <short description>`.

Please include:

- A clear description of the issue and its impact.
- Steps to reproduce (proof-of-concept code preferred).
- The Kavach version, crate, and language SDK (Rust / Python / Node) affected.
- Any suggested remediation you've considered.

We will acknowledge your report within **72 hours** and aim to provide an initial assessment within **7 days**. We follow a **90-day coordinated disclosure** window by default, shortened if a fix ships sooner and extended only with your agreement for unusually complex issues.

Researchers who report in good faith will be credited in the release notes (or anonymously, at your preference).

---

## Supported versions

Kavach is pre-1.0. Only the latest `0.x` minor is supported for security fixes.

| Version | Status |
|---------|--------|
| `0.1.x` | Supported |
| older   | Not supported |

---

## In scope

The following categories are treated as security issues and fixed on the expedited timeline above.

### Gate bypass
Anything that causes an action to execute despite the gate returning a non-Permit verdict, or that allows a `Guarded<A>` to be constructed without passing through `Gate::guard` / `Gate::evaluate`.

### Signature forgery or downgrade
- Forging an ML-DSA-65 or Ed25519 signature on a `PermitToken`, `SignedAuditEntry`, or `SignedDirectoryManifest`.
- Tricking a hybrid verifier into accepting a PQ-only envelope (or vice versa). The algorithm whitelist must be strict in both directions.
- Any chain of events that causes `DirectoryTokenVerifier` to accept a token whose signing key isn't the one pinned in the directory.

### Audit chain tamper that verifies
Modifying, reordering, deleting, or splicing entries in a `SignedAuditChain` (including a chain exported as JSONL) such that `verify_chain` returns success. Mode-splicing (mixing PQ-only entries into a hybrid chain or vice versa) must fail closed; see `audit_chain_rejects_mode_downgrade` in [kavach-pq/tests/crypto_integration.rs](kavach-pq/tests/crypto_integration.rs).

### SecureChannel compromise
- Decryption by a recipient other than the one bound in `recipient_key_id` (AAD).
- Successful replay of a previously-received sealed payload.
- Cross-context replay: a payload sealed for one `context_id` being accepted under a different `context_id`, or a signed-verdict payload replayed through the signed-bytes verifier (the nonce cache is shared on purpose).

### Fail-closed regressions
Any change that causes Kavach to fail **open** where it previously failed **closed**:
- `TokenSigner::sign` error downgrading Permit to anything other than Refuse.
- `RateLimitStore::record` / `count_in_window` error allowing an action through.
- `GeoLocationDrift` tolerance mode silently passing when geo data is missing.
- `TimeWindow` or other `Condition::matches` parse errors evaluating to `true`.
- `InvalidationBroadcaster` failure affecting the local verdict (local Invalidate must still stand).

### FFI memory safety
Any UB, leaks, or memory-safety issues reachable from the Python or Node SDK public API, including double-frees, dangling references, or unsound `unsafe` blocks in the bindings.

### Cryptographic misuse
Nonce reuse, insufficient randomness (including any path that bypasses `getrandom` / `OsCryptoRng`), KDF output reuse across contexts, or misuse of the embedded `ml-dsa` / `ml-kem` / `x25519-dalek` / `ed25519-dalek` crates that weakens their documented guarantees.

---

## Out of scope

The following are **not** treated as Kavach vulnerabilities:

- **Misconfigured policies.** A permissive `[[policy]]` that lets agents do more than intended is a configuration issue, not a gate bypass.
- **Leaked keys.** ML-DSA seeds, Ed25519 secret keys, X25519 static secrets, or any other key material exposed by the integrator is not a Kavach bug. Key rotation and storage are the integrator's responsibility.
- **Denial of service via legitimate load.** Rate-limit stores, file watchers, and secure-channel nonce caches have finite capacity; overwhelming them via legitimately-signed traffic is a capacity concern.
- **Pre-1.0 API changes** that break integrators. These will be noted in release notes but are not security issues.
- **Dependencies' upstream vulnerabilities.** Report those to the respective maintainers. If a transitive CVE meaningfully affects Kavach we will pin or patch, but the underlying issue is not ours.
- **Social engineering, phishing, or supply-chain attacks on the integrator's deploy pipeline.**
- **Theoretical attacks** below published parameter sets for ML-DSA-65 / ML-KEM-768 / Ed25519 / X25519 / ChaCha20-Poly1305.

---

## Threat model

Kavach's design assumes:

1. **An attacker may obtain valid credentials.** Keys leak, API tokens get committed, agents get prompt-injected. The gate must evaluate *context*, not just *possession*.
2. **The integrator's application code is partially trusted.** It can skip the gate only where Rust's type system allows; in practice this is never, because `Guarded<A>` has no public constructor.
3. **Evaluators trust each other.** The policy engine, drift detectors, and invariant set are all in-process; a malicious evaluator is outside the threat model.
4. **Network transport is hostile.** `SecureChannel` assumes the wire is attacker-controlled. All sealed payloads are authenticated; replay is rejected.
5. **Stores may be distributed and flaky.** `RateLimitStore`, `SessionStore`, `InvalidationBroadcaster`, and `PublicKeyDirectory` are pluggable and may fail. Every error path is documented as fail-closed on the local verdict.
6. **Post-quantum is real.** Transport (`SecureChannel`) uses X25519 + ML-KEM-768 in hybrid. Signatures (`PermitToken`, audit chain, directory manifest) use Ed25519 + ML-DSA-65 in hybrid, with a PQ-only mode for environments that forbid classical crypto.

Not in the model:

- **Compromised host** with arbitrary memory access. If the attacker can read process memory, signing keys are exposed and no gate can help.
- **Malicious Rust crate in the dependency tree.** Supply-chain integrity is delegated to `cargo` and `cargo-audit`.
- **Side-channel attacks** on the embedded RustCrypto and dalek primitives. Mitigations there are the upstream crates' responsibility.

---

## Cryptographic primitives

| Purpose | Algorithm | Crate |
|---------|-----------|-------|
| Signature (PQ) | ML-DSA-65 | `ml-dsa = "=0.1.0-rc.8"` |
| Key encapsulation (PQ) | ML-KEM-768 | `ml-kem = "=0.3.0-rc.2"` |
| Signature (classical) | Ed25519 | `ed25519-dalek 2` |
| Key agreement (classical) | X25519 | `x25519-dalek 2` |
| AEAD | ChaCha20-Poly1305 | `chacha20poly1305` |
| Hash | SHA-256 | `sha2` |
| KDF | HKDF-SHA-256 | `hkdf` |
| RNG | OS `getrandom` | `getrandom` |

ML-DSA and ML-KEM are pinned to release-candidate versions. When stable releases ship we will update in a patch release and note it in the security-relevant section of the release notes.

---

## What Kavach does *not* protect against

- **The action itself being wrong.** A Permit verdict means *policy allows this action for this principal in this context*. It does not attest that the action's business logic is correct.
- **Integrator code that leaks the `Guarded<A>` outside its intended scope.** Guarded is move-only and uncloneable, but the integrator can still choose to store a permit and use it later. The gate is at the entrance, not every step.
- **Policy correctness.** A TOML policy set that permits too much will permit too much. Observe mode (`observe_only = true`) is the intended path for tuning before enforcing.

---

## Contact

Security-only: `support@sarthiai.com`.
