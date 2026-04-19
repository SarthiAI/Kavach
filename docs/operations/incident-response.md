# Incident response

Playbooks for the four incidents you will actually see in production. Each one maps to a scenario exercised end-to-end in [e2e-tests/hard_runner.py](../../e2e-tests/hard_runner.py), which is a good place to read if you want to see the exact sequence run against a live service.

1. [Key compromise](#1-key-compromise): rotate the signing keypair, reissue the signed directory, verifiers reload, pre-rotation permits are rejected.
2. [Permissive policy shipped by mistake](#2-permissive-policy-shipped-by-mistake): roll forward with `Gate::reload`, kill-switch with an empty TOML.
3. [Session-level compromise](#3-session-level-compromise): the `Invalidate` verdict propagates across nodes via the invalidation broadcaster.
4. [Audit tamper suspected](#4-audit-tamper-suspected): run `verify_jsonl` against the known-good public bundle and triage the error variants.

Cross-links:

- [SECURITY.md](../../SECURITY.md) for the threat model that frames these.
- [operations/deployment-patterns.md](deployment-patterns.md) for the topologies each playbook assumes.
- [operations/observability.md](observability.md) for the tracing events that detect these incidents.
- [concepts/key-management.md](../concepts/key-management.md) and [concepts/audit.md](../concepts/audit.md) for the underlying primitives.

---

## 1. Key compromise

**Signal:** the agent's signing key is known or suspected compromised. Any `PermitToken` signed by that key can no longer be trusted.

**Invariant Kavach gives you:** every verifier is a `DirectoryTokenVerifier` backed by a `PublicKeyDirectory`. Tokens are rejected if their `key_id` is not present in the directory. Rotating = removing the old `key_id` from the signed directory, then making every verifier reload it.

**Playbook:**

### Step 1: generate a new agent keypair

```python
from kavach import KavachKeyPair

k2 = KavachKeyPair.generate()
print("new key_id =", k2.public_keys().id)
```

### Step 2: rebuild the signed manifest from your root keypair

The root keypair is the pinned ML-DSA-65 key that verifiers trust. Every verifier was bootstrapped with its root verifying key (`root.vk`). Only the root can produce a signed manifest that verifiers will load.

```python
# `root_kp` is your root KavachKeyPair, kept offline / in an HSM.
# Include only the keys you want verifiers to accept.
new_manifest_bytes = root_kp.build_signed_manifest([k2.public_keys()])

# Ship this manifest to the distribution target (shared volume,
# HTTP server, config map, etc.).
open("/srv/kavach/directory.signed.json", "wb").write(new_manifest_bytes)
```

`hard_runner.py::s03_key_rotation` does exactly this, and the assertion that follows the rotation requires every previously-captured K1 permit to be rejected:

```python
# from hard_runner.py, abbreviated
k2 = KavachKeyPair.generate()
new_manifest = ctx.root_kp.build_signed_manifest([k2.public_keys()])
ctx.bootstrap_.directory_path.write_bytes(new_manifest)
# ... then POST /admin/reload_directory on every verifier ...
```

### Step 3: tell every verifier to reload

`FilePublicKeyDirectory` exposes `.reload()`; `HttpPublicKeyDirectory` *(experimental, validation pending; see [roadmap.md](../roadmap.md))* will pick up the new manifest on its next scheduled refresh (ETag busts to a full 200). For a file-backed setup the fastest path is a reload endpoint your service exposes:

```rust
// inside the verifier service
let reloaded = directory.reload();  // kavach_pq::FilePublicKeyDirectory::reload
if let Err(e) = reloaded {
    // NotFound / BackendUnavailable / RootSignatureInvalid / Corrupt -> keep the old one
    tracing::error!(error = %e, "directory reload failed, keeping previous manifest");
}
```

### Step 4: rotate the signing side

Swap the signer on the agent node to use K2:

```python
from kavach import PqTokenSigner
k2_signer = PqTokenSigner.from_keypair_hybrid(k2)
# ...rebuild the Gate with .with_token_signer(k2_signer) on the agent...
```

### Step 5: verify the rotation

Two behaviors must hold after Step 3 completes:

- Every permit signed by K1 that has not yet expired (Kavach permits are short-lived, default 30 s, but rotations typically happen before expiry for many in-flight permits) is rejected at the verifier. `DirectoryTokenVerifier::verify` returns a `KeyDirectoryError::NotFound` for the old `key_id`.
- A permit freshly signed by K2 is accepted. This is the sanity check that proves the rotation itself worked.

### Step 6: destroy the old key material

Only after you have confirmed Step 5. Once the old seed is destroyed, there is no going back.

### Watch for

- Verifiers running `HttpPublicKeyDirectory` log `key directory refresh failed` at `warn` and keep serving the stale cache. If the manifest server is slow to deploy, these verifiers keep accepting the OLD key until the refresh succeeds. On a real compromise, prefer file-backed distribution with an explicit reload.
- Verifiers that never reload will happily keep accepting K1 permits. Confirm each verifier reported success on its reload endpoint.

---

## 2. Permissive policy shipped by mistake

**Signal:** a policy change went live that permits more than intended. Refusal rates drop; the invariant evaluator starts catching things that should have been caught by policy first.

**Invariant Kavach gives you:** `PolicyEngine::reload` takes `&self`, is callable through an `Arc<PolicyEngine>` shared with a `Gate`, and swaps the policy set under an `RwLock` without interrupting in-flight evaluations. An empty `PolicySet` is valid and is the kill-switch: with no policies, every action hits default-deny.

### Option A: roll forward with a corrected policy

Ship a new `kavach.toml`, then call `reload`:

```rust
use kavach_core::{PolicyEngine, PolicySet};

let fixed = PolicySet::from_file("kavach.toml")?;   // or from_toml(&new_text)
policy_engine.reload(fixed);
```

From the Python SDK:

```python
gate.reload(fixed_toml)   # raises ValueError on parse error, previous set stays
```

From the Node SDK:

```typescript
gate.reload(fixedToml);   // throws on parse error, previous set stays
```

### Option B: kill-switch (empty policy)

If you cannot fix-forward fast enough, reload with an **empty TOML**. Empty is valid: `PolicySet::from_toml("")` produces a zero-rule set, and with no matching rules, `PolicyEngine` returns `Refuse { code: NoPolicyMatch }` for every action. The gate is effectively off for any action it can reach.

```python
gate.reload("")
```

From [hard_runner.py::s04_kill_switch](../../e2e-tests/hard_runner.py), the harness exercises this against a live service and asserts that between reload completion and the first post-reload refusal, the elapsed time is under 200 ms, with zero permits leaking through after reload:

```python
delta_ms = (timeline.first_refuse_after_reload_at - timeline.reload_completed_at) * 1000
ok = delta_ms < 200 and timeline.permits_after_reload == 0
```

That is the contract: a kill-switch is effective immediately on the reloading node, for the next evaluation that picks up the new snapshot. In-flight evaluations (already past the `find_matching_policy` read) finish on the old set; every subsequent call sees empty.

### File-watcher auto-reload

If you run with the `watcher` feature enabled on `kavach-core`, `spawn_policy_watcher(engine, path, debounce)` attaches a debounced file watcher. A parse error on the updated file does NOT wipe the existing policies; `PolicyEngine::reload` is only called on successful parse. So a typo in `kavach.toml` logs a warning and keeps the previous good set. A rolled-out empty TOML, however, is a valid parse and will apply.

### After the incident

- Capture the before/after policy diff.
- Add an invariant for any category of action the rogue policy permitted. The `InvariantSet` is in-code, not in TOML, and sits below policy in the evaluator chain. `hard_runner.py::s05_invariant_floor` demonstrates exactly this: a rogue admin policy permits up to ₹500,000; the `max_refund = 50,000` invariant refuses everything above that with the `invariants` evaluator as the attributed refuser.

---

## 3. Session-level compromise

> **Cross-node fan-out is experimental.** The local invalidation path is consumer-validated (it's exercised by `business-tests/` via `InMemoryInvalidationBroadcaster`), but the Redis-backed cross-node fan-out the playbook below assumes (`RedisInvalidationBroadcaster`, `spawn_session_store_listener` against a `RedisSessionStore`) is not yet covered by the consumer-validation harness. The Rust-level integration tests pass. Treat the multi-node portion of this playbook as a reference until validation lands; see [roadmap.md](../roadmap.md).

**Signal:** a session is known to be misbehaving, or an evaluator has emitted `Invalidate`. The local gate is already refusing; the concern is whether every *other* node holding the same session also stops honoring it.

**Invariant Kavach gives you:** when `Gate::evaluate` returns `Invalidate`, the scope is published through the attached `InvalidationBroadcaster`. Broadcast failures are logged but **never** downgrade the local verdict. Peers subscribe through `spawn_invalidation_listener` or `spawn_session_store_listener`, which apply the invalidation to their local `SessionStore`.

### Wire the listener once, at startup

```rust
use kavach_core::invalidation::{
    InvalidationBroadcaster, spawn_session_store_listener,
};
use kavach_core::session_store::SessionStore;
use std::sync::Arc;

// `broadcaster` is the same Arc you gave the Gate (e.g. RedisInvalidationBroadcaster).
// `session_store` is the same Arc your HTTP/MCP layer uses to look up sessions.
let handle = spawn_session_store_listener(
    broadcaster.clone(),
    session_store.clone(),
);

// Hold the JoinHandle alongside the rest of your service state. Drop = don't abort:
// call `handle.abort()` during shutdown.
```

`spawn_session_store_listener` iterates every incoming `InvalidationScope`:

- `InvalidationTarget::Session(uuid)`: looks up the session by UUID string, sets `invalidated = true`, writes it back. Fails safe: `get`/`put` errors log but do not panic the listener.
- `InvalidationTarget::Principal(id)` and `InvalidationTarget::Role(role)`: logged as `info` with an "integrator must handle" hint. The trait cannot iterate sessions generically, so scope-by-principal or scope-by-role invalidation is integrator-specific. Pair those targets with a custom handler via `spawn_invalidation_listener` if you need them.

### When a compromise is detected

Two paths:

1. **The gate detected it.** A drift evaluator or invariant emits `Invalidate`; the gate publishes the scope; listeners on every node mark the session invalidated in their store; the next evaluation on any node sees `session.invalidated = true` and refuses at the gate entry with `code: SessionInvalid`. No further action is required of the operator.
2. **You detected it out of band.** Publish manually:

```rust
use kavach_core::verdict::{InvalidationScope, InvalidationTarget};

broadcaster
    .publish(InvalidationScope {
        target: InvalidationTarget::Session(compromised_uuid),
        reason: "manual: credential leak suspected".into(),
        evaluator: "operator".into(),
    })
    .await?;
```

### What to check during the incident

- Log target `kavach_core::gate` for `"authority invalidated"`. Correlate the scope across nodes.
- Log target `kavach_core::invalidation` for `invalidation subscriber lagged`. A lagged listener missed some invalidations; it will keep running, but you should re-sync the affected node's session store from an authoritative source.
- Log target `kavach_core::gate` for `invalidation broadcast failed`. The broadcaster (Redis, etc.) is down. Local node is fine, peers were not notified. Fix the broadcaster and re-publish the scope if the compromise is still active.

### After the incident

- If `Principal` or `Role` invalidation was needed and your current listener only handles `Session`, add a custom handler via `spawn_invalidation_listener`.
- If the broadcaster was flaky, consider whether you need a durable replay log (broadcasters are best-effort; Pub/Sub is not a queue).

---

## 4. Audit tamper suspected

**Signal:** someone had write access to the audit store, or the chain is being exported to a third party who must be shown the record is intact. You need to verify the chain still hashes and signs cleanly.

**Invariant Kavach gives you:** `SignedAuditChain::verify_jsonl` (or `kavach_pq::audit::verify_chain` in Rust) walks every entry and enforces:

1. Chain mode is consistent across entries (no PQ-only entries mixed with hybrid; splice detection via `detect_mode`).
2. The verifier's mode matches the chain's mode (no downgrade: a PQ-only verifier cannot accept a hybrid chain, and vice versa).
3. Every signature (ML-DSA-65, plus Ed25519 in hybrid mode) validates.
4. Every hash-chain link is correct.
5. Indices are sequential: no gaps or duplicates.

Any failure raises a `PqError::AuditChainBroken { index, reason }` naming the entry and the specific problem.

### Step 1: verify against the known-good public bundle

```python
from kavach import SignedAuditChain

chain_bytes = open("audit.jsonl", "rb").read()
try:
    SignedAuditChain.verify_jsonl(
        chain_bytes,
        agent_public_bundle,     # the PublicKeyBundle from the signer
        hybrid=True,             # or False for PQ-only chains
    )
    print("clean")
except Exception as err:
    print("tampered:", err)
```

Rust equivalent:

```rust
use kavach_pq::audit::{parse_jsonl, verify_chain};
use kavach_pq::sign::Verifier;

let entries = parse_jsonl(&chain_bytes)?;
let verifier = Verifier::from_bundle(&agent_public_bundle, /* hybrid = */ true)?;
verify_chain(&entries, &verifier)?;
```

### Step 2: interpret the error

Every failure surfaces as `AuditChainBroken { index, reason }`. The `reason` string tells you which of the five checks failed. The five tamper variants exercised in [hard_runner.py::s06_audit_forensics](../../e2e-tests/hard_runner.py) map to the three root causes:

| Tamper | `reason` contains | Root cause |
|---|---|---|
| **Bit-flip inside an entry's signed payload** | `"signature verification failed: ..."` | The signed bytes changed; ML-DSA or Ed25519 signature no longer matches. Entry `index` identifies which entry. |
| **Deleted entry** | `"hash chain broken: expected '...', got '...'"` | The surviving entry's `previous_hash` does not match the hash of what the verifier expected at that index. |
| **Reordered entries** | `"hash chain broken: ..."` or `"expected index N, got M"` | Either the hash link breaks or the sequential-index check fires. |
| **Appended forged entry** | `"signature verification failed: ..."` or `"hash chain broken: ..."` | Signature never matches (attacker does not have the signing key) or the forged `previous_hash` is wrong. |
| **PQ-only entry spliced into a hybrid chain** | `"chain mode inconsistent: started as hybrid, entry is pq-only (possible splice)"` | `detect_mode` catches the mode mismatch before any crypto runs. Blocks downgrade attacks. |

The full list of error variants from `kavach_pq::error::PqError` that can surface through `verify_chain`:

- `AuditChainBroken { index, reason }`: the canonical failure mode. All five tamper patterns above resolve to this.
- `Serialization(_)`: a JSONL line did not parse as a `SignedAuditEntry`. Reported by `parse_jsonl` with `"parse failed at entry #N: ..."`. Entry `N` is the zero-based index of the failing entry, not the raw line number, so blank lines do not skew diagnostics.
- `VerificationFailed(_)`: the inner signature crate rejected the signature. Bubbled up as the `reason` on the `AuditChainBroken` that wraps it.

### Step 3: preserve the evidence

Do not mutate the tampered file. Copy it, hash the copy, keep both alongside the last known-good chain (if you have one, see below). The signed chain is the record; you want both the tampered and the untampered versions.

### Step 4: reconstruct the legitimate history

If you have an older export that verified cleanly, compare the tampered file's prefix to the good prefix. The `index` in the error tells you exactly where the tampering starts; everything strictly before that index with matching bytes is still trustworthy.

### Long-term prevention

- Sign and ship audit exports directly to append-only storage. The chain's own cryptographic integrity is your primary defense; write-once storage is the belt-and-suspenders.
- Run `verify_chain` as a scheduled job on exported chains so tampering is detected within hours, not weeks.
- Pin the signing key's `PublicKeyBundle` in your verifier config. A tamper accompanied by a swapped bundle (the attacker signs with their own key and pretends it is yours) is rejected by the `verifier/chain mode mismatch` and by the fact that the mismatched bundle's `key_id` will not match the pinned one.

---

## Running the hard suite

All four scenarios above are exercised end-to-end, with real HTTP services and real signing keys, by [e2e-tests/hard_runner.py](../../e2e-tests/hard_runner.py). If you are preparing incident-response runbooks for a team, have them run this suite locally first. Each `s0X_*` function is a working example of the corresponding playbook in code:

- `s01_mixed_role_concurrent`: concurrent load with a mid-run reload. Shows Option A of Section 2 under real traffic.
- `s02_permit_laundering`: 20+ permit tamper variants. Every variant 401s at the verifier; if any succeed, Section 1's invariants are broken.
- `s03_key_rotation`: full rotation sequence. Section 1, tested.
- `s04_kill_switch`: empty-TOML reload with timing assertion. Section 2 Option B, tested.
- `s05_invariant_floor`: rogue admin policy, invariant catches every over-cap refund. Section 2's "why invariants matter" in code.
- `s06_audit_forensics`: five tamper variants, all rejected. Section 4, tested.

Run it with the venv active:

```bash
source kavach-py/.venv/bin/activate
cd Kavach/e2e-tests && python hard_runner.py
```

A passing run means the four playbooks in this document are backed by live, working code.
