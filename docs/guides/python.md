# Python integration guide

The Python SDK is a thin PyO3 wrapper over the compiled Rust engine. Every `evaluate()` call crosses FFI into `kavach-core`; none of the gate logic runs in Python. This guide covers what lives above that boundary: the idiomatic wrappers, decorators, and PQ crypto surface exposed from the `kavach` package.

For the Rust surface underneath, see [rust.md](rust.md). For the TypeScript equivalent, see [typescript.md](typescript.md). For the operator-edited TOML workflow, see [toml-policies.md](toml-policies.md).

---

## Install

```bash
pip install kavach-sdk
```

Wheels are abi3, so a single wheel per platform covers CPython 3.10, 3.11, 3.12, and every future Python. Linux x86_64/aarch64, macOS x86_64/arm64, and Windows x64 are supported.

---

## First call

```python
from kavach import ActionContext, Gate

# Policy as a native Python dict. No separate config format to learn.
POLICY = {
    "policies": [
        {
            "name": "agent_small_refunds",
            "effect": "permit",
            "conditions": [
                {"identity_kind": "agent"},
                {"action": "issue_refund"},
                {"param_max": {"field": "amount", "max": 1000.0}},
            ],
        },
    ],
}

gate = Gate.from_dict(POLICY, invariants=[("hard_cap", "amount", 50_000.0)])

ctx = ActionContext(
    principal_id="agent-bot",
    principal_kind="agent",
    action_name="issue_refund",
    params={"amount": 500.0},
)

verdict = gate.evaluate(ctx)
if verdict.is_permit:
    print("permit", verdict.token_id)
else:
    print(f"blocked: [{verdict.code}] {verdict.evaluator}: {verdict.reason}")
```

An empty policy set is valid. It default-denies everything, which is useful as a kill-switch.

---

## Constructing a `Gate`

Five factories, all taking the same keyword options. Pick whichever fits how you store or generate policies; they all produce identical behavior.

```python
from kavach import Gate

gate = Gate.from_dict(policy_dict, ...)          # native Python dict (recommended)
gate = Gate.from_json_string(json_string, ...)   # JSON string (wire body)
gate = Gate.from_json_file("kavach.json", ...)   # JSON file on disk
gate = Gate.from_toml(toml_string, ...)          # operator-edited TOML string
gate = Gate.from_file("kavach.toml", ...)        # TOML file on disk
```

All five share the same condition vocabulary; see [../reference/policy-language.md](../reference/policy-language.md) for the full grammar. Typo'd or unknown field names raise a clear `ValueError` in every loader. Example:

```python
gate = Gate.from_dict({
    "policies": [
        {
            "name": "agent_small_refunds",
            "effect": "permit",
            "conditions": [
                {"identity_kind": "agent"},
                {"action": "issue_refund"},
                {"param_max": {"field": "amount", "max": 5000.0}},
                {"rate_limit": {"max": 50, "window": "24h"}},
            ],
        },
    ],
})
```

For programmatic policy construction (admin UI submissions, database rows, feature flags), `from_dict` is the cleanest path: build the dict however you like, hand it to the gate, no string templating. For policies operators hand-edit and commit to git, use the TOML loaders; see [toml-policies.md](toml-policies.md).

Keyword arguments:

| Arg | Type | Notes |
|-----|------|-------|
| `invariants` | `list[tuple[str, str, float]]` | `(name, field, max_value)` triples, applied as `param_max` invariants that always run after policy. |
| `observe_only` | `bool` | Gate logs verdicts but never blocks. Use for Phase 1 rollout. |
| `max_session_actions` | `int \| None` | Hard cap on actions per session. |
| `enable_drift` | `bool` | Default `True`. Attaches `DriftEvaluator::with_defaults()`. |
| `token_signer` | `PqTokenSigner \| None` | Signs every Permit; sign failures fail closed (Refuse). |
| `geo_drift_max_km` | `float \| None` | Enables tolerant-mode `GeoLocationDrift`. Missing geo with a threshold set still fails closed. |
| `rate_store` | `RedisRateLimitStore \| None` | Swaps the default in-memory rate counter for a Redis-backed one that stays consistent across service replicas. Redis errors fail closed. See [Distributed deployments](#distributed-deployments). |
| `broadcaster` | `InMemoryInvalidationBroadcaster \| RedisInvalidationBroadcaster \| None` | Publishes every `Invalidate` verdict so peer nodes can drop the session locally. Publish failures never downgrade the local verdict. |

---

## Building an `ActionContext`

`ActionContext` accepts flat keyword arguments and builds a full Rust-side context (principal, action, session, env) underneath.

```python
from kavach import ActionContext, GeoLocation

ctx = ActionContext(
    principal_id="alice",
    principal_kind="user",            # user | agent | service | scheduler | external
    action_name="issue_refund",
    roles=["support"],                 # optional
    resource="orders/ORD-42",          # optional
    params={"amount": 1_500.0},        # numeric values only, for invariants/policy
    ip="10.0.0.1",                     # current IP
    session_id="00000000-0000-0000-0000-000000000001",
    origin_ip="10.0.0.1",              # IP at session start
    current_geo=GeoLocation("IN", city="Chennai",   latitude=13.08, longitude=80.27),
    origin_geo =GeoLocation("IN", city="Bangalore", latitude=12.97, longitude=77.59),
)
```

Only numeric `params` survive the crossing. Everything else is dropped silently since policy and invariants operate on numeric thresholds. String parameters should live in `resource`.

---

## Evaluating and raising

Three APIs, picked by call style:

```python
verdict = gate.evaluate(ctx)        # returns Verdict
verdict.is_permit                    # bool
verdict.is_refuse                    # bool
verdict.is_invalidate                # bool
verdict.code                         # e.g. "POLICY_DENIED"
verdict.evaluator                    # which evaluator decided
verdict.reason                       # human-readable
verdict.token_id                     # on Permit
verdict.permit_token                 # PermitToken (full PQ-friendly view)
verdict.signature                    # bytes, populated when token_signer is set
```

```python
gate.check(ctx)                      # raises Refused / Invalidated on block
```

Catch the exception types at the top level:

```python
from kavach import Refused, Invalidated

try:
    gate.check(ctx)
except Refused as e:
    print(f"refused by {e.evaluator} ({e.code}): {e.reason}")
except Invalidated as e:
    # Session revoked. Kill session state, force re-auth.
    print(f"invalidated by {e.evaluator}: {e.reason}")
```

---

## Decorator: `@guarded`

Wraps an ordinary function with a gate check. Special `_`-prefixed kwargs become the context; they are stripped before the wrapped function runs.

```python
from kavach import guarded

@guarded(gate, action="issue_refund", param_fields={"amount": "amount"})
async def issue_refund(order_id: str, amount: float) -> dict:
    # Only runs if the gate permits.
    return {"status": "refunded", "order_id": order_id, "amount": amount}

result = await issue_refund(
    "ORD-123", 500.0,
    _principal_id="agent-bot",
    _principal_kind="agent",
    _roles=["support"],
    _ip="10.0.0.1",
    _session_id="sess-1",
)
```

`param_fields` maps gate-side parameter names to function argument names. Only `int` and `float` values are forwarded as params (other types are silently dropped, matching the numeric-only `ActionContext.params` contract).

Both async and sync functions are supported; the decorator returns the matching wrapper shape.

---

## Signed permit tokens: `PqTokenSigner`

Attach a signer to a gate, and every Permit verdict gets a signed envelope. Sign failures fail closed.

```python
from kavach import Gate, PermitToken, PqTokenSigner

signer = PqTokenSigner.generate_hybrid()   # ML-DSA-65 + Ed25519
# signer = PqTokenSigner.generate_pq_only()  # ML-DSA-65 only

gate = Gate.from_dict(POLICY, token_signer=signer)
verdict = gate.evaluate(ctx)

if verdict.is_permit:
    pt = verdict.permit_token
    token = PermitToken(
        token_id=pt.token_id,
        evaluation_id=pt.evaluation_id,
        issued_at=pt.issued_at,
        expires_at=pt.expires_at,
        action_name=pt.action_name,
    )
    signer.verify(token, pt.signature)   # raises ValueError on tamper/wrong-key/downgrade
```

A hybrid signer signs with both ML-DSA and Ed25519. Hybrid verifiers reject PQ-only envelopes (signature-downgrade defense); PQ-only verifiers reject hybrid envelopes.

---

## Key pairs: `KavachKeyPair.generate()`

```python
from kavach import KavachKeyPair

kp = KavachKeyPair.generate()                   # no expiry
short = KavachKeyPair.generate_with_expiry(3600)  # 1-hour lifetime

assert kp.id                       # UUID string, also the signer key_id
assert kp.created_at > 0           # unix seconds
assert kp.expires_at is None       # short.expires_at is an int
assert kp.is_expired is False
```

`KavachKeyPair.public_keys()` returns a shareable `PublicKeyBundle`:

```python
bundle = kp.public_keys()
bundle.id                         # matches kp.id
bundle.ml_dsa_verifying_key       # ~1952 bytes, PQ signature VK
bundle.ed25519_verifying_key      # 32 bytes
bundle.x25519_public_key          # 32 bytes, KEM recipient
bundle.ml_kem_encapsulation_key   # ML-KEM-768 EK
```

Build a signer directly from a keypair:

```python
PqTokenSigner.from_keypair_hybrid(kp)
PqTokenSigner.from_keypair_pq_only(kp)
```

A verifier-only signer (no signing key material) is also supported via `PqTokenSigner.pq_only(ml_dsa_signing_key=b"", ml_dsa_verifying_key=bundle.ml_dsa_verifying_key, key_id=kp.id)`.

---

## Persisting signer identity across restarts

In v0.1.0, `KavachKeyPair` does not expose secret-byte serialization. A keypair you generate inside the Python SDK lives in process memory only; on restart, a fresh keypair has a fresh `key_id` and the public bundle changes. There are two ways to live with this:

### Pattern B (recommended for v0.1.0): regenerate at boot, redistribute the public bundle

Generate a fresh keypair on every gate-process boot, attach it to the gate, and push the public bundle to your verifier pool through whatever distribution path you operate (a config service, a Kubernetes ConfigMap, a `PublicKeyDirectory` file, etc.).

```python
kp     = KavachKeyPair.generate()
signer = PqTokenSigner.from_keypair_hybrid(kp)
gate   = Gate.from_dict(POLICY, token_signer=signer)

distribute_to_verifiers(kp.public_keys())   # your code
```

Verifiers should accept multiple bundles in their `PublicKeyDirectory` and resolve by the `key_id` stamped on each envelope. Old bundles can be retired once permits issued under them have expired (default permit TTL is 30 seconds).

This is the only pattern fully reachable through the published Python SDK on its own. It is acceptable for single-tenant deployments and any setup where verifiers refresh within seconds of a gate-process restart.

### Pattern A: provision raw key bytes from your KMS / HSM

The lowest-level `PqTokenSigner.hybrid(...)` constructor accepts raw bytes:

```python
signer = PqTokenSigner.hybrid(
    ml_dsa_sk, ml_dsa_vk,
    ed_sk, ed_vk,
    key_id="kavach-prod-2026",
)
gate = Gate.from_dict(POLICY, token_signer=signer)
```

This gives stable identity across restarts, but presumes you have a non-Kavach path that emits ML-DSA-65 key material interoperable with `kavach-pq` (an HSM with native ML-DSA-65 support, for example). Do not install third-party Python PQ-crypto libraries (`pqcrypto`, `ml-dsa`, `pyca/cryptography`, etc.) to mint these bytes for use with Kavach; interoperability has not been validated and is not guaranteed.

Adding `KavachKeyPair` byte serialization so Pattern A reaches stable identity through the SDK alone is tracked on the [roadmap](../roadmap.md).

---

## Public key directory

Three factory styles, one unified class. The three variants have identical `fetch(key_id)` semantics; only management differs.

```python
from pathlib import Path
from kavach import (
    DirectoryTokenVerifier, KavachKeyPair, PublicKeyBundle, PublicKeyDirectory,
)

# In-memory, supports insert / remove.
dir_im = PublicKeyDirectory.in_memory([bundle_a, bundle_b])
dir_im.insert(bundle_c)
dir_im.remove(kp_a.id)
dir_im.reload()    # no-op; kept so callers are polymorphic across variants

# Plain JSON manifest on disk, fetch works, mutations raise.
Path("bundles.json").write_bytes(
    PublicKeyDirectory.build_unsigned_manifest([bundle_a, bundle_b]),
)
dir_file = PublicKeyDirectory.from_file("bundles.json")
dir_file.reload()  # re-reads the file

# Root-signed manifest on disk, tamper-evident.
signing_key = KavachKeyPair.generate()
signed = signing_key.build_signed_manifest([bundle_a, bundle_b])
Path("directory.json").write_bytes(signed)

dir_signed = PublicKeyDirectory.from_signed_file(
    "directory.json",
    root_ml_dsa_verifying_key=signing_key.public_keys().ml_dsa_verifying_key,
)
```

Mount any directory into a `DirectoryTokenVerifier` for downstream verification:

```python
verifier = DirectoryTokenVerifier(dir_signed, hybrid=True)
verifier.verify(token, signature)   # raises ValueError on any failure
```

Every error path (`NotFound`, `BackendUnavailable`, `RootSignatureInvalid`, `Corrupt`, `EnvelopeParse`, `AlgorithmMismatch`, `SignatureInvalid`) maps to `ValueError`. Missing keys fail closed, not silently.

---

## Signed audit chain

Append-only, tamper-evident audit. ML-DSA-signed per entry; `verify` runs both the per-entry signature and the mode check.

```python
from kavach import AuditEntry, KavachKeyPair, SignedAuditChain

kp = KavachKeyPair.generate()
chain = SignedAuditChain(kp, hybrid=True)

chain.append(AuditEntry("agent-alice", "issue_refund", "permit", "token=abc"))
chain.append(AuditEntry("agent-bob",   "issue_refund", "refuse", "[POLICY_DENIED] no match"))
chain.append(AuditEntry("agent-bob",   "delete_customer", "invalidate", "drift detected"))

chain.verify(kp.public_keys())
assert chain.length == 3
assert chain.head_hash != "genesis"

# Portable JSONL for off-node storage.
blob = chain.export_jsonl()
SignedAuditChain.verify_jsonl(blob, kp.public_keys())             # mode inferred
SignedAuditChain.verify_jsonl(blob, kp.public_keys(), hybrid=True) # strict assertion
```

A PQ-only verifier presented with a hybrid blob is rejected (silent-downgrade defense). Passing `hybrid=False` explicitly on a hybrid blob raises.

---

## Secure channel (bytes flow)

Hybrid-encrypted, PQ-signed byte channel between two peers. Sealed payloads are opaque JSON envelopes; ship them over any transport.

```python
from kavach import KavachKeyPair, SecureChannel

alice = KavachKeyPair.generate()
bob   = KavachKeyPair.generate()

alice_ch = SecureChannel(alice, bob.public_keys())
bob_ch   = SecureChannel(bob,   alice.public_keys())

sealed = alice_ch.send_signed(b"permit: issue_refund", context_id="issue_refund", correlation_id="eval-1")
payload = bob_ch.receive_signed(sealed, expected_context_id="issue_refund")
assert payload == b"permit: issue_refund"

# Unsigned helper for cases where the caller signs its own payload.
enc = alice_ch.send_data(b"opaque")
raw = bob_ch.receive_data(enc)
```

Replay, ciphertext tamper, wrong recipient, wrong expected context, and unsigned-into-`receive_signed` all raise `ValueError`.

---

## Distributed deployments

The default `Gate` uses in-process stores: rate-limit counters, session state, and invalidation bookkeeping all live in the current Python process. That is fine for a single pod, wrong for anything behind a load balancer with two or more replicas.

Kavach exposes pluggable stores at both the in-memory tier (useful for tests and single-node) and the Redis tier (multi-replica production).

### Single-node, in-process

```python
from kavach import (
    Gate, InMemoryInvalidationBroadcaster, spawn_invalidation_listener,
)

broadcaster = InMemoryInvalidationBroadcaster()
gate = Gate.from_dict(POLICY, broadcaster=broadcaster)

# React to Invalidate verdicts from anywhere in the process.
handle = spawn_invalidation_listener(
    broadcaster,
    lambda scope: print(f"invalidated: {scope.target} ({scope.reason})"),
)
# ...
handle.abort()   # stop the listener on shutdown
```

`InvalidationScope` carries `.target` (a tagged union: session / principal / role), `.reason`, and `.evaluator`. Listener exceptions are caught and printed to stderr; they never kill the listener.

### Multi-replica with Redis

> **Experimental. Not yet thoroughly validated.**
>
> The `kavach-redis` crate has Rust-level integration tests, and the Python SDK exposes the three Redis-backed classes, but the consumer-validation harness at `business-tests/` does not yet cover the multi-replica path end to end. Early adopters can wire this up; treat it as a reference until validation lands, tracked in [../roadmap.md](../roadmap.md).

Spin up Redis (`docker run --rm -p 6379:6379 redis:7`) and point every replica at the same URL.

```python
from kavach import (
    Gate,
    RedisRateLimitStore, RedisInvalidationBroadcaster,
    spawn_invalidation_listener,
)

REDIS_URL = "redis://127.0.0.1:6379"

rate_store  = RedisRateLimitStore(REDIS_URL)
broadcaster = RedisInvalidationBroadcaster(REDIS_URL, channel="kavach:invalidation")

gate = Gate.from_dict(
    POLICY,
    rate_store=rate_store,
    broadcaster=broadcaster,
)

# Listener bridges the Redis Pub/Sub channel into your process: one per replica.
handle = spawn_invalidation_listener(broadcaster, lambda scope: None)
```

Semantic notes:

- **Rate-limit store failure fails closed.** A Redis outage during `record` refuses the action; a failure during `count_in_window` makes the rate-limit condition evaluate to `false`, which cascades to default-deny. Either way, Redis down is never "free refunds."
- **Broadcast failure never downgrades the local verdict.** The local `Invalidate` stands; peers missing the publish pick up the state next time they read the shared session store.
- **Connect timeout is 5 s.** A bad Redis URL surfaces as `ValueError("redis connect timed out after 5s")` within seconds rather than hanging forever.

For the full multi-node wiring (session resolvers, Rust-level reconnect behaviour), see [distributed.md](distributed.md).

---

## Hot reload

```python
gate.reload(new_policy_toml)
```

`reload` accepts a TOML string. Parse errors raise `ValueError`; the previous good set stays in place. Empty TOML is valid and default-denies. For the full reload workflow (including the file-watcher pattern and the empty-TOML kill switch), see [toml-policies.md](toml-policies.md).

---

## End-to-end script

A standalone script that exercises policy, invariants, decorators, signed tokens, audit chain, directory, and secure channel. Drop it anywhere and run it with the SDK installed.

```python
#!/usr/bin/env python3
"""Kavach Python SDK end-to-end walkthrough."""
from __future__ import annotations
import asyncio
import uuid
from pathlib import Path

from kavach import (
    ActionContext, AuditEntry, DirectoryTokenVerifier, Gate, GeoLocation,
    KavachKeyPair, PermitToken, PqTokenSigner, PublicKeyDirectory,
    SecureChannel, SignedAuditChain, guarded,
)
from kavach import Invalidated, Refused


POLICY = {
    "policies": [
        {
            "name": "support_small_refunds",
            "effect": "permit",
            "conditions": [
                {"identity_role": "support"},
                {"action": "issue_refund"},
                {"param_max": {"field": "amount", "max": 5000.0}},
            ],
        },
        {
            "name": "allow_fetch_report",
            "effect": "permit",
            "conditions": [
                {"action": "fetch_report"},
            ],
        },
    ],
}


async def main() -> None:
    # 1. Signed gate.
    signer = PqTokenSigner.generate_hybrid()
    gate = Gate.from_dict(
        POLICY,
        invariants=[("hard_cap", "amount", 10_000.0)],
        token_signer=signer,
        geo_drift_max_km=500.0,
    )

    # 2. Direct evaluate, permit path.
    ctx = ActionContext(
        principal_id="agent-alice",
        principal_kind="agent",
        action_name="issue_refund",
        roles=["support"],
        params={"amount": 1500.0},
    )
    v = gate.evaluate(ctx)
    assert v.is_permit
    pt = v.permit_token
    signer.verify(PermitToken(
        token_id=pt.token_id, evaluation_id=pt.evaluation_id,
        issued_at=pt.issued_at, expires_at=pt.expires_at,
        action_name=pt.action_name,
    ), pt.signature)

    # 3. Invariant override: policy would permit, but invariant caps amount.
    big = ActionContext(
        principal_id="agent-alice", principal_kind="agent",
        action_name="issue_refund", roles=["support"],
        params={"amount": 25_000.0},
    )
    assert gate.evaluate(big).is_refuse

    # 4. Decorator wrapping a real function.
    @guarded(gate, action="issue_refund", param_fields={"amount": "amount"})
    async def issue_refund(order_id: str, amount: float) -> dict:
        return {"status": "refunded", "order_id": order_id, "amount": amount}

    result = await issue_refund(
        "ORD-1", 500.0,
        _principal_id="agent-alice",
        _principal_kind="agent",
        _roles=["support"],
    )
    print("decorator result:", result)

    try:
        await issue_refund(
            "ORD-2", 999_999.0,
            _principal_id="agent-alice", _principal_kind="agent", _roles=["support"],
        )
    except Refused as e:
        print("decorator blocked:", e)

    # 5. Geo drift plumbing.
    blr = GeoLocation("IN", city="Bangalore", latitude=12.97, longitude=77.59)
    chn = GeoLocation("IN", city="Chennai",   latitude=13.08, longitude=80.27)
    v_geo = gate.evaluate(ActionContext(
        principal_id="alice", principal_kind="user",
        action_name="fetch_report",
        ip="10.0.0.1", origin_geo=blr, current_geo=chn,
    ))
    print("tolerant geo verdict:", "permit" if v_geo.is_permit else "blocked")

    # 6. Signed audit chain.
    kp = KavachKeyPair.generate()
    chain = SignedAuditChain(kp, hybrid=True)
    chain.append(AuditEntry("agent-alice", "issue_refund", "permit", "token=abc"))
    chain.append(AuditEntry("agent-alice", "issue_refund", "refuse", "over cap"))
    chain.verify(kp.public_keys())
    blob = chain.export_jsonl()
    SignedAuditChain.verify_jsonl(blob, kp.public_keys())

    # 7. Directory + DirectoryTokenVerifier.
    root = KavachKeyPair.generate()
    signed_manifest = root.build_signed_manifest([kp.public_keys()])
    Path("/tmp/kavach-directory.json").write_bytes(signed_manifest)
    directory = PublicKeyDirectory.from_signed_file(
        "/tmp/kavach-directory.json",
        root_ml_dsa_verifying_key=root.public_keys().ml_dsa_verifying_key,
    )
    svc_signer = PqTokenSigner.from_keypair_hybrid(kp)
    tok = PermitToken(
        token_id=str(uuid.uuid4()),
        evaluation_id=str(uuid.uuid4()),
        issued_at=1_700_000_000,
        expires_at=1_700_000_030,
        action_name="issue_refund",
    )
    sig = svc_signer.sign(tok)
    verifier = DirectoryTokenVerifier(directory, hybrid=True)
    verifier.verify(tok, sig)
    print("directory-backed verify ok")

    # 8. Secure channel.
    alice = KavachKeyPair.generate()
    bob   = KavachKeyPair.generate()
    alice_ch = SecureChannel(alice, bob.public_keys())
    bob_ch   = SecureChannel(bob, alice.public_keys())
    sealed = alice_ch.send_signed(b"hello bob", context_id="greet", correlation_id="c-1")
    plaintext = bob_ch.receive_signed(sealed, expected_context_id="greet")
    assert plaintext == b"hello bob"
    print("secure channel roundtrip ok")

    # 9. Hot reload.
    gate.reload("")                    # default-deny everything
    assert gate.evaluate(ctx).is_refuse
    # Re-hydrate back into the full policy set from the dict form.
    gate2 = Gate.from_dict(POLICY, invariants=[("hard_cap", "amount", 10_000.0)])
    assert gate2.evaluate(ctx).is_permit
    print("reload roundtrip ok")


if __name__ == "__main__":
    asyncio.run(main())
```

For a multi-service runnable example (agent + payment service, 15 scenarios), see `Kavach/e2e-tests/runner.py`. The smoke test at `Kavach/kavach-py/python/tests/smoke_test.py` is the authoritative reference for every SDK surface.

---

## Next

- [../concepts/gate-and-verdicts.md](../concepts/gate-and-verdicts.md): Permit / Refuse / Invalidate semantics.
- [../concepts/post-quantum.md](../concepts/post-quantum.md): what hybrid means, and why.
- [../concepts/audit.md](../concepts/audit.md): SignedAuditChain internals.
- [toml-policies.md](toml-policies.md): operator-edited TOML workflow.
- [distributed.md](distributed.md): multi-node deployments.
- [../reference/policy-language.md](../reference/policy-language.md): full condition reference.
