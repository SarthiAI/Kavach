# kavach

**Post-quantum execution boundary enforcement for AI agents, APIs, and distributed systems. Python SDK.**

Kavach separates *possession of credentials* from *permission to act*. Every action passes through a gate that evaluates identity, policy, drift, and invariants before producing a verdict. All evaluation runs in compiled Rust via PyO3; this package is the idiomatic Python wrapper.

```
Action attempted ──▶ Gate (identity · policy · drift · invariants) ──▶ Permit / Refuse / Invalidate
```

---

## Install

```bash
pip install kavach
```

Wheels are published as `abi3`. A single wheel per platform covers CPython 3.10, 3.11, 3.12, and every future Python. Linux x86_64/aarch64, macOS x86_64/arm64, and Windows x64 are supported.

---

## 60-second quickstart

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

gate = Gate.from_dict(
    POLICY,
    invariants=[("hard_cap", "amount", 50_000.0)],
)

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

A policy set with no matching permit Refuses by default. There is no implicit allow.

### Loading a policy

The recommended surface for Python is a native dict (admin UI submissions, database rows, feature flags):

```python
gate = Gate.from_dict(policy_dict)              # native dict (recommended)
gate = Gate.from_json_string(json_string)       # JSON over the wire
gate = Gate.from_json_file("kavach.json")       # JSON file on disk
```

For operator-owned config that lives in git and is hand-edited, use TOML:

```python
gate = Gate.from_toml(toml_string)              # operator-edited TOML
gate = Gate.from_file("kavach.toml")            # TOML file on disk
```

Typo'd field names (`{"idnetity_kind": "agent"}`) raise `ValueError` in every loader instead of being silently dropped, so a misspelled condition cannot quietly weaken a policy. The full TOML workflow (rendered in Rust, Python, and Node) lives at [docs/guides/toml-policies.md](https://github.com/SarthiAI/Kavach/blob/main/docs/guides/toml-policies.md).

---

## Decorator

```python
from kavach import guarded

@guarded(gate, action="issue_refund", param_fields={"amount": "amount"})
async def issue_refund(order_id: str, amount: float):
    return {"status": "refunded", "order_id": order_id, "amount": amount}

result = await issue_refund(
    "ORD-123", 500.0,
    _principal_id="bot", _principal_kind="agent",
)
```

Both async and sync functions are supported; the decorator returns the matching wrapper shape. Only numeric parameters are forwarded to the gate (the policy and invariant evaluators operate on numeric thresholds).

---

## Feature surface

### Signed permit tokens (`PqTokenSigner`)

When a `PqTokenSigner` is attached to a gate, every Permit verdict carries an ML-DSA-65 (or ML-DSA-65 + Ed25519 hybrid) signed envelope. Downstream services verify independently.

```python
from kavach import Gate, PqTokenSigner, PermitToken

signer = PqTokenSigner.generate_hybrid()
gate = Gate.from_dict(POLICY, token_signer=signer)

verdict = gate.evaluate(...)
if verdict.is_permit:
    token = PermitToken(
        token_id=verdict.permit_token.token_id,
        evaluation_id=verdict.permit_token.evaluation_id,
        issued_at=verdict.permit_token.issued_at,
        expires_at=verdict.permit_token.expires_at,
        action_name=verdict.permit_token.action_name,
    )
    assert signer.verify(token, verdict.permit_token.signature)
```

Hybrid (`generate_hybrid`) signs with both ML-DSA-65 and Ed25519; a hybrid verifier rejects PQ-only envelopes as a signature-downgrade guard.

### Key pairs

```python
from kavach import KavachKeyPair

kp = KavachKeyPair.generate()                  # no expiry
kp = KavachKeyPair.generate_with_expiry(3600)  # 1-hour lifetime

assert not kp.is_expired
bundle = kp.public_keys()   # PublicKeyBundle, safe to share
```

### Signed audit chain

Append-only, tamper-evident audit log. `verify` rejects tampered entries, wrong keys, and mode mismatches (e.g., a PQ-only verifier on a hybrid chain, which is a silent downgrade).

```python
from kavach import AuditEntry, SignedAuditChain

chain = SignedAuditChain(kp, hybrid=True)
chain.append(AuditEntry(
    principal_id="agent-bot",
    action_name="issue_refund",
    verdict="permit",
    verdict_detail="within policy",
))
chain.verify(kp.public_keys())

# Portable JSONL for off-node storage:
blob = chain.export_jsonl()
SignedAuditChain.verify_jsonl(blob, kp.public_keys())
```

### Secure channel

Hybrid-encrypted, PQ-signed byte channel between two peers. Sealed payloads are opaque; ship them over any transport.

```python
from kavach import SecureChannel

alice, bob = KavachKeyPair.generate(), KavachKeyPair.generate()
alice_ch = SecureChannel(alice, bob.public_keys())
bob_ch = SecureChannel(bob, alice.public_keys())

sealed = alice_ch.send_signed(b"hello bob", context_id="greeting")
plaintext = bob_ch.receive_signed(sealed, expected_context_id="greeting")
assert plaintext == b"hello bob"
```

Replay, cross-context, and wrong-recipient attacks all fail closed.

### Public key directory

```python
from kavach import PublicKeyDirectory, DirectoryTokenVerifier

# Root-signed manifest on disk (tamper-evident):
signing_key = KavachKeyPair.generate()
manifest = signing_key.build_signed_manifest([bundle_a, bundle_b])
Path("directory.json").write_bytes(manifest)

directory = PublicKeyDirectory.from_signed_file(
    "directory.json",
    root_ml_dsa_verifying_key=signing_key.public_keys().ml_dsa_verifying_key,
)

verifier = DirectoryTokenVerifier(directory, hybrid=True)
verifier.verify(token, signed_envelope)  # raises on tamper/miss/downgrade
```

In-memory (`PublicKeyDirectory.in_memory([...])`) and unsigned-file variants are also available.

### Geo drift (tolerant mode)

Same-country IP hops become Warnings instead of Violations when you provide lat/lon and a threshold:

```python
from kavach import ActionContext, GeoLocation

gate = Gate.from_dict(POLICY, geo_drift_max_km=500.0)

verdict = gate.evaluate(ActionContext(
    principal_id="u", principal_kind="user",
    action_name="view_profile",
    ip="2.3.4.5",
    session_id="sess-1",
    current_geo=GeoLocation("IN", city="Chennai",   latitude=13.08, longitude=80.27),
    origin_geo =GeoLocation("IN", city="Bangalore", latitude=12.97, longitude=77.59),
))
```

Missing geo with a threshold set still **fails closed**. The SDK does not silently bypass.

### Policy hot reload

`gate.reload(...)` accepts a TOML string; it raises `ValueError` on parse error and leaves the previous good set in place. See [docs/guides/toml-policies.md](https://github.com/SarthiAI/Kavach/blob/main/docs/guides/toml-policies.md) for the full reload workflow (including the file-watcher pattern and the empty-TOML kill switch).

```python
gate.reload(new_policy_toml)   # parse error raises, previous set preserved
```

### Multi-replica (Redis) *(experimental)*

> The Rust-level integration tests for `kavach-redis` pass, and the Python SDK exposes `RedisRateLimitStore` / `RedisSessionStore` / `RedisInvalidationBroadcaster` as classes, but the end-to-end multi-replica story has not yet been validated through the consumer-test harness. Early adopters can wire this up; treat it as a reference rather than a production guarantee. Thorough validation is tracked in the [project roadmap](https://github.com/SarthiAI/Kavach/blob/main/docs/roadmap.md).

Rate limits and invalidation broadcast move to Redis so every replica agrees:

```python
from kavach import (
    Gate, RedisRateLimitStore, RedisInvalidationBroadcaster,
    spawn_invalidation_listener,
)

REDIS_URL = "redis://127.0.0.1:6379"

rate_store = RedisRateLimitStore(REDIS_URL)
broadcaster = RedisInvalidationBroadcaster(REDIS_URL, channel="kavach:invalidation")

gate = Gate.from_dict(POLICY, rate_store=rate_store, broadcaster=broadcaster)

handle = spawn_invalidation_listener(broadcaster, lambda scope: None)
# handle.abort() on shutdown
```

Redis outages fail closed: a dropped `record` refuses the action; a dropped `count` collapses the rate-limit condition to default-deny. Full wiring lives in [docs/guides/distributed.md](https://github.com/SarthiAI/Kavach/blob/main/docs/guides/distributed.md).

---

## Observe mode

Roll out incrementally: log verdicts without blocking.

```python
gate = Gate.from_dict(POLICY, observe_only=True)
```

---

## What's in the Rust engine

Every `evaluate()` call crosses FFI into compiled Rust. The Python layer is pure wrappers. The engine implements:

- **Policy:** a small, fixed condition vocabulary (`identity_kind`, `action`, `param_max`, `rate_limit`, `time_window` with optional timezone, etc.) expressed as a Python dict, JSON, or operator-edited TOML.
- **Drift detectors:** IP / geo, session age, device, behavior.
- **Invariants:** hard per-action limits that cannot be overridden by policy.
- **Post-quantum crypto:** ML-DSA-65, ML-KEM-768, Ed25519, X25519, ChaCha20-Poly1305.
- **Fail-closed:** any evaluator error, store failure, or broadcast issue errs on the side of Refuse.

---

## License

Elastic License 2.0. Source-available; free to use, embed, and modify for any purpose, including commercially. You may not offer Kavach itself as a hosted or managed service that competes with SarthiAI. See the [LICENSE](https://github.com/SarthiAI/Kavach/blob/main/LICENSE) file for the full text.
