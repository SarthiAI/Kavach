# kavach

**Post-quantum execution boundary enforcement for AI agents, APIs, and distributed systems — Python SDK.**

Kavach separates *possession of credentials* from *permission to act*. Every action passes through a gate that evaluates identity, policy, drift, and invariants before producing a verdict. All evaluation runs in compiled Rust via PyO3; this package is the idiomatic Python wrapper.

```
Action attempted ──▶ Gate (identity · policy · drift · invariants) ──▶ Permit / Refuse / Invalidate
```

---

## Install

```bash
pip install kavach
```

Wheels are published as `abi3` — a single wheel per platform covers CPython 3.10, 3.11, 3.12, and every future Python. Linux x86_64/aarch64, macOS x86_64/arm64, and Windows x64 are supported.

---

## 60-second quickstart

```python
from kavach import Gate

POLICY = """
[[policy]]
name = "agent_small_refunds"
effect = "permit"
conditions = [
    { identity_kind = "agent" },
    { action = "issue_refund" },
    { param_max = { field = "amount", max = 1000.0 } },
]
"""

gate = Gate.from_toml(
    POLICY,
    invariants=[("hard_cap", "amount", 50_000.0)],
)

verdict = gate.evaluate(
    principal_id="agent-bot",
    principal_kind="agent",
    action_name="issue_refund",
    params={"amount": 500},
)

if verdict.is_permit:
    process_refund()
else:
    print(f"blocked: [{verdict.code}] {verdict.evaluator}: {verdict.reason}")
```

A policy set with no matching permit Refuses by default — there is no implicit allow.

---

## MCP tool gating

```python
from kavach import Gate, McpKavachMiddleware

gate = Gate.from_file("kavach.toml")
kavach = McpKavachMiddleware(gate)

# In your MCP tool handler:
kavach.check_tool_call(
    tool_name="issue_refund",
    params={"amount": 500, "order_id": "ORD-123"},
    caller_id="agent-bot",
    caller_kind="agent",
)
# Raises kavach.Refused if blocked, kavach.Invalidated if session revoked.
```

## FastAPI middleware

```python
from fastapi import FastAPI
from kavach import Gate, HttpKavachMiddleware

app = FastAPI()
gate = Gate.from_file("kavach.toml")
kavach_http = HttpKavachMiddleware(gate)

@app.middleware("http")
async def kavach_gate(request, call_next):
    verdict = kavach_http.evaluate_fastapi(request)
    if not verdict.is_permit:
        return JSONResponse(status_code=403, content={"error": verdict.reason})
    return await call_next(request)
```

## Decorator

```python
from kavach import guarded

@guarded(gate, action="issue_refund", param_fields={"amount": "amount"})
async def issue_refund(order_id: str, amount: float):
    return process_refund(order_id, amount)

result = await issue_refund(
    "ORD-123", 500.0,
    _principal_id="bot", _principal_kind="agent",
)
```

---

## Feature surface

### Signed permit tokens (`PqTokenSigner`)

When a `PqTokenSigner` is attached to a gate, every Permit verdict carries an ML-DSA-65 (or ML-DSA-65 + Ed25519 hybrid) signed envelope. Downstream services verify independently.

```python
from kavach import Gate, PqTokenSigner, PermitToken

signer = PqTokenSigner.generate_hybrid()
gate = Gate.from_toml(POLICY, token_signer=signer)

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
bundle = kp.public_keys()   # PublicKeyBundle — safe to share
```

### Signed audit chain

Append-only, tamper-evident audit log. `verify` rejects tampered entries, wrong keys, and mode mismatches (e.g., a PQ-only verifier on a hybrid chain — a silent downgrade).

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

Hybrid-encrypted, PQ-signed byte channel between two peers. Sealed payloads are opaque — ship them over any transport.

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
    root_vk=signing_key.public_keys().ml_dsa_verifying_key,
)

verifier = DirectoryTokenVerifier(directory, hybrid=True)
verifier.verify(token, signed_envelope)  # raises on tamper/miss/downgrade
```

In-memory (`PublicKeyDirectory.in_memory([...])`) and unsigned-file variants are also available.

### Geo drift (tolerant mode)

Same-country IP hops become Warnings instead of Violations when you provide lat/lon and a threshold:

```python
from kavach import GeoLocation

gate = Gate.from_toml(POLICY, geo_drift_max_km=500.0)

verdict = gate.evaluate(
    principal_id="u", principal_kind="user",
    action_name="view_profile",
    ip="2.3.4.5",
    session_id="sess-1",
    current_geo=GeoLocation("IN", city="Chennai",   latitude=13.08, longitude=80.27),
    origin_geo =GeoLocation("IN", city="Bangalore", latitude=12.97, longitude=77.59),
)
```

Missing geo with a threshold set still **fails closed** — the SDK does not silently bypass.

### Policy hot reload

```python
gate.reload(new_policy_toml)   # parse error → raises, previous set preserved
```

---

## Observe mode

Roll out incrementally: log verdicts without blocking.

```python
gate = Gate.from_file("kavach.toml", observe_only=True)
```

---

## What's in the Rust engine

Every `evaluate()` call crosses FFI into compiled Rust. The Python layer is pure wrappers. The engine implements:

- **Policy** — TOML rules with conditions (`identity_kind`, `action`, `param_max`, `rate_limit`, `time_window` with optional timezone, etc.).
- **Drift detectors** — IP/geo, session age, device, behavior.
- **Invariants** — hard per-action limits that cannot be overridden by policy.
- **Post-quantum crypto** — ML-DSA-65, ML-KEM-768, Ed25519, X25519, ChaCha20-Poly1305.
- **Fail-closed** — any evaluator error, store failure, or broadcast issue errs on the side of Refuse.

---

## License

Elastic License 2.0. Source-available; free to use, embed, and modify for any purpose, including commercially. You may not offer Kavach itself as a hosted or managed service that competes with SarthiAI. See the [LICENSE](https://github.com/SarthiAI/Kavach/blob/main/LICENSE) file for the full text.
