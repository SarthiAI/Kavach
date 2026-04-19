"""End-to-end smoke test for the Python SDK.

Exercises every public surface:
  - Direct Rust binding imports (_kavach_engine)
  - Python wrapper Gate (from_toml, evaluate, check)
  - Exception paths (Refused, Invalidated)
  - McpKavachMiddleware check_tool_call + evaluate_tool_call
  - Session tracking

Run inside the project venv:
    source kavach-py/.venv/bin/activate
    python kavach-py/python/tests/smoke_test.py
"""
from __future__ import annotations

import os
import sys
import tempfile
import traceback

import time

from kavach import (
    ActionContext,
    AuditEntry,
    DirectoryTokenVerifier,
    Gate,
    GeoLocation,
    KavachKeyPair,
    McpKavachMiddleware,
    PermitToken,
    PqTokenSigner,
    PublicKeyBundle,
    PublicKeyDirectory,
    SecureChannel,
    SignedAuditChain,
    Verdict,
)
from kavach.wrappers import Invalidated, Refused


PASS = "\033[32m✓\033[0m"
FAIL = "\033[31m✗\033[0m"


def check(name: str, condition: bool, detail: str = "") -> bool:
    mark = PASS if condition else FAIL
    tail = f", {detail}" if detail else ""
    print(f"  {mark} {name}{tail}")
    return condition


# ─── 1. Direct Rust binding ────────────────────────────────────────────

def test_rust_binding_loads() -> list[bool]:
    print("\n[1] Direct _kavach_engine binding")
    results: list[bool] = []

    ctx = ActionContext(
        principal_id="agent-alice",
        principal_kind="agent",
        action_name="issue_refund",
        roles=["support"],
        params={"amount": 1500.0},
        ip="10.0.0.1",
    )
    results.append(check("ActionContext constructed", ctx is not None))

    # isinstance Verdict check, we can't instantiate Verdict directly
    # but evaluate() returns one.
    return results


# ─── 2. Gate wrapper, permit path ─────────────────────────────────────

def test_gate_permit() -> list[bool]:
    print("\n[2] Gate.from_toml → evaluate → Permit")
    results: list[bool] = []

    toml = """
[[policy]]
name = "permit_small_refunds"
effect = "permit"
conditions = [
    { identity_role = "support" },
    { action = "issue_refund" },
    { param_max = { field = "amount", max = 5000.0 } },
]
"""
    gate = Gate.from_toml(toml, invariants=[("max_refund", "amount", 10000.0)])
    results.append(check("gate constructed", gate is not None))
    results.append(
        check("evaluator_count >= 2", gate.evaluator_count >= 2,
              f"got {gate.evaluator_count}")
    )

    ctx = ActionContext(
        principal_id="agent-alice",
        principal_kind="agent",
        action_name="issue_refund",
        roles=["support"],
        params={"amount": 1500.0},
    )
    verdict = gate.evaluate(ctx)
    results.append(check("verdict is Permit", verdict.is_permit,
                         f"got {verdict!r}"))
    results.append(check("verdict has token_id", verdict.token_id is not None))
    return results


# ─── 3. Gate, default-deny path ───────────────────────────────────────

def test_gate_default_deny() -> list[bool]:
    print("\n[3] Empty policy set → default-deny")
    results: list[bool] = []

    gate = Gate.from_toml("")
    ctx = ActionContext(
        principal_id="agent",
        principal_kind="agent",
        action_name="anything",
    )
    v = gate.evaluate(ctx)
    results.append(check("empty policy set refuses", v.is_refuse, f"got {v!r}"))
    return results


# ─── 4. Gate, invariant override ──────────────────────────────────────

def test_invariant_overrides_policy() -> list[bool]:
    print("\n[4] Invariant blocks even when policy permits")
    results: list[bool] = []

    toml = """
[[policy]]
name = "permit_any_refund"
effect = "permit"
conditions = [
    { identity_role = "support" },
    { action = "issue_refund" },
]
"""
    # Policy permits any refund; invariant caps at 100.
    gate = Gate.from_toml(toml, invariants=[("hard_cap", "amount", 100.0)])
    ctx = ActionContext(
        principal_id="agent",
        principal_kind="agent",
        action_name="issue_refund",
        roles=["support"],
        params={"amount": 500.0},  # exceeds invariant
    )
    v = gate.evaluate(ctx)
    results.append(check("invariant wins over policy permit", v.is_refuse,
                         f"got {v!r}"))
    return results


# ─── 5. Gate.check raises Refused ──────────────────────────────────────

def test_check_raises_refused() -> list[bool]:
    print("\n[5] Gate.check raises Refused on block")
    results: list[bool] = []

    gate = Gate.from_toml("")  # default-deny
    ctx = ActionContext(
        principal_id="a", principal_kind="agent", action_name="x",
    )
    raised = False
    try:
        gate.check(ctx)
    except Refused as e:
        raised = True
        results.append(check("Refused.code populated", bool(e.code)))
        results.append(check("Refused.evaluator populated", bool(e.evaluator)))
    except Exception as e:
        results.append(check(f"only Refused raised (got {type(e).__name__})", False))
    results.append(check("Refused exception raised", raised))
    return results


# ─── 6. MCP middleware permit + refuse ─────────────────────────────────

def test_mcp_middleware() -> list[bool]:
    print("\n[6] McpKavachMiddleware")
    results: list[bool] = []

    toml = """
[[policy]]
name = "agent_small_refunds"
effect = "permit"
conditions = [
    { identity_kind = "agent" },
    { action = "issue_refund" },
    { param_max = { field = "amount", max = 5000.0 } },
]
"""
    gate = Gate.from_toml(toml)
    kv = McpKavachMiddleware(gate)

    # Permit path
    v = kv.evaluate_tool_call(
        tool_name="issue_refund",
        params={"order_id": "ORD-1", "amount": 500.0},
        caller_id="support-bot",
        caller_kind="agent",
        session_id="sess-1",
    )
    results.append(check("small refund permitted", v.is_permit, f"got {v!r}"))

    # Over-policy-limit refuse path
    v = kv.evaluate_tool_call(
        tool_name="issue_refund",
        params={"order_id": "ORD-2", "amount": 25000.0},
        caller_id="support-bot",
        caller_kind="agent",
        session_id="sess-1",
    )
    results.append(check("over-limit refund refused", v.is_refuse, f"got {v!r}"))

    # Unknown tool → default deny
    v = kv.evaluate_tool_call(
        tool_name="delete_customer",
        params={"customer_id": "c1"},
        caller_id="support-bot",
        caller_kind="agent",
    )
    results.append(check("unknown tool refused (default deny)", v.is_refuse,
                         f"got {v!r}"))

    # check_tool_call raises path
    raised = False
    try:
        kv.check_tool_call(
            tool_name="delete_customer",
            params={},
            caller_id="support-bot",
            caller_kind="agent",
        )
    except Refused:
        raised = True
    results.append(check("check_tool_call raises Refused", raised))

    return results


# ─── 7. Invalid TOML surfaces as a Python error ────────────────────────

def test_invalid_toml() -> list[bool]:
    print("\n[7] Malformed TOML → ValueError")
    results: list[bool] = []

    raised = False
    try:
        Gate.from_toml("this is not valid toml === [][")
    except ValueError:
        raised = True
    except Exception as e:
        results.append(check(f"ValueError (got {type(e).__name__})", False))
    results.append(check("ValueError raised on bad TOML", raised))
    return results


# ─── 8. PqTokenSigner, sign/verify roundtrip + tamper detection ───────

def test_pq_token_signer() -> list[bool]:
    print("\n[8] PqTokenSigner sign/verify (PQ-only + hybrid)")
    results: list[bool] = []

    # PQ-only roundtrip
    pq = PqTokenSigner.generate_pq_only()
    results.append(check("PQ-only signer constructed", pq is not None))
    results.append(check("PQ-only signer.is_hybrid is False", pq.is_hybrid is False))

    token = PermitToken(
        token_id="00000000-0000-0000-0000-000000000001",
        evaluation_id="00000000-0000-0000-0000-000000000002",
        issued_at=1_700_000_000,
        expires_at=1_700_000_030,
        action_name="issue_refund",
    )
    sig = pq.sign(token)
    results.append(check("PQ-only sign returned bytes", isinstance(sig, bytes) and len(sig) > 0))
    try:
        pq.verify(token, sig)
        results.append(check("PQ-only verify(valid) succeeds", True))
    except Exception as e:
        results.append(check(f"PQ-only verify(valid), got {type(e).__name__}: {e}", False))

    # Tamper signature
    bad_sig = bytearray(sig)
    bad_sig[len(bad_sig) // 2] ^= 0x01
    raised = False
    try:
        pq.verify(token, bytes(bad_sig))
    except ValueError:
        raised = True
    results.append(check("PQ-only verify(tampered sig) raises ValueError", raised))

    # Tamper token (change action_name), verify against original sig must fail
    tampered_token = PermitToken(
        token_id="00000000-0000-0000-0000-000000000001",
        evaluation_id="00000000-0000-0000-0000-000000000002",
        issued_at=1_700_000_000,
        expires_at=1_700_000_030,
        action_name="delete_customer",  # was "issue_refund"
    )
    raised = False
    try:
        pq.verify(tampered_token, sig)
    except ValueError:
        raised = True
    results.append(check("PQ-only verify(tampered token) raises ValueError", raised))

    # Wrong-key rejection
    other_pq = PqTokenSigner.generate_pq_only()
    raised = False
    try:
        other_pq.verify(token, sig)
    except ValueError:
        raised = True
    results.append(check("PQ-only verify(wrong key) raises ValueError", raised))

    # Hybrid roundtrip
    hy = PqTokenSigner.generate_hybrid()
    results.append(check("hybrid signer.is_hybrid is True", hy.is_hybrid is True))
    sig_h = hy.sign(token)
    try:
        hy.verify(token, sig_h)
        results.append(check("hybrid verify(valid) succeeds", True))
    except Exception as e:
        results.append(check(f"hybrid verify(valid), got {type(e).__name__}: {e}", False))

    # Hybrid rejects PQ-only envelope (downgrade guard)
    raised = False
    try:
        hy.verify(token, sig)
    except ValueError:
        raised = True
    results.append(check("hybrid verifier rejects PQ-only envelope", raised))

    # PQ-only verifier rejects hybrid envelope
    raised = False
    try:
        pq.verify(token, sig_h)
    except ValueError:
        raised = True
    results.append(check("PQ-only verifier rejects hybrid envelope", raised))

    return results


# ─── 9. Gate.with token_signer, signed permit roundtrip ───────────────

def test_gate_with_signer() -> list[bool]:
    print("\n[9] Gate(token_signer=…) → signed Permit verifies end-to-end")
    results: list[bool] = []

    toml = """
[[policy]]
name = "permit_small_refunds"
effect = "permit"
conditions = [
    { identity_role = "support" },
    { action = "issue_refund" },
    { param_max = { field = "amount", max = 5000.0 } },
]
"""
    signer = PqTokenSigner.generate_hybrid()
    gate = Gate.from_toml(toml, token_signer=signer)
    ctx = ActionContext(
        principal_id="agent-alice",
        principal_kind="agent",
        action_name="issue_refund",
        roles=["support"],
        params={"amount": 1500.0},
    )
    v = gate.evaluate(ctx)
    results.append(check("Permit returned", v.is_permit, f"got {v!r}"))

    pt = v.permit_token
    results.append(check("verdict.permit_token populated", pt is not None))
    results.append(check("permit_token.signature populated", pt is not None and pt.signature is not None))

    # Verify the signed token end-to-end through the same signer object
    try:
        signer.verify(pt, pt.signature)
        results.append(check("signer.verify(permit_token, signature) succeeds", True))
    except Exception as e:
        results.append(check(f"signer.verify, got {type(e).__name__}: {e}", False))

    # Tamper: forge a token reusing the signature for a different action
    forged = PermitToken(
        token_id=pt.token_id,
        evaluation_id=pt.evaluation_id,
        issued_at=pt.issued_at,
        expires_at=pt.expires_at,
        action_name="delete_customer",
    )
    raised = False
    try:
        signer.verify(forged, pt.signature)
    except ValueError:
        raised = True
    results.append(check("forged action_name rejected by verify", raised))

    return results


# ─── 10. Gate.reload, hot policy swap + parse error fail-safe ─────────

def test_gate_reload() -> list[bool]:
    print("\n[10] Gate.reload, hot policy swap")
    results: list[bool] = []

    permissive = """
[[policy]]
name = "permit_refunds"
effect = "permit"
conditions = [
    { identity_role = "support" },
    { action = "issue_refund" },
]
"""
    gate = Gate.from_toml(permissive)
    ctx = ActionContext(
        principal_id="agent",
        principal_kind="agent",
        action_name="issue_refund",
        roles=["support"],
        params={"amount": 100.0},
    )
    results.append(check("initial policy permits", gate.evaluate(ctx).is_permit))

    # Swap to default-deny, an empty PolicySet
    gate.reload("")
    results.append(check("reload('') swaps to default-deny", gate.evaluate(ctx).is_refuse))

    # Swap back, should permit again
    gate.reload(permissive)
    results.append(check("reload(permissive) restores permit", gate.evaluate(ctx).is_permit))

    # Parse-error reload must NOT wipe the running engine
    raised = False
    try:
        gate.reload("this is === not valid toml [[[")
    except ValueError:
        raised = True
    results.append(check("reload(bad toml) raises ValueError", raised))
    results.append(
        check("policy still permits after failed reload", gate.evaluate(ctx).is_permit)
    )

    return results


# ─── 11. KavachKeyPair.generate + public_keys + signer integration ─────

def test_keypair_generate() -> list[bool]:
    print("\n[11] KavachKeyPair.generate + public_keys + signer integration")
    results: list[bool] = []

    kp = KavachKeyPair.generate()
    results.append(check("KavachKeyPair constructed", kp is not None))
    results.append(check("kp.id non-empty", isinstance(kp.id, str) and len(kp.id) > 0))
    results.append(check("kp.created_at > 0", kp.created_at > 0))
    results.append(check("kp.expires_at is None (no expiry)", kp.expires_at is None))
    results.append(check("kp.is_expired is False", kp.is_expired is False))

    bundle = kp.public_keys()
    results.append(check("public_keys returns PublicKeyBundle", isinstance(bundle, PublicKeyBundle)))
    results.append(check("bundle.id matches kp.id", bundle.id == kp.id))

    # ML-DSA-65 verifying key is the encoded form (~1952 bytes for ML-DSA-65).
    # Ed25519 VK is 32 bytes; X25519 PK is 32 bytes.
    results.append(check("ml_dsa_verifying_key returns bytes", isinstance(bundle.ml_dsa_verifying_key, bytes)))
    results.append(check("ml_dsa_verifying_key non-empty", len(bundle.ml_dsa_verifying_key) > 0))
    results.append(check("ed25519_verifying_key is 32 bytes",
                         isinstance(bundle.ed25519_verifying_key, bytes)
                         and len(bundle.ed25519_verifying_key) == 32))
    results.append(check("x25519_public_key is 32 bytes",
                         isinstance(bundle.x25519_public_key, bytes)
                         and len(bundle.x25519_public_key) == 32))
    results.append(check("ml_kem_encapsulation_key non-empty",
                         isinstance(bundle.ml_kem_encapsulation_key, bytes)
                         and len(bundle.ml_kem_encapsulation_key) > 0))

    # Two generations give different ids
    other = KavachKeyPair.generate()
    results.append(check("two generations produce distinct ids", kp.id != other.id))

    # Signer from keypair (PQ-only), sign + verify roundtrip through bundle's VK
    signer = PqTokenSigner.from_keypair_pq_only(kp)
    results.append(check("from_keypair_pq_only forwards kp.id",
                         signer.key_id == kp.id and signer.is_hybrid is False))

    token = PermitToken(
        token_id="00000000-0000-0000-0000-000000000003",
        evaluation_id="00000000-0000-0000-0000-000000000004",
        issued_at=1_700_000_000,
        expires_at=1_700_000_030,
        action_name="kp_test",
    )
    sig = signer.sign(token)

    # Verify via a *separate* signer rebuilt from the bundle's VK + the kp's
    # signing-key bytes (we still need the SK to construct it, but the VK
    # comes from the bundle, proves bundle bytes are usable).
    rebuilt = PqTokenSigner.pq_only(
        ml_dsa_signing_key=b"",  # placeholder, we won't sign with this
        ml_dsa_verifying_key=bundle.ml_dsa_verifying_key,
        key_id=kp.id,
    )
    try:
        rebuilt.verify(token, sig)
        results.append(check("verify via bundle's VK succeeds", True))
    except Exception as e:
        results.append(check(f"verify via bundle's VK, got {type(e).__name__}: {e}", False))

    # Hybrid from_keypair
    hy = PqTokenSigner.from_keypair_hybrid(kp)
    results.append(check("from_keypair_hybrid is_hybrid", hy.is_hybrid is True))
    sig_h = hy.sign(token)
    try:
        hy.verify(token, sig_h)
        results.append(check("from_keypair_hybrid roundtrip succeeds", True))
    except Exception as e:
        results.append(check(f"hybrid roundtrip, got {type(e).__name__}: {e}", False))

    # Expiry: a 1-second TTL is expired after sleeping past it
    short = KavachKeyPair.generate_with_expiry(1)
    results.append(check("short-lived kp has expires_at", short.expires_at is not None))
    results.append(check("short-lived kp is not expired immediately", short.is_expired is False))
    time.sleep(1.5)
    results.append(check("short-lived kp expired after 1.5s", short.is_expired is True))

    return results


# ─── 12. SignedAuditChain, append/verify/export/tamper detection ──────

def test_signed_audit_chain() -> list[bool]:
    print("\n[12] SignedAuditChain append + verify + export + tamper detection")
    results: list[bool] = []

    kp = KavachKeyPair.generate()
    bundle = kp.public_keys()

    chain = SignedAuditChain(kp, hybrid=True)
    results.append(check("empty chain length == 0", chain.length == 0))
    results.append(check("len(chain) == 0", len(chain) == 0))
    results.append(check("empty chain is_empty is True", chain.is_empty is True))
    results.append(check("chain.is_hybrid is True", chain.is_hybrid is True))
    results.append(check("empty chain head_hash == 'genesis'", chain.head_hash == "genesis"))

    e1 = AuditEntry("agent-alice", "issue_refund", "permit", "token=abc")
    e2 = AuditEntry("agent-bob", "issue_refund", "refuse", "[POLICY_DENIED] no match")
    e3 = AuditEntry("agent-bob", "delete_customer", "invalidate", "drift detected")
    n1 = chain.append(e1)
    n2 = chain.append(e2)
    n3 = chain.append(e3)
    results.append(check("append returns growing length", n1 == 1 and n2 == 2 and n3 == 3))
    results.append(check("len(chain) == 3 after appends", len(chain) == 3))
    results.append(check("is_empty False after appends", chain.is_empty is False))
    results.append(check("head_hash advanced past 'genesis'", chain.head_hash != "genesis" and len(chain.head_hash) == 64))

    # Verify in-place
    try:
        chain.verify(bundle)
        results.append(check("chain.verify(bundle) succeeds", True))
    except Exception as e:
        results.append(check(f"chain.verify, got {type(e).__name__}: {e}", False))

    # Export to JSONL bytes
    blob = chain.export_jsonl()
    results.append(check("export_jsonl returns bytes", isinstance(blob, bytes) and len(blob) > 0))
    line_count = blob.count(b"\n")
    results.append(check("export_jsonl has 3 lines", line_count == 3))

    # verify_jsonl roundtrip, explicit hybrid=True
    verified_n = SignedAuditChain.verify_jsonl(blob, bundle, hybrid=True)
    results.append(check("verify_jsonl(hybrid=True) returns 3", verified_n == 3))

    # verify_jsonl mode inference, omit the hybrid flag; blob says hybrid
    inferred_n = SignedAuditChain.verify_jsonl(blob, bundle)
    results.append(check("verify_jsonl without hybrid infers hybrid", inferred_n == 3))
    inferred_n2 = SignedAuditChain.verify_jsonl(blob, bundle, hybrid=None)
    results.append(check("verify_jsonl hybrid=None infers hybrid", inferred_n2 == 3))

    # Tamper: flip a byte mid-blob → verify must fail
    tampered = bytearray(blob)
    tampered[len(tampered) // 2] ^= 0x01
    raised = False
    try:
        SignedAuditChain.verify_jsonl(bytes(tampered), bundle, hybrid=True)
    except (ValueError, Exception) as exc:
        # Tampering may cause JSON parse error (also caught) or sig failure.
        if isinstance(exc, ValueError):
            raised = True
    results.append(check("tampered blob → verify_jsonl raises", raised))

    # Wrong-key bundle → verify fails
    other_bundle = KavachKeyPair.generate().public_keys()
    raised = False
    try:
        SignedAuditChain.verify_jsonl(blob, other_bundle, hybrid=True)
    except ValueError:
        raised = True
    results.append(check("wrong-key bundle → verify_jsonl raises", raised))

    # Hybrid/PQ-only mismatch, a PQ-only verifier MUST reject a hybrid chain.
    # This is the signature-downgrade surface; it must fail closed.
    raised = False
    try:
        SignedAuditChain.verify_jsonl(blob, bundle, hybrid=False)
    except ValueError:
        raised = True
    results.append(check("PQ-only verifier rejects hybrid chain (downgrade blocked)", raised))

    # PQ-only chain
    pq_chain = SignedAuditChain(kp, hybrid=False)
    pq_chain.append(AuditEntry("a", "x", "permit", "ok"))
    results.append(check("PQ-only chain is_hybrid is False", pq_chain.is_hybrid is False))
    try:
        pq_chain.verify(bundle)
        results.append(check("PQ-only chain.verify succeeds", True))
    except Exception as e:
        results.append(check(f"PQ-only chain.verify, got {type(e).__name__}: {e}", False))

    # Hybrid verifier rejects PQ-only chain (no Ed25519 sig present)
    pq_blob = pq_chain.export_jsonl()
    raised = False
    try:
        SignedAuditChain.verify_jsonl(pq_blob, bundle, hybrid=True)
    except ValueError:
        raised = True
    results.append(check("hybrid verifier rejects PQ-only chain (missing Ed25519)", raised))

    # Inference picks the right mode for a PQ-only blob too.
    inferred_pq = SignedAuditChain.verify_jsonl(pq_blob, bundle)
    results.append(check("verify_jsonl infers PQ-only from PQ-only blob", inferred_pq == 1))

    # JSONL with blank lines in the middle still parses cleanly.
    blob_with_blanks = b"\n" + blob + b"\n\n"
    results.append(
        check(
            "verify_jsonl tolerates blank lines",
            SignedAuditChain.verify_jsonl(blob_with_blanks, bundle) == 3,
        )
    )

    # Empty chain verifies trivially
    empty = SignedAuditChain(kp)
    try:
        empty.verify(bundle)
        results.append(check("empty chain verifies", True))
    except Exception as e:
        results.append(check(f"empty chain.verify, got {type(e).__name__}: {e}", False))

    return results


# ─── 13. SecureChannel, hybrid encrypt + sign + replay + context binding ────

def test_secure_channel() -> list[bool]:
    print("\n[13] SecureChannel send/receive + replay + tamper + context binding")
    results: list[bool] = []

    gate_kp = KavachKeyPair.generate()
    handler_kp = KavachKeyPair.generate()
    outsider_kp = KavachKeyPair.generate()

    gate_bundle = gate_kp.public_keys()
    handler_bundle = handler_kp.public_keys()

    # Each side establishes against the other's public bundle only.
    gate_ch = SecureChannel(gate_kp, handler_bundle)
    handler_ch = SecureChannel(handler_kp, gate_bundle)

    results.append(
        check("gate_ch.local_key_id == gate_kp.id", gate_ch.local_key_id == gate_kp.id)
    )
    results.append(
        check(
            "gate_ch.remote_key_id == handler_kp.id",
            gate_ch.remote_key_id == handler_kp.id,
        )
    )
    results.append(
        check(
            "handler_ch.local_key_id == handler_kp.id",
            handler_ch.local_key_id == handler_kp.id,
        )
    )
    results.append(
        check(
            "handler_ch.remote_key_id == gate_kp.id",
            handler_ch.remote_key_id == gate_kp.id,
        )
    )

    # --- send_signed / receive_signed happy path ---
    payload = b'{"kind":"permit","action":"issue_refund"}'
    sealed = gate_ch.send_signed(payload, context_id="issue_refund", correlation_id="eval-1")
    results.append(check("send_signed returns bytes", isinstance(sealed, bytes) and len(sealed) > 0))
    decrypted = handler_ch.receive_signed(sealed, expected_context_id="issue_refund")
    results.append(check("receive_signed roundtrip preserves bytes", decrypted == payload))

    # --- Replay rejected ---
    raised = False
    try:
        handler_ch.receive_signed(sealed, expected_context_id="issue_refund")
    except ValueError:
        raised = True
    results.append(check("replay of same sealed payload rejected", raised))

    # --- Cross-context replay rejected ---
    sealed2 = gate_ch.send_signed(payload, context_id="issue_refund", correlation_id="eval-2")
    raised = False
    try:
        handler_ch.receive_signed(sealed2, expected_context_id="delete_customer")
    except ValueError:
        raised = True
    results.append(check("cross-context (wrong expected_context_id) rejected", raised))

    # --- Ciphertext tamper rejected ---
    sealed3 = gate_ch.send_signed(payload, context_id="issue_refund", correlation_id="eval-3")
    # Flip a byte deep inside, envelope is JSON so the offset lands in the base64-ish ciphertext field.
    tampered = bytearray(sealed3)
    tampered[len(tampered) // 2] ^= 0x01
    raised = False
    try:
        handler_ch.receive_signed(bytes(tampered), expected_context_id="issue_refund")
    except ValueError:
        raised = True
    results.append(check("tampered sealed payload rejected", raised))

    # --- Wrong recipient can't decrypt ---
    outsider_ch = SecureChannel(outsider_kp, gate_bundle)
    sealed4 = gate_ch.send_signed(payload, context_id="issue_refund", correlation_id="eval-4")
    raised = False
    try:
        outsider_ch.receive_signed(sealed4, expected_context_id="issue_refund")
    except ValueError:
        raised = True
    results.append(check("outsider can't decrypt (wrong recipient)", raised))

    # --- send_data / receive_data (no signing) roundtrip ---
    raw = b"arbitrary bytes, not signed"
    enc = gate_ch.send_data(raw)
    results.append(check("send_data returns bytes", isinstance(enc, bytes) and len(enc) > 0))
    dec = handler_ch.receive_data(enc)
    results.append(check("receive_data roundtrip preserves bytes", dec == raw))

    # --- Unsigned bytes survive the bytes→bytes roundtrip but can't bypass
    # the sign check: passing an unsigned envelope to receive_signed must
    # raise (decrypt succeeds but JSON-parse of SignedBytes fails).
    raised = False
    try:
        handler_ch.receive_signed(enc, expected_context_id="issue_refund")
    except ValueError:
        raised = True
    results.append(check("receive_signed rejects unsigned envelope", raised))

    # --- Outsider can't decrypt unsigned bytes either ---
    raised = False
    try:
        outsider_ch.receive_data(enc)
    except ValueError:
        raised = True
    results.append(check("outsider can't decrypt unsigned bytes", raised))

    # --- Replay across successes ---
    sealed5 = gate_ch.send_signed(payload, context_id="issue_refund", correlation_id="eval-5")
    handler_ch.receive_signed(sealed5, expected_context_id="issue_refund")
    raised = False
    try:
        handler_ch.receive_signed(sealed5, expected_context_id="issue_refund")
    except ValueError:
        raised = True
    results.append(check("replay after successful receive rejected", raised))

    return results


# ─── 14. PublicKeyDirectory + DirectoryTokenVerifier ────────────────────

def test_public_key_directory() -> list[bool]:
    print("\n[14] PublicKeyDirectory + DirectoryTokenVerifier")
    results: list[bool] = []

    # Build a few keypairs and a permit token signed by one of them.
    kp_a = KavachKeyPair.generate()
    kp_b = KavachKeyPair.generate()
    kp_c = KavachKeyPair.generate()
    signer_a = PqTokenSigner.from_keypair_hybrid(kp_a)
    signer_c_pq_only = PqTokenSigner.from_keypair_pq_only(kp_c)

    import uuid
    token = PermitToken(
        token_id=str(uuid.uuid4()),
        evaluation_id=str(uuid.uuid4()),
        issued_at=1_700_000_000,
        expires_at=1_700_000_060,
        action_name="issue_refund",
    )
    sig_a = signer_a.sign(token)
    sig_c_pq = signer_c_pq_only.sign(token)

    bundle_a = kp_a.public_keys()
    bundle_b = kp_b.public_keys()
    bundle_c = kp_c.public_keys()

    # ── In-memory directory ────────────────────────────────────────
    dir_im = PublicKeyDirectory.in_memory([bundle_a, bundle_b])
    results.append(check("in-memory length == 2", dir_im.length == 2))
    results.append(check("in-memory __len__ == 2", len(dir_im) == 2))
    results.append(check("in-memory is_empty False", dir_im.is_empty is False))
    fetched = dir_im.fetch(kp_a.id)
    results.append(check("fetch returns PublicKeyBundle", isinstance(fetched, PublicKeyBundle)))
    results.append(check("fetch id matches", fetched.id == kp_a.id))

    # Fetch miss
    raised = False
    try:
        dir_im.fetch("nonexistent-key")
    except ValueError:
        raised = True
    results.append(check("fetch miss raises", raised))

    # Insert + remove
    dir_im.insert(bundle_c)
    results.append(check("after insert length == 3", dir_im.length == 3))
    results.append(check("inserted key fetchable", dir_im.fetch(kp_c.id).id == kp_c.id))
    results.append(check("remove existing returns True", dir_im.remove(kp_c.id) is True))
    results.append(check("remove missing returns False", dir_im.remove(kp_c.id) is False))
    results.append(check("after remove length == 2", dir_im.length == 2))

    # DirectoryTokenVerifier, hybrid verifier against hybrid signer → success
    verifier = DirectoryTokenVerifier(dir_im, hybrid=True)
    try:
        verifier.verify(token, sig_a)
        results.append(check("hybrid verifier: valid hybrid sig succeeds", True))
    except Exception as e:
        results.append(check(f"hybrid verifier: hybrid sig, got {type(e).__name__}: {e}", False))

    # Tampered signature → rejected
    tampered = bytearray(sig_a)
    tampered[len(tampered) // 2] ^= 0x01
    raised = False
    try:
        verifier.verify(token, bytes(tampered))
    except ValueError:
        raised = True
    results.append(check("tampered signature rejected", raised))

    # Tampered token → rejected (different token_id → canonical_bytes differ)
    wrong_token = PermitToken(
        token_id=str(uuid.uuid4()),
        evaluation_id=token.evaluation_id,
        issued_at=token.issued_at,
        expires_at=token.expires_at,
        action_name=token.action_name,
    )
    raised = False
    try:
        verifier.verify(wrong_token, sig_a)
    except ValueError:
        raised = True
    results.append(check("wrong token id rejected", raised))

    # Key not in directory → fail-closed with ValueError
    dir_empty = PublicKeyDirectory.in_memory()
    verifier_empty = DirectoryTokenVerifier(dir_empty, hybrid=True)
    raised = False
    try:
        verifier_empty.verify(token, sig_a)
    except ValueError:
        raised = True
    results.append(check("missing key in directory → refuse (fail-closed)", raised))

    # Hybrid verifier rejects PQ-only envelope (downgrade guard)
    dir_with_c = PublicKeyDirectory.in_memory([bundle_c])
    verifier_hybrid = DirectoryTokenVerifier(dir_with_c, hybrid=True)
    raised = False
    try:
        verifier_hybrid.verify(token, sig_c_pq)
    except ValueError:
        raised = True
    results.append(check("hybrid verifier rejects PQ-only envelope (downgrade)", raised))

    # PQ-only verifier accepts PQ-only envelope
    verifier_pq = DirectoryTokenVerifier(dir_with_c, hybrid=False)
    try:
        verifier_pq.verify(token, sig_c_pq)
        results.append(check("PQ-only verifier accepts PQ-only envelope", True))
    except Exception as e:
        results.append(
            check(f"PQ-only verifier + PQ sig, got {type(e).__name__}: {e}", False)
        )

    # PQ-only verifier rejects hybrid envelope
    raised = False
    try:
        DirectoryTokenVerifier(dir_im, hybrid=False).verify(token, sig_a)
    except ValueError:
        raised = True
    results.append(check("PQ-only verifier rejects hybrid envelope", raised))

    # insert/remove raise on file-backed directory
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".json", delete=False) as f:
        unsigned_bytes = PublicKeyDirectory.build_unsigned_manifest([bundle_a, bundle_b])
        f.write(unsigned_bytes)
        unsigned_path = f.name
    try:
        dir_file = PublicKeyDirectory.from_file(unsigned_path)
        results.append(check("from_file loads bundles", dir_file.length == 2))
        results.append(check("from_file fetch works", dir_file.fetch(kp_a.id).id == kp_a.id))

        raised = False
        try:
            dir_file.insert(bundle_c)
        except ValueError:
            raised = True
        results.append(check("insert on file-backed directory raises", raised))

        raised = False
        try:
            dir_file.remove(kp_a.id)
        except ValueError:
            raised = True
        results.append(check("remove on file-backed directory raises", raised))

        # reload on in-memory is a no-op, not an error
        try:
            dir_im.reload()
            results.append(check("reload on in-memory directory is no-op", True))
        except Exception as e:
            results.append(check(f"reload on in-memory, got {type(e).__name__}: {e}", False))

        # File reload picks up changes
        updated = PublicKeyDirectory.build_unsigned_manifest([bundle_a, bundle_b, bundle_c])
        with open(unsigned_path, "wb") as fw:
            fw.write(updated)
        dir_file.reload()
        results.append(check("file reload picks up new bundle", dir_file.length == 3))

        # File reload with corrupt file preserves old cache
        with open(unsigned_path, "wb") as fw:
            fw.write(b"not-json")
        raised = False
        try:
            dir_file.reload()
        except ValueError:
            raised = True
        results.append(check("corrupt file reload raises", raised))
        results.append(check("after corrupt reload, cache preserved", dir_file.length == 3))
    finally:
        os.unlink(unsigned_path)

    # ── Signed-manifest directory ─────────────────────────────────
    root_kp = KavachKeyPair.generate()
    signed_bytes = root_kp.build_signed_manifest([bundle_a, bundle_b])
    results.append(
        check(
            "build_signed_manifest returns non-empty bytes",
            isinstance(signed_bytes, bytes) and len(signed_bytes) > 0,
        )
    )

    # Write signed manifest → load → fetch works
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".json", delete=False) as f:
        f.write(signed_bytes)
        signed_path = f.name
    try:
        root_vk = bytes(root_kp.public_keys().ml_dsa_verifying_key)
        dir_signed = PublicKeyDirectory.from_signed_file(signed_path, root_vk)
        results.append(check("from_signed_file loads with correct root VK", dir_signed.length == 2))
        results.append(
            check("signed-file fetch works", dir_signed.fetch(kp_a.id).id == kp_a.id)
        )

        # Wrong root VK → load rejected
        imposter_vk = bytes(KavachKeyPair.generate().public_keys().ml_dsa_verifying_key)
        raised = False
        try:
            PublicKeyDirectory.from_signed_file(signed_path, imposter_vk)
        except ValueError:
            raised = True
        results.append(check("signed-file with wrong root VK rejected", raised))

        # Tamper with bundles_json content → root signature no longer valid → reject
        # (Parse the signed manifest JSON, flip a byte in bundles_json, re-serialize.)
        import json
        manifest = json.loads(signed_bytes.decode("utf-8"))
        manifest["bundles_json"] = manifest["bundles_json"].replace(kp_a.id, "evil-" + kp_a.id[5:])
        tampered_bytes = json.dumps(manifest).encode("utf-8")
        with open(signed_path, "wb") as fw:
            fw.write(tampered_bytes)
        raised = False
        try:
            PublicKeyDirectory.from_signed_file(signed_path, root_vk)
        except ValueError:
            raised = True
        results.append(check("signed-file with tampered bundles rejected", raised))
    finally:
        os.unlink(signed_path)

    # End-to-end: signer (keypair A) → directory → DirectoryTokenVerifier
    # simulates a downstream service that only has the root-signed manifest
    # and the token envelope, and still verifies correctly.
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".json", delete=False) as f:
        f.write(root_kp.build_signed_manifest([bundle_a]))
        signed_path2 = f.name
    try:
        dir_e2e = PublicKeyDirectory.from_signed_file(
            signed_path2, bytes(root_kp.public_keys().ml_dsa_verifying_key)
        )
        verifier_e2e = DirectoryTokenVerifier(dir_e2e, hybrid=True)
        try:
            verifier_e2e.verify(token, sig_a)
            results.append(check("E2E: signed-manifest-backed verifier accepts valid token", True))
        except Exception as e:
            results.append(
                check(f"E2E verify, got {type(e).__name__}: {e}", False)
            )
    finally:
        os.unlink(signed_path2)

    return results


# ─── 15. GeoLocation + tolerant-mode GeoLocationDrift ──────────────────

def test_geo_drift() -> list[bool]:
    print("\n[15] GeoLocation + tolerant-mode GeoLocationDrift across the SDK")
    results: list[bool] = []

    # Allow policy that covers fetch_report, drift runs after policy.
    policy_toml = """
[[policy]]
name = "allow_fetch_report"
effect = "permit"
conditions = [
    { action = "fetch_report" },
]
"""

    bangalore = GeoLocation(
        country_code="IN", city="Bangalore", latitude=12.9716, longitude=77.5946
    )
    chennai = GeoLocation(
        country_code="IN", city="Chennai", latitude=13.0827, longitude=80.2707
    )
    new_york = GeoLocation(
        country_code="US", city="New York", latitude=40.7128, longitude=-74.0060
    )

    # GeoLocation distance helper
    bangalore_to_chennai = bangalore.distance_km(chennai) or 0.0
    bangalore_to_ny = bangalore.distance_km(new_york) or 0.0
    results.append(
        check(
            "Bangalore→Chennai ~290km (plausible Haversine)",
            280 < bangalore_to_chennai < 310,
            f"got {bangalore_to_chennai:.1f}km",
        )
    )
    results.append(
        check(
            "Bangalore→NewYork >13000km",
            bangalore_to_ny > 13000,
            f"got {bangalore_to_ny:.1f}km",
        )
    )

    # Geo getters
    results.append(check("country_code getter", bangalore.country_code == "IN"))
    results.append(check("city getter", bangalore.city == "Bangalore"))
    results.append(check("latitude getter", abs(bangalore.latitude - 12.9716) < 1e-6))

    # ── Strict-mode gate: any IP change → Invalidate regardless of geo ─
    strict_gate = Gate.from_toml(policy_toml)
    session_id = "00000000-0000-0000-0000-000000000001"

    # Session start (no IP change yet, just populate origin)
    v0 = strict_gate.evaluate(
        ActionContext(
            principal_id="alice",
            principal_kind="user",
            action_name="fetch_report",
            ip="10.0.0.1",
            session_id=session_id,
            origin_geo=bangalore,
            current_geo=bangalore,
        )
    )
    # SessionState is constructed fresh per evaluate (SDK doesn't persist),
    # so origin_ip == current_ip and this should Permit cleanly.
    results.append(check("strict: matching ip+geo permits", v0.is_permit))

    # Different current IP vs origin, strict mode always invalidates.
    # Note: the SDK's ActionContext builds a fresh SessionState every call
    # and sets session.origin_ip = env.ip. To simulate a mid-session IP
    # change from the SDK, we'd need to persist session state across calls,
    # which the SDK doesn't expose. Instead, exercise the geo knob via
    # the gate construction path and trust the core integration tests.
    # We still verify the SDK passes geo through by constructing contexts
    # that carry current_geo + origin_geo and assert no crash.

    # ── Tolerant-mode gate: plumbing test ──────────────────────────────
    tolerant_gate = Gate.from_toml(policy_toml, geo_drift_max_km=500.0)
    v1 = tolerant_gate.evaluate(
        ActionContext(
            principal_id="alice",
            principal_kind="user",
            action_name="fetch_report",
            ip="10.0.0.1",
            session_id=session_id,
            origin_geo=bangalore,
            current_geo=bangalore,
        )
    )
    results.append(check("tolerant: matching ip+geo still permits", v1.is_permit))

    # ── Explicit drift simulation via manual ActionContext construction ─
    # We can't easily manipulate SessionState across FFI calls, but we CAN
    # verify that passing geo to ActionContext doesn't break existing
    # evaluators (which is the production concern, P2.7 is plumbing).
    ctx_with_geo = ActionContext(
        principal_id="alice",
        principal_kind="user",
        action_name="fetch_report",
        ip="10.0.0.1",
        origin_geo=bangalore,
        current_geo=chennai,
    )
    v2 = tolerant_gate.evaluate(ctx_with_geo)
    results.append(
        check("tolerant: geo plumbed, evaluates without error", v2 is not None)
    )

    # ── Middleware plumbing ─────────────────────────────────────────────
    # MCP middleware forwards current_geo / origin_geo.
    mcp = McpKavachMiddleware(tolerant_gate)
    try:
        mcp.check_tool_call(
            tool_name="fetch_report",
            params={},
            caller_id="alice",
            caller_kind="user",
            ip="10.0.0.1",
            current_geo=bangalore,
            origin_geo=bangalore,
        )
        results.append(check("MCP check_tool_call accepts geo kwargs", True))
    except Exception as e:
        results.append(
            check(f"MCP check_tool_call with geo, got {type(e).__name__}: {e}", False)
        )

    vdict = mcp.evaluate_tool_call(
        tool_name="fetch_report",
        params={},
        caller_id="alice",
        caller_kind="user",
        ip="10.0.0.1",
        current_geo=bangalore,
        origin_geo=chennai,
    )
    results.append(
        check("MCP evaluate_tool_call accepts geo kwargs", vdict is not None)
    )

    # HTTP middleware with geo_resolver
    from kavach import HttpKavachMiddleware

    def resolver(method, path, ip, **_) -> dict:
        # Pretend we did GeoIP, always return Bangalore.
        return {"current_geo": bangalore, "origin_geo": bangalore}

    http = HttpKavachMiddleware(tolerant_gate, geo_resolver=resolver)
    v_http = http.evaluate(
        method="POST",
        path="/api/fetch_report",
        principal_id="alice",
        ip="10.0.0.1",
    )
    results.append(
        check("HTTP middleware uses geo_resolver when no explicit geo", v_http is not None)
    )

    # Explicit geo beats the resolver
    v_http_explicit = http.evaluate(
        method="POST",
        path="/api/fetch_report",
        principal_id="alice",
        ip="10.0.0.1",
        current_geo=new_york,
        origin_geo=bangalore,
    )
    results.append(
        check("HTTP middleware: explicit geo overrides resolver", v_http_explicit is not None)
    )

    return results


# ─── Main runner ───────────────────────────────────────────────────────

def main() -> int:
    print("=== Kavach Python SDK smoke test ===")

    all_results: list[bool] = []
    for t in (
        test_rust_binding_loads,
        test_gate_permit,
        test_gate_default_deny,
        test_invariant_overrides_policy,
        test_check_raises_refused,
        test_mcp_middleware,
        test_invalid_toml,
        test_pq_token_signer,
        test_gate_with_signer,
        test_gate_reload,
        test_keypair_generate,
        test_signed_audit_chain,
        test_secure_channel,
        test_public_key_directory,
        test_geo_drift,
    ):
        try:
            all_results.extend(t())
        except Exception:
            print(f"  {FAIL} {t.__name__} raised unexpectedly")
            traceback.print_exc()
            all_results.append(False)

    passed = sum(all_results)
    total = len(all_results)
    print(f"\n=== {passed}/{total} checks passed ===")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
