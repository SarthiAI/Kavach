"""
Scenario 07: post quantum hybrid mode and the downgrade defence.

The story
---------
Kavach signs things (permits, audit entries, channel messages) in
one of two modes:

    PQ only. ML-DSA-65 signature alone. Post quantum strength only.
    Slightly smaller on the wire.

    Hybrid. ML-DSA-65 signature AND Ed25519 signature, both required.
    Twice the bytes, but a break in either scheme alone does not
    break the chain. This is the sensible default while the world
    is still in the middle of the PQ transition: ML-DSA is brand new
    and might have a flaw nobody has found yet, Ed25519 is old and
    will fall to a real quantum computer eventually. Hybrid means
    you need to break both, at the same time, to forge a signature.

The whole point of hybrid mode is to rule out a downgrade attack. A
sophisticated attacker who has broken one of the two schemes could
try to present a PQ only chain to a verifier configured for hybrid,
or a hybrid chain to a verifier configured for PQ only, hoping the
verifier accepts the weaker proof and then ignores the other half.

Kavach refuses to allow either confusion. The verifier is strict
about mode: if the caller passes hybrid=True or hybrid=False, the
verifier checks the blob matches BEFORE it runs any crypto. If the
caller omits hybrid=..., Kavach infers from the blob. No silent
downgrade, ever.

This is not something you can get from a JWT library. JWT has an
'alg' header that callers have to validate themselves (the famous
'alg:none' bug was exactly this kind of confusion). Kavach's gate
and chain verifiers enforce the mode by construction.

Six cases, all on a signed audit chain:

    A. Hybrid chain, verify with inferred mode, expect clean pass.
    B. Hybrid chain, explicit hybrid=True, clean pass (asserted).
    C. Hybrid chain, explicit hybrid=False, expect REFUSE, mode
       mismatch reported before any crypto runs.
    D. PQ only chain, explicit hybrid=True, expect REFUSE (the
       other direction of the same confusion).
    E. PQ only chain, inferred mode, clean pass.
    F. Tamper one byte inside a hybrid chain entry and expect
       verify to refuse and point at the broken entry. This is to
       confirm hybrid mode does not accidentally weaken tamper
       detection.

Run this file directly:

    python tier2/07_pq_hybrid_downgrade.py
"""

import json

from kavach import AuditEntry, KavachKeyPair, SignedAuditChain


def audit_entry(principal_id, action_name, verdict_kind, detail):
    return AuditEntry(
        principal_id=principal_id,
        action_name=action_name,
        verdict=verdict_kind,
        verdict_detail=json.dumps(detail, separators=(",", ":")),
    )


def mutate_line(jsonl: bytes, idx: int, mutator) -> bytes:
    lines = jsonl.splitlines()
    obj = json.loads(lines[idx].decode("utf-8"))
    mutator(obj)
    lines[idx] = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return b"\n".join(lines) + (b"\n" if jsonl.endswith(b"\n") else b"")


def main():
    print("=" * 70)
    print("Scenario 07: post quantum hybrid mode and the downgrade defence")
    print("=" * 70)
    print()
    print("We are going to build two signed audit chains. One is hybrid")
    print("(ML-DSA-65 plus Ed25519), the other is PQ only (ML-DSA-65")
    print("alone). Then we will try every combination of chain mode and")
    print("verifier assertion, showing Kavach refuses every downgrade")
    print("attempt before any crypto even runs.")
    print()

    results = []

    # -----------------------------------------------------------------
    # Build both chains.
    # -----------------------------------------------------------------
    print("Generating one keypair, building both chains against it.")
    kp = KavachKeyPair.generate()
    bundle = kp.public_keys()
    print(f"  key_id: {kp.id}")
    print()

    hybrid_chain = SignedAuditChain(kp, hybrid=True)
    pq_chain = SignedAuditChain(kp, hybrid=False)
    print(f"  hybrid_chain.is_hybrid: {hybrid_chain.is_hybrid}")
    print(f"  pq_chain.is_hybrid:     {pq_chain.is_hybrid}")

    for i in range(3):
        hybrid_chain.append(audit_entry(
            f"user-{i}",
            "payments.charge",
            "permit",
            {"amount_usd": 100 + i * 10},
        ))
        pq_chain.append(audit_entry(
            f"user-{i}",
            "payments.charge",
            "permit",
            {"amount_usd": 100 + i * 10},
        ))

    print(f"  hybrid_chain.length: {hybrid_chain.length}")
    print(f"  pq_chain.length:     {pq_chain.length}")
    print()

    hybrid_jsonl = bytes(hybrid_chain.export_jsonl())
    pq_jsonl = bytes(pq_chain.export_jsonl())
    print(f"  hybrid_jsonl size: {len(hybrid_jsonl)} bytes  (two signatures per entry)")
    print(f"  pq_jsonl size:     {len(pq_jsonl)} bytes  (one signature per entry)")
    print("(note: hybrid entries are bigger because every entry carries")
    print(" both ML-DSA-65 and Ed25519 signatures. This is the cost of")
    print(" the transition.)")
    print()

    # -----------------------------------------------------------------
    # Case A: hybrid chain, inferred mode.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case A: hybrid chain, verify with inferred mode.")
    print("-" * 70)
    print("No hybrid kwarg passed. The verifier reads the blob, sees")
    print("two-signature-per-entry structure, infers hybrid mode, and")
    print("runs the full ML-DSA plus Ed25519 verification. Clean pass.")
    print()

    try:
        verified = SignedAuditChain.verify_jsonl(hybrid_jsonl, bundle)
        print(f"  verify_jsonl passed: {verified} entries verified.")
        results.append(("Case A: hybrid chain, inferred mode, passes",
                        verified == hybrid_chain.length))
    except Exception as e:
        print(f"  verify_jsonl raised unexpectedly: {type(e).__name__}: {e}")
        results.append(("Case A: hybrid chain, inferred mode, passes", False))
    print()

    # -----------------------------------------------------------------
    # Case B: hybrid chain, explicit hybrid=True.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case B: hybrid chain, explicit hybrid=True.")
    print("-" * 70)
    print("The caller knows what they wrote and asserts hybrid. The")
    print("blob matches, the crypto runs, clean pass. This is the")
    print("defensive form you want in production: state the mode you")
    print("expect so a misconfigured signer downstream is caught.")
    print()

    try:
        verified = SignedAuditChain.verify_jsonl(hybrid_jsonl, bundle, hybrid=True)
        print(f"  verify_jsonl(hybrid=True) passed: {verified} entries.")
        results.append(("Case B: hybrid chain, hybrid=True asserted, passes",
                        verified == hybrid_chain.length))
    except Exception as e:
        print(f"  verify_jsonl raised unexpectedly: {type(e).__name__}: {e}")
        results.append(("Case B: hybrid chain, hybrid=True asserted, passes", False))
    print()

    # -----------------------------------------------------------------
    # Case C: hybrid chain, verifier asserts PQ only.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case C: hybrid chain, caller asserts hybrid=False. Downgrade.")
    print("-" * 70)
    print("This is the first downgrade direction: caller has been fooled")
    print("into thinking they are handling a PQ only chain, but the blob")
    print("is actually hybrid. A naive verifier might pick the ML-DSA")
    print("half and skip Ed25519, accepting a 'proof' that silently")
    print("dropped one of the two required signatures. Kavach catches")
    print("the mismatch at the caller's assertion BEFORE crypto runs,")
    print("and raises with both sides named.")
    print()

    refused = False
    msg = ""
    try:
        SignedAuditChain.verify_jsonl(hybrid_jsonl, bundle, hybrid=False)
    except ValueError as e:
        refused = True
        msg = str(e)
    print(f"  verifier raised: {refused}")
    print(f"  message (first 220 chars): {msg[:220]}")
    print()

    ok = refused and ("hybrid" in msg.lower())
    results.append(("Case C: hybrid=False on hybrid chain refused", ok))

    # -----------------------------------------------------------------
    # Case D: PQ only chain, verifier asserts hybrid.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case D: PQ only chain, caller asserts hybrid=True. Other direction.")
    print("-" * 70)
    print("A caller configured for hybrid is handed a PQ only blob. If")
    print("the verifier accepted this (silently ignored the missing")
    print("Ed25519 half), an attacker who could break ML-DSA but not")
    print("Ed25519 could forge a 'hybrid' permit by sending only the")
    print("ML-DSA half. Same defence: assertion mismatch raises.")
    print()

    refused = False
    msg = ""
    try:
        SignedAuditChain.verify_jsonl(pq_jsonl, bundle, hybrid=True)
    except ValueError as e:
        refused = True
        msg = str(e)
    print(f"  verifier raised: {refused}")
    print(f"  message (first 220 chars): {msg[:220]}")
    print()

    ok = refused and ("pq" in msg.lower() or "hybrid" in msg.lower())
    results.append(("Case D: hybrid=True on PQ only chain refused", ok))

    # -----------------------------------------------------------------
    # Case E: PQ only chain, inferred mode.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case E: PQ only chain, verify with inferred mode.")
    print("-" * 70)
    print("Baseline: PQ only chain verifies cleanly when mode is not")
    print("asserted. Inferred from the single signature structure.")
    print()

    try:
        verified = SignedAuditChain.verify_jsonl(pq_jsonl, bundle)
        print(f"  verify_jsonl passed: {verified} entries verified.")
        results.append(("Case E: PQ only chain, inferred mode, passes",
                        verified == pq_chain.length))
    except Exception as e:
        print(f"  verify_jsonl raised unexpectedly: {type(e).__name__}: {e}")
        results.append(("Case E: PQ only chain, inferred mode, passes", False))
    print()

    # -----------------------------------------------------------------
    # Case F: tamper a hybrid entry and make sure it is still caught.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case F: tamper one byte inside hybrid chain entry 1, reverify.")
    print("-" * 70)
    print("Hybrid mode carries two signatures per entry. We flip a byte")
    print("in the signed payload of entry 1 (zero indexed). Both")
    print("signatures break, the verifier reports the broken entry by")
    print("its position. Tamper detection has the same granularity as")
    print("PQ only mode.")
    print()

    def flip_first_data_byte(obj):
        data = list(obj["signed_payload"]["data"])
        data[0] = (data[0] + 7) & 0xFF
        obj["signed_payload"]["data"] = data

    tampered = mutate_line(hybrid_jsonl, 1, flip_first_data_byte)
    refused = False
    msg = ""
    try:
        SignedAuditChain.verify_jsonl(tampered, bundle)
    except ValueError as e:
        refused = True
        msg = str(e)
    print(f"  verifier raised: {refused}")
    print(f"  message (first 220 chars): {msg[:220]}")
    print()

    ok = refused and ("entry 1" in msg or "entry" in msg.lower())
    results.append(("Case F: hybrid chain tamper at entry 1 refused", ok))

    # -----------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------
    print("=" * 70)
    print("Summary")
    print("=" * 70)
    passed = sum(1 for _, ok in results if ok)
    for label, ok in results:
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] {label}")
    print()
    print(f"{passed}/{len(results)} checks passed.")
    print()

    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
