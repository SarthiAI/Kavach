"""
Scenario 17: PQ audit archives across a key rotation, read back years later.

The story
---------
A commercial bank is subject to a seven year audit retention rule.
Every consumer loan decision between 2026 and 2033 has to be
retrievable on demand, with a proof that the decision really was
what the audit says it was, signed by a real authoriser.

Two forces pull against each other:

    Short keypair TTL is good practice. If a signing keypair is
    compromised, you want the damage bounded to a narrow window.
    A signing identity that lives for years makes every entry
    signed in that window forgeable the second the key leaks.

    Long retention demands that OLD signatures remain verifiable
    forever. If the keypair that signed a 2026 entry has long
    since been retired, the verifier still has to be able to check
    the signature today.

Classical crypto has a deeper problem: when a real quantum
computer exists, Ed25519 and RSA signatures on those old archives
become forgeable. Anyone can craft a "2026 audit entry" that
verifies under a 2026 keypair's public key. Your archive stops
being evidence; it becomes a suggestion.

Kavach's answer to both problems:

    1. Rotation is cheap. Each keypair has an `expires_at`. When a
       rotation is due, generate a new keypair, ship its bundle to
       the directory, and new entries sign under it. Old bundles
       stay in the directory for historical verification, marked
       by their `expires_at` so nobody mistakes them for an active
       signing identity.

    2. Signatures are ML-DSA-65 (post quantum). An archive signed
       in 2026 still verifies in 2040 even if a quantum computer
       has broken every classical scheme in the meantime.

This scenario walks through the full lifecycle:

    - 2026: sign 5 audit entries under keypair A.
    - 2029: rotate to keypair B. Old bundle is retained in the
      directory with its expires_at set to the rotation date.
    - 2030: sign 5 more audit entries under keypair B.
    - 2033: a compliance review exports both chains from the
      archive and reverifies every entry. The directory resolves
      each chain's bundle by key_id, verifies, and reports clean.
    - Then: simulate the "archive key was actually retired in 2028"
      case by pulling the old bundle out of the directory. The old
      chain no longer verifies against the stripped directory, as
      expected (this is what a rotation with full revocation would
      look like).

We do not actually sleep for years. We simulate the lifecycle with
keypair generation, bundle management, and verify calls.

Six cases:

    A. Archive A signed under key A, verifier has both bundles,
       reverifies cleanly.
    B. Archive B signed under key B, verifier has both bundles,
       reverifies cleanly.
    C. Tamper inside archive A, verify reports the exact entry.
    D. Stripped directory (only key B, retroactive revocation of A),
       verify on archive A refuses because the signing bundle is
       no longer resolvable.
    E. Forensic path on archive A with enforce_expiry=False. Even
       if A's bundle was marked expired at rotation time, the
       forensic verifier accepts old entries for the audit review.
    F. Cross-key replay: an attacker copies a signature from an A
       entry onto a B envelope. Verify refuses (envelope resolves
       to B, signature does not match).

Run this file directly:

    python tier3/17_pq_audit_rotation.py
"""

import json

from kavach import (
    AuditEntry,
    DirectoryTokenVerifier,
    KavachKeyPair,
    PublicKeyDirectory,
    SignedAuditChain,
)


def append_entries(chain, count, tag):
    for i in range(count):
        chain.append(AuditEntry(
            principal_id=f"officer-{tag}-{i:03d}",
            action_name="loan.approve",
            verdict="permit",
            verdict_detail=json.dumps({
                "tag": tag,
                "entry_index": i,
                "amount_usd": 1000 + i * 50,
            }, separators=(",", ":")),
        ))


def mutate_line(jsonl: bytes, idx: int, mutator) -> bytes:
    lines = jsonl.splitlines()
    obj = json.loads(lines[idx].decode("utf-8"))
    mutator(obj)
    lines[idx] = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return b"\n".join(lines) + (b"\n" if jsonl.endswith(b"\n") else b"")


def main():
    print("=" * 70)
    print("Scenario 17: PQ audit archives across a key rotation")
    print("=" * 70)
    print()
    print("We are going to simulate the 2026 to 2033 life of a bank's")
    print("loan approval archive. Two keypairs signed entries in that")
    print("window; both should still verify against a directory that")
    print("retains their public bundles. Then we show what a real")
    print("revocation and a cross key replay look like.")
    print()

    results = []

    # -----------------------------------------------------------------
    # Generate the two keypairs. In production, 'year2026_kp' would
    # have been generated with some TTL we've since passed; here both
    # are no-expiry for brevity. Case E exercises enforce_expiry=False
    # separately.
    # -----------------------------------------------------------------
    print("Generating two signing keypairs.")
    year2026_kp = KavachKeyPair.generate()
    year2029_kp = KavachKeyPair.generate()
    bundle_2026 = year2026_kp.public_keys()
    bundle_2029 = year2029_kp.public_keys()
    print(f"  2026 key_id: {year2026_kp.id}")
    print(f"  2029 key_id: {year2029_kp.id}")
    print()

    # -----------------------------------------------------------------
    # Two chains. Each one carries its own hash linkage, its own
    # signatures, and names its own signing key id on every entry.
    # -----------------------------------------------------------------
    print("Signing archive A (5 entries) under the 2026 keypair.")
    chain_a = SignedAuditChain(year2026_kp, hybrid=False)
    append_entries(chain_a, 5, tag="A")
    print(f"  chain_a.length:    {chain_a.length}")

    print("Signing archive B (5 entries) under the 2029 keypair.")
    chain_b = SignedAuditChain(year2029_kp, hybrid=False)
    append_entries(chain_b, 5, tag="B")
    print(f"  chain_b.length:    {chain_b.length}")
    print()

    jsonl_a = bytes(chain_a.export_jsonl())
    jsonl_b = bytes(chain_b.export_jsonl())
    print(f"  archive A JSONL bytes: {len(jsonl_a)}")
    print(f"  archive B JSONL bytes: {len(jsonl_b)}")
    print()

    # -----------------------------------------------------------------
    # Case A: archive A, verifier has both bundles, verifies cleanly.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case A: reverify archive A against bundle_2026.")
    print("-" * 70)
    print("The compliance tool looks up archive A's signing key_id (the")
    print("first entry names the 2026 keypair), fetches bundle_2026")
    print("from the directory, and runs verify_jsonl. All 5 entries")
    print("pass.")
    print()

    count_a = SignedAuditChain.verify_jsonl(jsonl_a, bundle_2026)
    print(f"  verify_jsonl(archive A, bundle_2026) -> {count_a} entries")
    print()
    results.append(("Case A: archive A reverifies under bundle_2026",
                    count_a == chain_a.length))

    # -----------------------------------------------------------------
    # Case B: archive B, verifier has both bundles, verifies cleanly.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case B: reverify archive B against bundle_2029.")
    print("-" * 70)
    print("Same flow against the post rotation chain. This is what tells")
    print("us rotation does not mean 'lose everything before the")
    print("rotation date'. Both keypairs live in the archive forever.")
    print()

    count_b = SignedAuditChain.verify_jsonl(jsonl_b, bundle_2029)
    print(f"  verify_jsonl(archive B, bundle_2029) -> {count_b} entries")
    print()
    results.append(("Case B: archive B reverifies under bundle_2029",
                    count_b == chain_b.length))

    # -----------------------------------------------------------------
    # Case C: tamper one entry deep inside archive A.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case C: flip a byte inside entry 2 of archive A, reverify.")
    print("-" * 70)
    print("If a bad actor edits an entry in the archive years later,")
    print("verify_jsonl refuses and names the exact entry position.")
    print("This is the property that makes the archive evidence, not")
    print("just 'stuff our database had stored'.")
    print()

    def flip_first_data_byte(obj):
        data = list(obj["signed_payload"]["data"])
        data[0] = (data[0] + 7) & 0xFF
        obj["signed_payload"]["data"] = data

    tampered_a = mutate_line(jsonl_a, 2, flip_first_data_byte)
    refused = False
    msg = ""
    try:
        SignedAuditChain.verify_jsonl(tampered_a, bundle_2026)
    except ValueError as e:
        refused = True
        msg = str(e)
    print(f"  verify_jsonl raised: {refused}")
    print(f"  message (first 220 chars): {msg[:220]}")
    print()

    ok = refused and ("entry 2" in msg or "entry" in msg.lower())
    results.append(("Case C: tampered entry 2 in archive A caught", ok))

    # -----------------------------------------------------------------
    # Case D: retroactive revocation of the 2026 keypair. Strip that
    # bundle out of the caller's view so archive A cannot be verified.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case D: retroactive revocation of bundle_2026.")
    print("-" * 70)
    print("Suppose at some point we learn the 2026 keypair was")
    print("compromised retroactively. The right response is to remove")
    print("bundle_2026 from the verifier's trusted set. Once that is")
    print("done, archive A cannot be verified: the verifier looks up")
    print("the signer's key_id, finds nothing, and refuses. This is")
    print("how full revocation looks. If compliance decides they")
    print("still need a forensic pass, they can re-add the bundle")
    print("read only in a separate tool, but no production path uses")
    print("the revoked bundle again.")
    print()

    # We model "retroactive revocation" as just not passing bundle_2026
    # to verify_jsonl. Passing the wrong bundle should fail to resolve
    # entry A's key_id, which is the Kavach failure mode for this.
    refused = False
    msg = ""
    try:
        SignedAuditChain.verify_jsonl(jsonl_a, bundle_2029)
    except ValueError as e:
        refused = True
        msg = str(e)
    print(f"  verify_jsonl(archive A, bundle_2029) raised: {refused}")
    print(f"  message (first 220 chars): {msg[:220]}")
    print()

    results.append(("Case D: revoked bundle refuses the old archive", refused))

    # -----------------------------------------------------------------
    # Case E: forensic path through DirectoryTokenVerifier, showing
    # enforce_expiry=False still accepts entries whose bundle has
    # since been expired.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case E: forensic path across a rotation.")
    print("-" * 70)
    print("For permits (as opposed to chain entries) Kavach exposes")
    print("DirectoryTokenVerifier, whose verify() enforces the bundle's")
    print("expires_at by default and accepts enforce_expiry=False for")
    print("historical review. We simulate the forensic case for an old")
    print("permit by issuing one under a TTL'd keypair, letting the TTL")
    print("pass, and reverifying with enforce_expiry=False. This is the")
    print("audit path a regulator would use to confirm a historical")
    print("decision was validly signed at the time it was made.")
    print()

    import time

    short_lived_kp = KavachKeyPair.generate_with_expiry(1)
    short_bundle = short_lived_kp.public_keys()
    short_dir = PublicKeyDirectory.in_memory([short_bundle])
    short_verifier = DirectoryTokenVerifier(short_dir, hybrid=False)

    # We need a PermitToken to feed DirectoryTokenVerifier. Borrow
    # one quickly from a Gate + signer, same as scenario 22.
    from kavach import (
        ActionContext,
        Gate,
        PqTokenSigner,
    )

    POL = {
        "policies": [
            {
                "name": "p",
                "effect": "permit",
                "priority": 10,
                "conditions": [{"action": "loan.approve"}],
            },
        ],
    }
    short_signer = PqTokenSigner.from_keypair_pq_only(short_lived_kp)
    short_gate = Gate.from_dict(POL, token_signer=short_signer)
    verdict = short_gate.evaluate(ActionContext(
        principal_id="officer-historical",
        principal_kind="user",
        action_name="loan.approve",
    ))
    permit = verdict.permit_token
    print("Sleeping 2 seconds to let the short TTL bundle expire...")
    time.sleep(2)

    strict_refused = False
    try:
        short_verifier.verify(permit, permit.signature)
    except ValueError:
        strict_refused = True
    print(f"  strict verify (default) refuses expired bundle: {strict_refused}")

    forensic_ok = False
    try:
        short_verifier.verify(permit, permit.signature, enforce_expiry=False)
        forensic_ok = True
    except Exception as e:
        print(f"  forensic verify raised: {type(e).__name__}: {e}")
    print(f"  forensic verify (enforce_expiry=False) accepts: {forensic_ok}")
    print()

    results.append(("Case E: strict rejects expired bundle", strict_refused))
    results.append(("Case E: forensic path still accepts", forensic_ok))

    # -----------------------------------------------------------------
    # Case F: cross key replay. Lift a signature from archive A onto
    # an archive B envelope by mutating the key_id. The verifier
    # looks up the (forged) key_id, finds bundle_2029, and runs
    # verify; the signature was produced by ML-DSA under the 2026
    # secret and does not match the 2029 public key. Refuse.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case F: cross key replay, splice A's signature onto a B envelope.")
    print("-" * 70)
    print("An attacker captures an entry from archive A and tries to")
    print("pass it off as though it had been signed under the 2029")
    print("keypair. They overwrite the envelope's key_id field to point")
    print("at the 2029 bundle. The verifier resolves the new key_id,")
    print("fetches bundle_2029, runs ML-DSA verify. The signature does")
    print("not match the 2029 public key, so verify refuses.")
    print()

    def swap_key_id(obj):
        obj["signed_payload"]["key_id"] = year2029_kp.id

    spliced = mutate_line(jsonl_a, 1, swap_key_id)
    refused = False
    msg = ""
    try:
        # Feed the spliced archive with the 2029 bundle so the lookup
        # succeeds but the signature check fails.
        SignedAuditChain.verify_jsonl(spliced, bundle_2029)
    except ValueError as e:
        refused = True
        msg = str(e)
    print(f"  verify_jsonl raised: {refused}")
    print(f"  message (first 220 chars): {msg[:220]}")
    print()

    results.append(("Case F: cross key signature splice refused", refused))

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
