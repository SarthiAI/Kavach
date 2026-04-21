"""
Scenario 06: ephemeral PQ permits replacing static API keys.

The story
---------
A fintech service calls five downstream vendors: Stripe for cards,
Adyen for EU cards, Plaid for bank verification, Onfido for KYC,
and an internal wallet. The classical way to authenticate is with
a long lived bearer API key per vendor. The keys sit in a secret
store, get injected at boot, and stay valid for weeks or months.
If one ever leaks (log line, cached HAR, compromised CI runner),
the attacker owns that vendor integration until somebody notices
and rotates.

Kavach's answer: every outbound call carries a freshly signed
short TTL permit instead of a static key. The permit is signed by
an ML-DSA-65 keypair whose bundle is pinned by the vendor's
verifier against a root signed directory. When the bundle expires,
every permit ever signed by it stops verifying, not at the next
rotation window but at the second the bundle's expires_at is past.

Short timescales in this demo
-----------------------------
The signing keypair in this scenario expires in 2 seconds to
keep the script fast. In production, tens of seconds to a few
minutes is typical, bounded by clock skew between services.

Three things this buys you:

    1. A captured permit cannot be reused after the keypair's TTL.

    2. Rotation is not an emergency. Rotate the keypair, ship the
       new bundle into the directory, done. The old keypair
       naturally expires and every still-in-flight permit signed
       by it also expires. There is no race between 'I changed the
       secret' and 'the old secret still works'.

    3. Post-quantum signatures. The signature is ML-DSA-65, the
       NIST standardised post-quantum scheme. Classical signatures
       (RSA, Ed25519) remain secure today, but audit archives that
       outlive the quantum transition are on firmer ground with a
       PQ scheme from day one. Kavach's hybrid mode combines both
       when you want belt and suspenders.

Four cases:

    A. Fresh keypair, permit issued, verified inside the TTL. Pass.
    B. Wait past the keypair's expiry, reverify the SAME permit.
       Rejected because the signing bundle is expired.
    C. Forensic verify with enforce_expiry=False still accepts,
       for audit trails that need to re-check archived signatures
       against bundles that have since expired.
    D. Rotation: a second keypair is generated, its bundle is added
       to the directory, a new permit signed under it verifies
       cleanly. The old keypair's bundle remains so historical
       forensic verification still works.

Run this file directly:

    python tier2/06_ephemeral_permits.py
"""

import time

from kavach import (
    ActionContext,
    DirectoryTokenVerifier,
    Gate,
    KavachKeyPair,
    PqTokenSigner,
    PublicKeyDirectory,
)


# Keep the TTL small so the scenario runs in a few seconds.
KEY_TTL_SECONDS = 2
SLEEP_SECONDS = 3


POLICIES = {
    "policies": [
        {
            "name": "vendor_call",
            "description": "Fintech may call vendor APIs",
            "effect": "permit",
            "priority": 10,
            "conditions": [
                {"identity_role": "fintech_service"},
                {"action": "vendor.call"},
            ],
        },
    ],
}


def main():
    print("=" * 70)
    print("Scenario 06: ephemeral PQ permits replacing static API keys")
    print("=" * 70)
    print()
    print("(The keypair TTL is 2 seconds so this script runs fast; in")
    print(" production, tens of seconds to a few minutes is typical.)")
    print()
    print("We are going to generate a signing keypair with a 2 second")
    print("TTL, sign one permit, verify it cleanly, wait 3 seconds, then")
    print("try to verify the SAME permit. The verifier will refuse")
    print("because the signing bundle's expiry has passed. After that we")
    print("check the forensic path and rotation flow.")
    print()

    results = []

    # -----------------------------------------------------------------
    # Set up a short lived signing keypair and the directory used by
    # the vendor's verifier.
    # -----------------------------------------------------------------
    print(f"Generating a signing keypair with TTL = {KEY_TTL_SECONDS} seconds.")
    signing_kp = KavachKeyPair.generate_with_expiry(KEY_TTL_SECONDS)
    bundle = signing_kp.public_keys()
    print(f"  signing.key_id:     {signing_kp.id}")
    print(f"  signing.expires_at: {signing_kp.expires_at}")
    print(f"  is_expired now:     {signing_kp.is_expired}")
    print()

    directory = PublicKeyDirectory.in_memory([bundle])
    verifier = DirectoryTokenVerifier(directory, hybrid=False)
    print(f"  directory.length:   {directory.length}")
    print()

    signer = PqTokenSigner.from_keypair_pq_only(signing_kp)
    gate = Gate.from_dict(POLICIES, token_signer=signer)
    print(f"  gate.evaluator_count: {gate.evaluator_count}")
    print()

    # -----------------------------------------------------------------
    # Case A: within the TTL window, happy path.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case A: fintech service calls Stripe, verifier accepts the permit.")
    print("-" * 70)
    print("Fresh keypair, fresh permit, verifier's enforce_expiry=True")
    print("default kicks in, bundle.expires_at is in the future, signature")
    print("checks out. This is the everyday case: a permit signed thirty")
    print("milliseconds ago, verified against a bundle that is good for")
    print("another two seconds.")
    print()

    ctx = ActionContext(
        principal_id="fintech-service",
        principal_kind="service",
        action_name="vendor.call",
        roles=["fintech_service"],
    )
    verdict = gate.evaluate(ctx)
    permit = verdict.permit_token

    print(f"gate.evaluate().kind:   {verdict.kind}")
    print(f"permit.token_id:        {permit.token_id}")
    print(f"permit.issued_at:       {permit.issued_at}")
    print(f"permit.expires_at:      {permit.expires_at}")
    print()

    verify_ok = False
    try:
        verifier.verify(permit, permit.signature)
        verify_ok = True
        print("verifier.verify(): accepted.")
    except Exception as e:
        print(f"verifier raised unexpectedly: {type(e).__name__}: {e}")
    print()

    results.append(("Case A: in TTL window, verify passes", verify_ok))

    # -----------------------------------------------------------------
    # Case B: past the TTL, verify refuses by default.
    # -----------------------------------------------------------------
    print("-" * 70)
    print(f"Case B: sleep {SLEEP_SECONDS} seconds, past the keypair's TTL.")
    print("-" * 70)
    print("Same permit bytes as in Case A. We did not touch it. The only")
    print("thing that changed is the wall clock: the signing bundle's")
    print("expires_at is now in the past. The verifier's default")
    print("(enforce_expiry=True) refuses. This is what makes a leaked")
    print("permit from a logs dump useless after the window. A static")
    print("API key in the same situation would still authenticate.")
    print()

    time.sleep(SLEEP_SECONDS)
    print(f"  signing_kp.is_expired (after sleep): {signing_kp.is_expired}")

    refused = False
    msg = ""
    try:
        verifier.verify(permit, permit.signature)
    except ValueError as e:
        refused = True
        msg = str(e)
    print(f"  verifier raised: {refused}")
    print(f"  message (first 200 chars): {msg[:200]}")
    print()

    ok = refused and ("expired" in msg.lower() or "expire" in msg.lower())
    results.append(("Case B: past TTL, default verify refuses", ok))

    # -----------------------------------------------------------------
    # Case C: forensic verify with enforce_expiry=False still accepts.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case C: forensic path, enforce_expiry=False.")
    print("-" * 70)
    print("A compliance tool re-checks an archived permit against the")
    print("directory months after the fact, asking only 'was this")
    print("signature valid at the time?'. Passing enforce_expiry=False")
    print("skips the TTL check and runs the crypto anyway. This is the")
    print("one, carefully labelled, opt out. No production authorisation")
    print("path should ever set this flag.")
    print()

    forensic_ok = False
    try:
        verifier.verify(permit, permit.signature, enforce_expiry=False)
        forensic_ok = True
        print("verifier.verify(enforce_expiry=False): accepted.")
    except Exception as e:
        print(f"forensic verify raised unexpectedly: {type(e).__name__}: {e}")
    print()

    results.append(("Case C: forensic verify still accepts", forensic_ok))

    # -----------------------------------------------------------------
    # Case D: rotation, new keypair, new bundle in the directory.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case D: rotate to a fresh keypair, sign again, verify.")
    print("-" * 70)
    print("The fintech service rotates. A new keypair is generated with")
    print("a fresh TTL. The new bundle is added to the directory. The")
    print("old bundle stays, so Case C's forensic path keeps working.")
    print("A new permit is signed under the new keypair and verifies")
    print("cleanly. This is what a zero downtime rotation looks like:")
    print("no window where 'the old key still works and the new key")
    print("does not', because every permit names its signing key id")
    print("inside the envelope and the verifier looks up the right")
    print("bundle by id.")
    print()

    new_kp = KavachKeyPair.generate_with_expiry(60)
    new_bundle = new_kp.public_keys()
    new_signer = PqTokenSigner.from_keypair_pq_only(new_kp)

    # Rebuild directory with BOTH old (for forensic) and new (for auth).
    rotated_directory = PublicKeyDirectory.in_memory([bundle, new_bundle])
    rotated_verifier = DirectoryTokenVerifier(rotated_directory, hybrid=False)
    print(f"  rotated directory length: {rotated_directory.length}")

    # Build a fresh gate under the new signer.
    new_gate = Gate.from_dict(POLICIES, token_signer=new_signer)
    ctx_new = ActionContext(
        principal_id="fintech-service",
        principal_kind="service",
        action_name="vendor.call",
        roles=["fintech_service"],
    )
    v_new = new_gate.evaluate(ctx_new)
    new_permit = v_new.permit_token
    print(f"  new permit token_id: {new_permit.token_id}")

    new_verify_ok = False
    try:
        rotated_verifier.verify(new_permit, new_permit.signature)
        new_verify_ok = True
        print("rotated_verifier.verify() on new permit: accepted.")
    except Exception as e:
        print(f"new permit verify raised unexpectedly: {type(e).__name__}: {e}")

    # The old permit should still refuse under the rotated verifier's
    # default, because the old bundle is still expired.
    old_refused = False
    try:
        rotated_verifier.verify(permit, permit.signature)
    except ValueError:
        old_refused = True
    print(f"  old permit still refused by rotated verifier: {old_refused}")
    print()

    results.append(("Case D: new keypair signs, new permit verifies", new_verify_ok))
    results.append(("Case D: old expired permit still refused", old_refused))

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
