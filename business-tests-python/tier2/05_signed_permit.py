"""
Scenario 05: signed permit token crossing a service boundary.

The story
---------
A financial platform splits "who is authorised" from "who actually
moves the money" across two services:

    Auth service      : holds the signing keys. Runs Kavach's policy
                        chain for every charge request. If the rules
                        permit, returns a permit token signed with
                        ML-DSA-65 (a post quantum signature scheme)
                        over a canonical payload.

    Payments service  : does not hold any policy. It takes the permit
                        token off the wire and verifies it against a
                        public key directory. If the signature checks
                        out, the token is trusted. If not, the request
                        is refused before the payment rail ever sees
                        it.

This split is how Kavach's multi service story works in practice.
The permit token is the single source of truth for "this action was
authorised at this time for this principal". Payments never has to
re-run the policy chain, it only has to verify the signature.

We will show four things:

    1. Happy path. Auth permits a $250 charge. Payments verifies
       the signature against its trusted directory. Accept.

    2. Action swap attack. An attacker captures the permit for
       'payments.charge' and relabels it 'payments.refund' before
       forwarding. The signature covers the action name, so the
       verify must fail.

    3. Evaluation id swap attack. Attacker captures two real permits
       (say, two real charges), lifts the evaluation id from one
       and grafts it onto the envelope of the other. The signature
       covers the evaluation id, so the verify must fail.

    4. Forged permit. Attacker spins up their own ML-DSA keypair,
       signs a fabricated permit, and sends it to Payments. The
       rogue key is not in the trusted directory, so verify fails
       with 'public key not found' before any crypto even runs.

Run this file directly:

    python tier2/05_signed_permit.py
"""

import tempfile
import uuid
from pathlib import Path

from kavach import (
    ActionContext,
    DirectoryTokenVerifier,
    Gate,
    KavachKeyPair,
    PermitToken,
    PqTokenSigner,
    PublicKeyDirectory,
)


# ---------------------------------------------------------------------
# Step 1. Write the Auth service's permit rule.
# ---------------------------------------------------------------------
# A customer may charge a card up to $500 per call. Nothing fancy,
# this scenario is about the signed token and the verification on the
# other side.

POLICIES = {
    "policies": [
        {
            "name": "customer_may_charge_under_cap",
            "description": "Any customer may charge a card up to $500 per call",
            "effect": "permit",
            "priority": 10,
            "conditions": [
                {"identity_role": "customer"},
                {"action": "payments.charge"},
                {"param_max": {"field": "amount_usd", "max": 500.0}},
            ],
        },
    ],
}


def main():
    print("=" * 70)
    print("Scenario 05: signed permit token crossing a service boundary")
    print("=" * 70)
    print()
    print("We are going to set up two services. Auth holds the signing")
    print("keys and runs the Kavach policy chain. Payments holds no")
    print("policy, only a trusted public key directory. We show the")
    print("happy path first, then three attacks that the directory")
    print("verifier must refuse.")
    print()

    results = []

    # -----------------------------------------------------------------
    # Step 2. Generate two keypairs: one for Auth, one for the directory root.
    # -----------------------------------------------------------------
    # The root keypair signs the directory manifest at deploy time.
    # Payments holds only the root's verifying key, which is how we
    # bootstrap trust: any bundle listed in a manifest the root
    # signed is treated as a trusted identity.
    print("Generating two keypairs.")
    auth_kp = KavachKeyPair.generate()
    root_kp = KavachKeyPair.generate()
    auth_bundle = auth_kp.public_keys()
    root_bundle = root_kp.public_keys()
    print(f"  auth.key_id: {auth_kp.id}")
    print(f"  root.key_id: {root_kp.id}")
    print()

    # -----------------------------------------------------------------
    # Step 3. Build a root signed directory manifest.
    # -----------------------------------------------------------------
    # Operator writes a JSON manifest that lists every trusted auth
    # bundle, signed by the root keypair. Payments verifies this
    # signature once at startup using the pinned root verifying key;
    # any bundle in that manifest is then a first class identity.
    print("Building a root signed directory manifest that lists the auth bundle.")
    manifest_bytes = bytes(root_kp.build_signed_manifest([auth_bundle]))
    tmpdir = Path(tempfile.mkdtemp(prefix="kavach-07-"))
    manifest_path = tmpdir / "trusted_signers.json"
    manifest_path.write_bytes(manifest_bytes)
    print(f"  manifest written to: {manifest_path}")
    print(f"  manifest size:       {len(manifest_bytes)} bytes")
    print()

    print("Loading the directory into Payments and building the verifier.")
    directory = PublicKeyDirectory.from_signed_file(
        str(manifest_path),
        root_bundle.ml_dsa_verifying_key,
    )
    print(f"  directory.length:   {directory.length}")
    print(f"  directory.is_empty: {directory.is_empty}")
    verifier = DirectoryTokenVerifier(directory, hybrid=False)
    print()

    # -----------------------------------------------------------------
    # Step 4. Build the Auth gate, with the token signer attached.
    # -----------------------------------------------------------------
    print("Building Auth's gate with its signer attached.")
    signer = PqTokenSigner.from_keypair_pq_only(auth_kp)
    print(f"  signer.is_hybrid: {signer.is_hybrid}")
    print(f"  signer.key_id:    {signer.key_id}")
    gate = Gate.from_dict(POLICIES, token_signer=signer)
    print(f"  gate.evaluator_count: {gate.evaluator_count}")
    print()

    # -----------------------------------------------------------------
    # Case 1: happy path.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case 1: customer charges $250. Auth permits, Payments verifies.")
    print("-" * 70)
    print("Auth runs the policy chain, which permits ($250 is under the")
    print("$500 cap). Auth returns a signed permit token. Payments calls")
    print("verifier.verify(token, token.signature) and accepts. This is")
    print("the baseline that says the signing and verification loop")
    print("works end to end.")
    print()

    ctx = ActionContext(
        principal_id="cust-7f11",
        principal_kind="user",
        action_name="payments.charge",
        roles=["customer"],
        params={"amount_usd": 250.0},
    )
    real_verdict = gate.evaluate(ctx)

    print(f"Auth verdict kind:   {real_verdict.kind}")
    print(f"Auth is permit:      {real_verdict.is_permit}")
    print(f"Permit token id:     {real_verdict.token_id}")
    real_token = real_verdict.permit_token
    print(f"Permit action_name:  {real_token.action_name if real_token else None}")
    print()

    results.append(("Case 1: Auth permits a $250 charge", real_verdict.is_permit))
    results.append(("Case 1: verdict carries a permit token", real_token is not None))

    print("Payments verifies the permit:")
    try:
        verifier.verify(real_token, real_token.signature)
        print("  directory.verify() accepted the permit.")
        results.append(("Case 1: Payments accepts the real permit", True))
    except Exception as e:
        print(f"  directory.verify() raised unexpectedly: {type(e).__name__}: {e}")
        results.append(("Case 1: Payments accepts the real permit", False))
    print()

    # -----------------------------------------------------------------
    # Case 2: action swap attack.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case 2: attacker relabels the permit from 'charge' to 'refund'.")
    print("-" * 70)
    print("The attacker keeps the original signature bytes and every")
    print("other field identical, but overwrites action_name. The")
    print("signature covers the canonical serialisation of the token,")
    print("which includes the action name. So when the verifier")
    print("recomputes the canonical payload, the bytes do not match")
    print("what was signed, and the ML-DSA check fails.")
    print()

    tampered_action = PermitToken(
        token_id=real_token.token_id,
        evaluation_id=real_token.evaluation_id,
        issued_at=real_token.issued_at,
        expires_at=real_token.expires_at,
        action_name="payments.refund",
        signature=real_token.signature,
    )
    print(f"  original action_name:  {real_token.action_name}")
    print(f"  tampered action_name:  {tampered_action.action_name}")
    print(f"  signature bytes reused: {len(bytes(real_token.signature))} bytes")
    print()
    try:
        verifier.verify(tampered_action, tampered_action.signature)
        print("  directory.verify() accepted the permit when it should have refused.")
        results.append(("Case 2: action swap is refused", False))
    except ValueError as e:
        msg = str(e)
        ok = "signature verification failed" in msg
        print("  directory.verify() raised ValueError as expected.")
        print(f"  message (first 180 chars): {msg[:180]}")
        results.append(("Case 2: action swap is refused", ok))
    print()

    # -----------------------------------------------------------------
    # Case 3: evaluation id swap attack.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case 3: attacker grafts another permit's evaluation id.")
    print("-" * 70)
    print("More realistic attack. Auth has issued many valid permits")
    print("over time. Attacker captures two of them, lifts the")
    print("evaluation id from permit B and pastes it onto permit A's")
    print("envelope, hoping that downstream logs show 'fresh activity'")
    print("tied to B's id. The signature on permit A covered permit")
    print("A's evaluation id, so swapping it (even to another valid")
    print("id from elsewhere) breaks the signature check.")
    print()

    ctx_second = ActionContext(
        principal_id="cust-9e42",
        principal_kind="user",
        action_name="payments.charge",
        roles=["customer"],
        params={"amount_usd": 100.0},
    )
    second_verdict = gate.evaluate(ctx_second)
    second_token = second_verdict.permit_token
    print(f"  permit A evaluation_id: {real_token.evaluation_id}")
    print(f"  permit B evaluation_id: {second_token.evaluation_id}")

    tampered_eid = PermitToken(
        token_id=real_token.token_id,
        evaluation_id=second_token.evaluation_id,
        issued_at=real_token.issued_at,
        expires_at=real_token.expires_at,
        action_name=real_token.action_name,
        signature=real_token.signature,
    )
    print(f"  spliced onto A's envelope: {tampered_eid.evaluation_id}")
    print()

    try:
        verifier.verify(tampered_eid, tampered_eid.signature)
        print("  directory.verify() accepted the permit when it should have refused.")
        results.append(("Case 3: evaluation id swap is refused", False))
    except ValueError as e:
        msg = str(e)
        ok = "signature verification failed" in msg
        print("  directory.verify() raised ValueError as expected.")
        print(f"  message (first 180 chars): {msg[:180]}")
        results.append(("Case 3: evaluation id swap is refused", ok))
    print()

    # -----------------------------------------------------------------
    # Case 4: forged permit from a rogue keypair.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case 4: attacker signs a fabricated permit with their own key.")
    print("-" * 70)
    print("Attacker generates their own ML-DSA keypair, signs a crafted")
    print("permit, and forwards it to Payments. The signature is")
    print("perfectly valid against the attacker's own public key, but")
    print("their public key is not in the trusted directory. The")
    print("verifier resolves the envelope's key id, finds nothing, and")
    print("raises ValueError with 'public key not found'. No crypto")
    print("even runs in this path, the lookup fails first.")
    print()

    rogue_kp = KavachKeyPair.generate()
    rogue_bundle = rogue_kp.public_keys()
    rogue_signer = PqTokenSigner.from_keypair_pq_only(rogue_kp)
    print(f"  rogue key_id:          {rogue_kp.id}")
    print(f"  trusted auth key_id:   {auth_kp.id}")
    print(f"  is the rogue key in the trusted directory? no")
    print()

    forged_base = PermitToken(
        token_id=str(uuid.uuid4()),
        evaluation_id=str(uuid.uuid4()),
        issued_at=real_token.issued_at,
        expires_at=real_token.expires_at,
        action_name="payments.charge",
        signature=b"\x00",
    )
    forged_signature = bytes(rogue_signer.sign(forged_base))
    forged_token = PermitToken(
        token_id=forged_base.token_id,
        evaluation_id=forged_base.evaluation_id,
        issued_at=forged_base.issued_at,
        expires_at=forged_base.expires_at,
        action_name=forged_base.action_name,
        signature=forged_signature,
    )
    try:
        verifier.verify(forged_token, forged_token.signature)
        print("  directory.verify() accepted the permit when it should have refused.")
        results.append(("Case 4: rogue key forgery is refused", False))
    except ValueError as e:
        msg = str(e)
        ok = "public key not found" in msg
        print("  directory.verify() raised ValueError as expected.")
        print(f"  message (first 180 chars): {msg[:180]}")
        results.append(("Case 4: rogue key forgery is refused", ok))
    print()

    # Sanity check: the rogue signature IS valid against a directory
    # that only contains the rogue bundle. The trust boundary is the
    # root signed directory, not the signature itself.
    print("  Sanity check: the forgery does verify against a directory")
    print("  that contains the rogue bundle. This is not a bug, it is")
    print("  the whole point of the trusted directory. The directory")
    print("  is the trust boundary, not the signature on its own.")
    rogue_only = PublicKeyDirectory.in_memory([rogue_bundle])
    rogue_verifier = DirectoryTokenVerifier(rogue_only, hybrid=False)
    rogue_self_verify_ok = False
    try:
        rogue_verifier.verify(forged_token, forged_token.signature)
        rogue_self_verify_ok = True
    except Exception as e:
        print(f"  unexpected: rogue-only directory refused the forgery: {e}")
    print(f"  forgery verifies against a rogue-only directory: {rogue_self_verify_ok}")
    print()

    results.append((
        "Case 4: rogue forgery verifies against a rogue only directory",
        rogue_self_verify_ok,
    ))

    # -----------------------------------------------------------------
    # Case 5: empty directory refuses even the real permit.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case 5: swap to an empty directory and reverify the real permit.")
    print("-" * 70)
    print("This proves the directory is the load bearing part. If the")
    print("directory is empty, the real permit has no trusted bundle to")
    print("verify against, and the lookup fails with 'public key not")
    print("found'. The permit itself is fine; what is missing is the")
    print("trust binding.")
    print()

    empty_directory = PublicKeyDirectory.in_memory([])
    empty_verifier = DirectoryTokenVerifier(empty_directory, hybrid=False)
    print(f"  empty_directory.length:   {empty_directory.length}")
    print(f"  empty_directory.is_empty: {empty_directory.is_empty}")
    print()
    try:
        empty_verifier.verify(real_token, real_token.signature)
        print("  directory.verify() accepted the permit when it should have refused.")
        results.append(("Case 5: real permit is refused against an empty directory", False))
    except ValueError as e:
        msg = str(e)
        ok = "public key not found" in msg
        print("  directory.verify() raised ValueError as expected.")
        print(f"  message (first 180 chars): {msg[:180]}")
        results.append(("Case 5: real permit is refused against an empty directory", ok))
    print()

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
