"""
Scenario 09: API key rotation with the two person rule.

The story
---------
A fintech's internal platform holds the master API keys for every
third party payment rail, exchange, and KYC vendor it integrates
with. Rotating one of those keys is a high blast radius operation:
rotate the wrong one and a production revenue line stops moving
money until the next deploy. Rotate it with a bad value and you
just leaked a key into the logs.

The platform team wants three rules on every rotation:

    1. Two person rule. The caller must be 'security_admin', and
       they must present a recorded second approval from another
       'security_admin' (never from themselves). The approval id
       is a param the caller fills in from the approval service's
       database.

    2. The vendor the key belongs to must be in the currently
       tracked set. Rotating a key for a vendor that isn't even
       onboarded yet is almost always a mistake.

    3. A rate cap of 10 rotations per day per admin. Anything over
       that is either an automation in a loop or an attacker who
       got a session token and is trying to churn keys across many
       vendors at once.

Then two things on top of the gate:

    4. Every rotation that permits gets a signed permit issued by
       the Platform Auth service. The downstream Vault worker takes
       the permit, verifies the ML-DSA-65 signature against the root
       signed directory, and only then updates the secret in the
       secrets store.

    5. Every attempt (permit or refuse) is appended to a signed
       audit chain for the security team's weekly review.

Six cases:

    A. Legitimate rotation. security_admin Priya, fresh gate,
       vendor "stripe", approval id carries Rahul's signature.
       Expect PERMIT, permit is signed, Vault verifies, session opens.
    B. Self approval. Same admin fills in her own id as the
       approval_admin. The param_min rule on distinct_approvers
       fails and the rotation refuses.
    C. Unknown vendor. "acme-cash-v0" is not in the tracked set,
       param_in refuses.
    D. Non admin tries. Engineer Aarav has 'platform_engineer', not
       'security_admin', default deny.
    E. Eleven rotations in a day by a fresh admin. Ten permit, the
       eleventh refuses on the rate condition.
    F. An attacker relabels a permit from vendor 'stripe' to vendor
       'internal-wallet' on the wire. The Vault worker's verifier
       catches the signature mismatch and refuses.

Run this file directly:

    python tier2/09_api_key_rotation.py
"""

import json
import tempfile
from pathlib import Path

from kavach import (
    ActionContext,
    AuditEntry,
    DirectoryTokenVerifier,
    Gate,
    KavachKeyPair,
    PermitToken,
    PqTokenSigner,
    PublicKeyDirectory,
    SignedAuditChain,
)


# ---------------------------------------------------------------------
# Step 1. The policy.
#
# We encode the "two person rule" as a param_min on distinct_approvers.
# The caller sends:
#     requesting_admin_id     : string (who is clicking rotate)
#     approval_admin_id       : string (who signed off in the approval
#                                        tool)
#     distinct_approvers      : 1.0 if the two ids differ, 0.0 if they
#                                are the same person
#
# A real production gate would infer distinct_approvers server side
# from the approval record. Passing it as a param here keeps the
# scenario self contained. The invariant and the param_in do the rest.
# ---------------------------------------------------------------------

TRACKED_VENDORS = ["stripe", "adyen", "plaid", "onfido", "internal-wallet"]


POLICIES = {
    "policies": [
        {
            "name": "dual_control_key_rotation",
            "description": "Security admins rotate API keys with a second admin approval",
            "effect": "permit",
            "priority": 10,
            "conditions": [
                {"identity_role": "security_admin"},
                {"action": "platform.rotate_api_key"},
                {"param_in": {"field": "vendor", "values": TRACKED_VENDORS}},
                {"param_min": {"field": "distinct_approvers", "min": 1.0}},
                {"rate_limit": {"max": 10, "window": "1d"}},
            ],
        },
    ],
}


def rotate_ctx(requester_id, roles, vendor, approver_id):
    ctx = ActionContext(
        principal_id=requester_id,
        principal_kind="user",
        action_name="platform.rotate_api_key",
        roles=roles,
        resource=f"secrets/vendor/{vendor}/api_key",
        params={
            "distinct_approvers": 1.0 if approver_id != requester_id else 0.0,
        },
    )
    # vendor is a string, approver id is a string. Strings go through
    # with_param (the constructor's params dict only takes floats).
    ctx.with_param("vendor", vendor)
    ctx.with_param("approval_admin_id", approver_id)
    return ctx


def audit_from_verdict(chain, requester_id, vendor, approver_id, verdict):
    detail = {
        "vendor": vendor,
        "approver": approver_id,
        "evaluator": verdict.evaluator,
        "code": verdict.code,
        "reason": verdict.reason,
    }
    chain.append(AuditEntry(
        principal_id=requester_id,
        action_name="platform.rotate_api_key",
        verdict=verdict.kind,
        verdict_detail=json.dumps(detail, separators=(",", ":")),
    ))


def main():
    print("=" * 70)
    print("Scenario 09: API key rotation with the two person rule")
    print("=" * 70)
    print()
    print("We are going to set up Platform Auth (signs rotation permits)")
    print("and a Vault worker (verifies permits against a root signed")
    print("directory, then updates the secret). Every attempt is also")
    print("appended to a signed audit chain. Then we run six cases,")
    print("including one wire tampering attempt.")
    print()

    results = []

    # -----------------------------------------------------------------
    # Keypairs.
    # -----------------------------------------------------------------
    print("Generating three keypairs.")
    auth_kp = KavachKeyPair.generate()
    root_kp = KavachKeyPair.generate()
    audit_kp = KavachKeyPair.generate()
    auth_bundle = auth_kp.public_keys()
    root_bundle = root_kp.public_keys()
    print(f"  auth.key_id:  {auth_kp.id}")
    print(f"  root.key_id:  {root_kp.id}")
    print(f"  audit.key_id: {audit_kp.id}")
    print()

    # -----------------------------------------------------------------
    # Trusted directory, loaded into the Vault worker.
    # -----------------------------------------------------------------
    print("Building the root signed directory that Vault trusts.")
    manifest_bytes = bytes(root_kp.build_signed_manifest([auth_bundle]))
    tmpdir = Path(tempfile.mkdtemp(prefix="kavach-18-"))
    manifest_path = tmpdir / "trusted_signers.json"
    manifest_path.write_bytes(manifest_bytes)
    directory = PublicKeyDirectory.from_signed_file(
        str(manifest_path),
        root_bundle.ml_dsa_verifying_key,
    )
    verifier = DirectoryTokenVerifier(directory, hybrid=False)
    print(f"  manifest path:    {manifest_path}")
    print(f"  directory.length: {directory.length}")
    print()

    # -----------------------------------------------------------------
    # Audit chain.
    # -----------------------------------------------------------------
    print("Opening the audit chain.")
    chain = SignedAuditChain(audit_kp, hybrid=False)
    print(f"  chain.is_hybrid: {chain.is_hybrid}")
    print(f"  chain.length:    {chain.length}")
    print()

    # -----------------------------------------------------------------
    # Auth gate.
    # -----------------------------------------------------------------
    print("Building Platform Auth's gate with its signer attached.")
    signer = PqTokenSigner.from_keypair_pq_only(auth_kp)
    gate = Gate.from_dict(POLICIES, token_signer=signer)
    print(f"  gate.evaluator_count: {gate.evaluator_count}")
    print(f"  signer.key_id:        {signer.key_id}")
    print()

    # -----------------------------------------------------------------
    # Case A: legitimate rotation.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case A: admin-priya rotates stripe's API key, approval from admin-rahul.")
    print("-" * 70)
    print("Role is 'security_admin'. Vendor is in the tracked set. The")
    print("approver id (rahul) differs from the requester id (priya), so")
    print("distinct_approvers is 1.0, which clears the param_min on it.")
    print("Rate is fresh. We expect: PERMIT, with a signed permit that")
    print("the Vault worker verifies and accepts.")
    print()

    ctx = rotate_ctx("admin-priya", ["security_admin"], "stripe", "admin-rahul")
    v = gate.evaluate(ctx)
    audit_from_verdict(chain, "admin-priya", "stripe", "admin-rahul", v)

    print(f"Auth verdict:      {v.kind}")
    print(f"Is permit:         {v.is_permit}")
    print(f"Permit token id:   {v.token_id}")
    permit = v.permit_token
    vault_ok = False
    if permit is not None:
        try:
            verifier.verify(permit, permit.signature)
            vault_ok = True
            print("Vault.verify(): accepted.")
        except Exception as e:
            print(f"Vault.verify() raised unexpectedly: {type(e).__name__}: {e}")
    print(f"Chain length: {chain.length}")
    print()

    results.append(("Case A: dual control rotation permits", v.is_permit))
    results.append(("Case A: Vault verifies the signature", vault_ok))

    # -----------------------------------------------------------------
    # Case B: self approval.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case B: admin-priya lists herself as her own approver.")
    print("-" * 70)
    print("The param_min rule on distinct_approvers requires the field")
    print("to be at least 1.0. When the requester and the approver are")
    print("the same person, the wrapper sets the field to 0.0, which")
    print("fails the min check. The rule does not match, default deny")
    print("refuses. The audit chain still records the attempt, because")
    print("this is a red flag you want a human to see.")
    print()

    ctx = rotate_ctx("admin-priya", ["security_admin"], "stripe", "admin-priya")
    v = gate.evaluate(ctx)
    audit_from_verdict(chain, "admin-priya", "stripe", "admin-priya", v)

    print(f"Auth verdict: {v.kind}")
    print(f"Is refuse:    {v.is_refuse}")
    print(f"Evaluator:    {v.evaluator}")
    print(f"Code:         {v.code}")
    print(f"Chain length: {chain.length}")
    print()

    ok = v.is_refuse and v.evaluator == "policy" and v.code == "NO_POLICY_MATCH"
    results.append(("Case B: self approval refused", ok))

    # -----------------------------------------------------------------
    # Case C: unknown vendor.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case C: admin-priya tries to rotate a key for 'acme-cash-v0'.")
    print("-" * 70)
    print("'acme-cash-v0' is not in the tracked vendor list. param_in")
    print("fails and the rule does not match. Default deny refuses.")
    print("This protects against a developer fat-finger like")
    print("'stripeprod' when they meant 'stripe'.")
    print()

    ctx = rotate_ctx("admin-priya", ["security_admin"], "acme-cash-v0", "admin-rahul")
    v = gate.evaluate(ctx)
    audit_from_verdict(chain, "admin-priya", "acme-cash-v0", "admin-rahul", v)

    print(f"Auth verdict: {v.kind}")
    print(f"Is refuse:    {v.is_refuse}")
    print(f"Evaluator:    {v.evaluator}")
    print(f"Code:         {v.code}")
    print()

    ok = v.is_refuse and v.evaluator == "policy" and v.code == "NO_POLICY_MATCH"
    results.append(("Case C: unknown vendor refused", ok))

    # -----------------------------------------------------------------
    # Case D: non admin tries.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case D: engineer Aarav (platform_engineer) tries to rotate.")
    print("-" * 70)
    print("The identity_role condition requires 'security_admin'. Aarav")
    print("has 'platform_engineer' only. The rule does not match. Refuse.")
    print()

    ctx = rotate_ctx("eng-aarav", ["platform_engineer"], "stripe", "admin-rahul")
    v = gate.evaluate(ctx)
    audit_from_verdict(chain, "eng-aarav", "stripe", "admin-rahul", v)

    print(f"Auth verdict: {v.kind}")
    print(f"Is refuse:    {v.is_refuse}")
    print(f"Evaluator:    {v.evaluator}")
    print(f"Code:         {v.code}")
    print()

    ok = v.is_refuse and v.evaluator == "policy" and v.code == "NO_POLICY_MATCH"
    results.append(("Case D: non admin refused", ok))

    # -----------------------------------------------------------------
    # Case E: rate burst on a fresh gate.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case E: fresh gate, admin-zara fires 11 rotations back to back.")
    print("-" * 70)
    print("The daily cap is 10 per admin. We build a fresh gate so the")
    print("rate bucket is isolated. Expect 10 permits and 1 refuse.")
    print("Each attempt is audited.")
    print()

    burst_gate = Gate.from_dict(POLICIES, token_signer=signer)
    permit_count = 0
    refuse_count = 0
    for i in range(11):
        vendor = TRACKED_VENDORS[i % len(TRACKED_VENDORS)]
        ctx = rotate_ctx("admin-zara", ["security_admin"], vendor, "admin-rahul")
        v = burst_gate.evaluate(ctx)
        audit_from_verdict(chain, "admin-zara", vendor, "admin-rahul", v)
        if v.is_permit:
            permit_count += 1
        else:
            refuse_count += 1

    print(f"Permits: {permit_count}")
    print(f"Refuses: {refuse_count}")
    print(f"Chain length: {chain.length}")
    print()

    results.append(("Case E: 10 permit, 11th refuses on rate",
                    permit_count == 10 and refuse_count == 1))

    # -----------------------------------------------------------------
    # Case F: wire tampering, vendor relabel.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case F: attacker relabels the permit's action on the wire.")
    print("-" * 70)
    print("admin-priya's legitimate permit from Case A was for rotating")
    print("stripe's key. An attacker in the middle copies the permit,")
    print("keeps every field identical except for action_name, which")
    print("they flip from 'platform.rotate_api_key' to something more")
    print("interesting ('platform.disable_vendor'). The signature covers")
    print("the action name, so the Vault worker's verifier recomputes")
    print("the canonical bytes, finds the mismatch, and raises.")
    print()

    real_permit = permit
    tampered = PermitToken(
        token_id=real_permit.token_id,
        evaluation_id=real_permit.evaluation_id,
        issued_at=real_permit.issued_at,
        expires_at=real_permit.expires_at,
        action_name="platform.disable_vendor",
        signature=real_permit.signature,
    )
    print(f"  original action_name: {real_permit.action_name}")
    print(f"  tampered action_name: {tampered.action_name}")

    tamper_refused = False
    tamper_msg = ""
    try:
        verifier.verify(tampered, tampered.signature)
    except ValueError as e:
        tamper_refused = True
        tamper_msg = str(e)
    print(f"  Vault.verify() raised: {tamper_refused}")
    print(f"  message (first 180 chars): {tamper_msg[:180]}")
    print()

    results.append(("Case F: wire tamper is refused", tamper_refused))

    # -----------------------------------------------------------------
    # Close out: reverify the full chain.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Close out: export the audit chain and reverify.")
    print("-" * 70)
    print("The security team exports the full JSONL blob to archive it.")
    print("Reverify against the audit bundle returns a count equal to")
    print("chain.length on an untouched chain.")
    print()

    jsonl = bytes(chain.export_jsonl())
    audit_bundle = audit_kp.public_keys()
    clean_count = -1
    try:
        clean_count = SignedAuditChain.verify_jsonl(jsonl, audit_bundle)
        print(f"Clean reverify: passed ({clean_count} entries verified).")
    except Exception as e:
        print(f"Clean reverify raised unexpectedly: {type(e).__name__}: {e}")
    print(f"JSONL bytes length: {len(jsonl)}")
    print(f"Chain length:       {chain.length}")
    print()

    results.append(("Close out: chain reverifies cleanly",
                    clean_count == chain.length))

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
