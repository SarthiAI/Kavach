"""
Scenario 08: tiered loan approval with a signed disbursement permit.

The story
---------
A digital lender splits "underwriting decision" from "moving money
to the borrower" across two services:

    Underwriting service
        Holds the risk policy. Every loan approval runs through a
        Kavach gate with three tiers of permission, each with its
        own ceiling. When the gate permits, Underwriting signs a
        permit token with its ML-DSA-65 key.

    Disbursement service
        Does not hold any risk rules. It reads the signed permit
        off the wire, looks the signer up in a root signed
        directory, and verifies the permit. If the verify passes,
        it moves funds; if not, it refuses before the ACH rail is
        even contacted.

The three risk tiers inside Underwriting are:

    1. loan_officer: may approve loans up to $50,000.
    2. senior_officer: may approve loans up to $250,000.
    3. committee_chair: may approve loans up to $1,000,000.

On top of that, a regulator style invariant caps any single
disbursement at $1,500,000. No single person can approve a loan
bigger than that, no matter what role they hold. The chain also
rate limits each officer to 20 approvals per hour, which is an
abuse ceiling (real throughput is nowhere near that).

Seven cases:

    A. loan_officer approves a $40,000 consumer loan. Underwriting
       permits and signs. Disbursement verifies and pays.
    B. loan_officer tries $60,000. Over their tier's cap. Policy
       refuses. No signature was even generated.
    C. senior_officer takes the same $60,000. Their cap is $250k.
       Permits and signs. Disbursement verifies.
    D. senior_officer tries $400,000. Over their cap, under the
       committee cap, policy refuses.
    E. committee_chair approves a $900,000 SMB loan. Permits,
       signs, Disbursement verifies.
    F. committee_chair tries a $1,600,000 loan. Policy permits on
       its own (under the $1M committee cap... wait, it is over,
       so actually policy refuses first). We instead build a
       "loose" rule that would permit up to $2M, show the permit,
       and then watch the invariant refuse above $1.5M. This
       pins the property that the invariant is the final line.
    G. Attacker flips the amount on a legitimate $40k permit to
       $400k on the wire. The Disbursement service recomputes the
       canonical bytes, finds the mismatch, refuses.

Run this file directly:

    python tier2/08_loan_approval.py
"""

import tempfile
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
# Step 1. Policy. Three permit rules, one invariant.
# ---------------------------------------------------------------------

POLICIES = {
    "policies": [
        {
            "name": "loan_officer_small",
            "description": "Loan officers may approve loans up to $50,000",
            "effect": "permit",
            "priority": 10,
            "conditions": [
                {"identity_role": "loan_officer"},
                {"action": "loan.approve"},
                {"param_max": {"field": "amount_usd", "max": 50000.0}},
                {"rate_limit": {"max": 20, "window": "1h"}},
            ],
        },
        {
            "name": "senior_officer_medium",
            "description": "Senior officers may approve loans up to $250,000",
            "effect": "permit",
            "priority": 10,
            "conditions": [
                {"identity_role": "senior_officer"},
                {"action": "loan.approve"},
                {"param_max": {"field": "amount_usd", "max": 250000.0}},
                {"rate_limit": {"max": 20, "window": "1h"}},
            ],
        },
        {
            "name": "committee_chair_large",
            "description": "Committee chairs may approve loans up to $1,000,000",
            "effect": "permit",
            "priority": 10,
            "conditions": [
                {"identity_role": "committee_chair"},
                {"action": "loan.approve"},
                {"param_max": {"field": "amount_usd", "max": 1000000.0}},
                {"rate_limit": {"max": 20, "window": "1h"}},
            ],
        },
    ],
}

# The regulator line. No single disbursement above $1,500,000, no
# matter who signed it off. Also a field a human scan can verify
# quickly: "is this amount over the hard cap? then refuse regardless".
INVARIANTS = [("regulator_single_loan_cap", "amount_usd", 1500000.0)]


def loan_ctx(principal_id, roles, amount_usd):
    return ActionContext(
        principal_id=principal_id,
        principal_kind="user",
        action_name="loan.approve",
        roles=roles,
        resource="applications/2026-04-21-00347",
        params={"amount_usd": float(amount_usd)},
    )


def main():
    print("=" * 70)
    print("Scenario 08: tiered loan approval with a signed disbursement permit")
    print("=" * 70)
    print()
    print("We are going to set up Underwriting (signs permits, runs the")
    print("risk policy) and Disbursement (verifies the permit, moves")
    print("money). Then seven cases including a tier violation, an")
    print("invariant breach, and a wire tamper.")
    print()

    results = []

    # -----------------------------------------------------------------
    # Keypairs.
    # -----------------------------------------------------------------
    print("Generating two keypairs.")
    underwriting_kp = KavachKeyPair.generate()
    root_kp = KavachKeyPair.generate()
    underwriting_bundle = underwriting_kp.public_keys()
    root_bundle = root_kp.public_keys()
    print(f"  underwriting.key_id: {underwriting_kp.id}")
    print(f"  root.key_id:         {root_kp.id}")
    print()

    # -----------------------------------------------------------------
    # Root signed directory loaded into Disbursement.
    # -----------------------------------------------------------------
    print("Building the root signed directory.")
    manifest_bytes = bytes(root_kp.build_signed_manifest([underwriting_bundle]))
    tmpdir = Path(tempfile.mkdtemp(prefix="kavach-19-"))
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
    # Underwriting's gate.
    # -----------------------------------------------------------------
    print("Building Underwriting's gate with its signer attached.")
    signer = PqTokenSigner.from_keypair_pq_only(underwriting_kp)
    gate = Gate.from_dict(POLICIES, invariants=INVARIANTS, token_signer=signer)
    print(f"  gate.evaluator_count: {gate.evaluator_count}")
    print(f"  signer.key_id:        {signer.key_id}")
    print()

    # -----------------------------------------------------------------
    # Case A: small consumer loan, loan officer.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case A: loan officer Meera approves a $40,000 consumer loan.")
    print("-" * 70)
    print("Role is 'loan_officer', amount is under $50k. The first")
    print("rule matches, Underwriting permits and signs. Disbursement")
    print("verifies against the directory and accepts. This is the")
    print("happy path for everyday retail lending.")
    print()

    ctx = loan_ctx("officer-meera", ["loan_officer"], 40000.0)
    v = gate.evaluate(ctx)
    print(f"Underwriting verdict: {v.kind}")
    print(f"Is permit:            {v.is_permit}")
    permit = v.permit_token
    verify_ok = False
    if permit is not None:
        try:
            verifier.verify(permit, permit.signature)
            verify_ok = True
            print("Disbursement.verify(): accepted.")
        except Exception as e:
            print(f"Disbursement.verify() raised unexpectedly: {type(e).__name__}: {e}")
    print()

    results.append(("Case A: loan officer $40k permits", v.is_permit))
    results.append(("Case A: Disbursement verifies", verify_ok))
    case_a_permit = permit

    # -----------------------------------------------------------------
    # Case B: loan officer, over their tier.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case B: loan officer Meera tries $60,000.")
    print("-" * 70)
    print("Her tier caps at $50k. The loan_officer_small rule does not")
    print("match because of the param_max. The other two rules require")
    print("roles she does not have. No rule matches, default deny. No")
    print("signature is ever produced, so no permit leaks to")
    print("Disbursement.")
    print()

    ctx = loan_ctx("officer-meera", ["loan_officer"], 60000.0)
    v = gate.evaluate(ctx)
    print(f"Underwriting verdict: {v.kind}")
    print(f"Is refuse:            {v.is_refuse}")
    print(f"Evaluator:            {v.evaluator}")
    print(f"Code:                 {v.code}")
    print(f"Permit token present: {v.permit_token is not None}")
    print()

    ok = (
        v.is_refuse
        and v.evaluator == "policy"
        and v.code == "NO_POLICY_MATCH"
        and v.permit_token is None
    )
    results.append(("Case B: loan officer $60k refused on tier", ok))

    # -----------------------------------------------------------------
    # Case C: senior officer, $60k.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case C: senior officer Vikram approves the same $60,000 loan.")
    print("-" * 70)
    print("The senior_officer_medium rule caps at $250k. $60k is well")
    print("under. Permits and signs.")
    print()

    ctx = loan_ctx("officer-vikram", ["senior_officer"], 60000.0)
    v = gate.evaluate(ctx)
    print(f"Underwriting verdict: {v.kind}")
    print(f"Is permit:            {v.is_permit}")
    permit_c = v.permit_token
    verify_ok_c = False
    if permit_c is not None:
        try:
            verifier.verify(permit_c, permit_c.signature)
            verify_ok_c = True
            print("Disbursement.verify(): accepted.")
        except Exception as e:
            print(f"Disbursement.verify() raised unexpectedly: {type(e).__name__}: {e}")
    print()

    results.append(("Case C: senior officer $60k permits", v.is_permit))
    results.append(("Case C: Disbursement verifies", verify_ok_c))

    # -----------------------------------------------------------------
    # Case D: senior officer over their tier.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case D: senior officer Vikram tries $400,000.")
    print("-" * 70)
    print("$400k is over the senior tier's $250k cap. The committee")
    print("rule would accept it ($1M cap) but Vikram doesn't carry")
    print("that role. No rule matches, default deny.")
    print()

    ctx = loan_ctx("officer-vikram", ["senior_officer"], 400000.0)
    v = gate.evaluate(ctx)
    print(f"Underwriting verdict: {v.kind}")
    print(f"Is refuse:            {v.is_refuse}")
    print(f"Evaluator:            {v.evaluator}")
    print(f"Code:                 {v.code}")
    print()

    ok = v.is_refuse and v.evaluator == "policy"
    results.append(("Case D: senior officer $400k refused on tier", ok))

    # -----------------------------------------------------------------
    # Case E: committee chair, $900k.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case E: committee chair Amara approves a $900,000 SMB loan.")
    print("-" * 70)
    print("Committee chair caps at $1,000,000. $900k is under. Invariant")
    print("is $1.5M, also fine. Permits and signs. Disbursement verifies.")
    print()

    ctx = loan_ctx("chair-amara", ["committee_chair"], 900000.0)
    v = gate.evaluate(ctx)
    print(f"Underwriting verdict: {v.kind}")
    print(f"Is permit:            {v.is_permit}")
    permit_e = v.permit_token
    verify_ok_e = False
    if permit_e is not None:
        try:
            verifier.verify(permit_e, permit_e.signature)
            verify_ok_e = True
            print("Disbursement.verify(): accepted.")
        except Exception as e:
            print(f"Disbursement.verify() raised unexpectedly: {type(e).__name__}: {e}")
    print()

    results.append(("Case E: committee chair $900k permits", v.is_permit))
    results.append(("Case E: Disbursement verifies", verify_ok_e))

    # -----------------------------------------------------------------
    # Case F: policy permits, invariant refuses.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case F: loose rule permits $1.6M, but the invariant refuses.")
    print("-" * 70)
    print("We build a separate gate whose committee rule caps at $2,000,000")
    print("(a config mistake that somehow made it past review). The same")
    print("regulator invariant of $1.5M is wired in. A $1,600,000 loan")
    print("would permit at the policy stage but must refuse at the")
    print("invariant. This is the safety net property: a too-permissive")
    print("policy cannot override a regulator invariant.")
    print()

    LOOSE_POLICIES = {
        "policies": [
            {
                "name": "loose_committee_rule",
                "description": "Misconfigured rule (demo only): chairs up to $2M",
                "effect": "permit",
                "priority": 10,
                "conditions": [
                    {"identity_role": "committee_chair"},
                    {"action": "loan.approve"},
                    {"param_max": {"field": "amount_usd", "max": 2000000.0}},
                ],
            },
        ],
    }
    loose_gate = Gate.from_dict(
        LOOSE_POLICIES,
        invariants=INVARIANTS,
        token_signer=signer,
    )
    ctx = loan_ctx("chair-amara", ["committee_chair"], 1600000.0)
    v = loose_gate.evaluate(ctx)
    print(f"Verdict kind: {v.kind}")
    print(f"Is refuse:    {v.is_refuse}")
    print(f"Evaluator:    {v.evaluator}")
    print(f"Reason:       {v.reason}")
    print()

    ok = (
        v.is_refuse
        and v.evaluator == "invariants"
        and "regulator_single_loan_cap" in (v.reason or "")
    )
    results.append(("Case F: loose policy permits, invariant refuses", ok))

    # -----------------------------------------------------------------
    # Case G: wire tamper, flip the amount on a real permit.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case G: attacker tampers Case A's permit on the wire.")
    print("-" * 70)
    print("The attacker captures the real $40,000 permit issued to")
    print("officer Meera, keeps the signature bytes and every field")
    print("other than action_name intact, then relabels the permit")
    print("from 'loan.approve' to 'loan.approve_mega' (a made up")
    print("privilege). Disbursement recomputes the canonical bytes,")
    print("finds that the signature does not cover them, and refuses.")
    print("This is what stops an attacker from forwarding a real small")
    print("permit as authorisation for a larger or differently named")
    print("action.")
    print()

    tampered = PermitToken(
        token_id=case_a_permit.token_id,
        evaluation_id=case_a_permit.evaluation_id,
        issued_at=case_a_permit.issued_at,
        expires_at=case_a_permit.expires_at,
        action_name="loan.approve_mega",
        signature=case_a_permit.signature,
    )
    print(f"  original action_name: {case_a_permit.action_name}")
    print(f"  tampered action_name: {tampered.action_name}")
    tamper_refused = False
    tamper_msg = ""
    try:
        verifier.verify(tampered, tampered.signature)
    except ValueError as e:
        tamper_refused = True
        tamper_msg = str(e)
    print(f"  Disbursement.verify() raised: {tamper_refused}")
    print(f"  message (first 180 chars): {tamper_msg[:180]}")
    print()

    results.append(("Case G: wire tamper refused", tamper_refused))

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
