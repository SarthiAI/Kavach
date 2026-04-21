"""
Scenario 10: break glass emergency prod console access.

The story
---------
A SaaS company locks down production almost all the time. The only
way an on call SRE can pop a shell on a prod database host is through
a break glass flow. The business wants three things from that flow:

    1. Only a currently on call SRE can even attempt it. People not
       on rotation get refused immediately, no matter how senior.

    2. Every attempt is pinned to a live incident ticket. The caller
       has to pass the incident id as a param, and the ticket id has
       to sit inside the company's active incident window. This
       prevents "I'll just claim there was an incident last Tuesday"
       after the fact.

    3. A hard rate limit of 3 attempts per hour per SRE, because
       real break glass is rare. More than three in an hour almost
       always means an automation gone wrong or someone poking at
       the gate.

And two things from the pipeline around it:

    4. Every granted permit is signed by the Auth service using an
       ML-DSA-65 keypair. Infrastructure receives the permit, looks
       up the Auth bundle in a root signed directory, verifies the
       signature, and only then opens the session. This keeps prod
       console access to "only things Auth permitted in the last
       few seconds", no shared secrets on disk.

    5. Every attempt, permitted or refused, is appended to a signed
       audit chain so the security team can replay the week during
       post incident review. The chain is hash linked, so tamper in
       the middle is detected by the verifier and points at the
       exact entry that was touched.

Five cases:

    A. On call SRE, valid open incident, first attempt. PERMIT, the
       permit is signed, Infrastructure verifies, session opens.
    B. Senior engineer NOT on call tries. REFUSE on identity role.
    C. On call SRE with a fabricated incident id (not in the active
       set). REFUSE on identity. Policy rule does not match because
       the param_in on incident_id fails.
    D. Fourth attempt in the same hour. REFUSE on rate.
    E. After the dust settles, export the audit chain to JSONL,
       reverify it, and then tamper one byte inside entry 2 to show
       the verifier names the exact broken entry.

Run this file directly:

    python tier2/10_break_glass.py
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
    PqTokenSigner,
    PublicKeyDirectory,
    SignedAuditChain,
)


# ---------------------------------------------------------------------
# Step 1. Policy. One permit rule, four conditions.
# ---------------------------------------------------------------------
# identity_role = sre_on_call. Carried as a runtime role by an
# identity provider that knows who is actually paging at this minute.
#
# action = infra.break_glass_session.
#
# param_in on incident_id restricts accepted ids to the currently
# open incident set. A fabricated id or an id for an already closed
# incident fails this check and the rule does not match.
#
# rate_limit = 3 per hour. Break glass is not something anyone runs
# at volume; 3 is plenty of headroom for real incidents.
# ---------------------------------------------------------------------

OPEN_INCIDENTS = ["INC-2026-0418-payments", "INC-2026-0418-auth"]


POLICIES = {
    "policies": [
        {
            "name": "sre_break_glass",
            "description": "On call SRE may open a break glass session against a live incident",
            "effect": "permit",
            "priority": 10,
            "conditions": [
                {"identity_role": "sre_on_call"},
                {"action": "infra.break_glass_session"},
                {"param_in": {"field": "incident_id", "values": OPEN_INCIDENTS}},
                {"rate_limit": {"max": 3, "window": "1h"}},
            ],
        },
    ],
}


def break_glass_ctx(principal_id, roles, incident_id):
    ctx = ActionContext(
        principal_id=principal_id,
        principal_kind="user",
        action_name="infra.break_glass_session",
        roles=roles,
        resource="prod/region-use1/db-primary",
    )
    # incident_id is a string, so it goes through with_param. The
    # constructor's params dict only accepts numeric values.
    ctx.with_param("incident_id", incident_id)
    return ctx


def audit_from_verdict(chain, principal_id, incident_id, verdict):
    detail = {
        "incident_id": incident_id,
        "evaluator": verdict.evaluator,
        "code": verdict.code,
        "reason": verdict.reason,
    }
    chain.append(AuditEntry(
        principal_id=principal_id,
        action_name="infra.break_glass_session",
        verdict=verdict.kind,
        verdict_detail=json.dumps(detail, separators=(",", ":")),
    ))


def mutate_line(jsonl: bytes, idx: int, mutator) -> bytes:
    # Load, mutate, and re-serialise a single JSONL line so we can
    # build a deliberately broken blob for the tamper test.
    lines = jsonl.splitlines()
    obj = json.loads(lines[idx].decode("utf-8"))
    mutator(obj)
    lines[idx] = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return b"\n".join(lines) + (b"\n" if jsonl.endswith(b"\n") else b"")


def main():
    print("=" * 70)
    print("Scenario 10: break glass emergency prod console access")
    print("=" * 70)
    print()
    print("We are going to set up an Auth service that signs break glass")
    print("permits, an Infrastructure service that verifies them against")
    print("a root signed directory, and a signed audit chain that records")
    print("every attempt. Then we walk five real cases through it.")
    print()

    results = []

    # -----------------------------------------------------------------
    # Keypairs: one for Auth (signs permits), one for the directory
    # root (signs the list of trusted Auth bundles), and one for the
    # audit chain.
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
    # Directory: the root signs a manifest that says "Auth's bundle is
    # trusted". Infrastructure pins the root verifying key, loads the
    # manifest, and now trusts Auth's bundle.
    # -----------------------------------------------------------------
    print("Building a root signed directory and loading it into Infrastructure.")
    manifest_bytes = bytes(root_kp.build_signed_manifest([auth_bundle]))
    tmpdir = Path(tempfile.mkdtemp(prefix="kavach-17-"))
    manifest_path = tmpdir / "trusted_signers.json"
    manifest_path.write_bytes(manifest_bytes)
    directory = PublicKeyDirectory.from_signed_file(
        str(manifest_path),
        root_bundle.ml_dsa_verifying_key,
    )
    verifier = DirectoryTokenVerifier(directory, hybrid=False)
    print(f"  manifest path:      {manifest_path}")
    print(f"  directory.length:   {directory.length}")
    print(f"  directory.is_empty: {directory.is_empty}")
    print()

    # -----------------------------------------------------------------
    # Audit chain.
    # -----------------------------------------------------------------
    print("Opening the audit chain (PQ only signing).")
    chain = SignedAuditChain(audit_kp, hybrid=False)
    print(f"  chain.is_hybrid: {chain.is_hybrid}")
    print(f"  chain.length:    {chain.length}")
    print(f"  chain.head_hash: {chain.head_hash}")
    print()

    # -----------------------------------------------------------------
    # Auth gate.
    # -----------------------------------------------------------------
    print("Building Auth's gate with its token signer attached.")
    signer = PqTokenSigner.from_keypair_pq_only(auth_kp)
    gate = Gate.from_dict(POLICIES, token_signer=signer)
    print(f"  gate.evaluator_count: {gate.evaluator_count}")
    print(f"  signer.key_id:        {signer.key_id}")
    print()

    # -----------------------------------------------------------------
    # Case A: on call SRE, valid incident, first attempt.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case A: on call SRE Maya opens a shell for INC-2026-0418-payments.")
    print("-" * 70)
    print("Role is 'sre_on_call'. Incident id is in the active set. The")
    print("rate bucket is fresh. Auth permits and signs the permit.")
    print("Infrastructure calls verifier.verify(permit, permit.signature)")
    print("and accepts. The audit chain records the permit.")
    print()

    ctx = break_glass_ctx("sre-maya", ["sre_on_call"], "INC-2026-0418-payments")
    v = gate.evaluate(ctx)
    audit_from_verdict(chain, "sre-maya", "INC-2026-0418-payments", v)

    print(f"Auth verdict:      {v.kind}")
    print(f"Is permit:         {v.is_permit}")
    print(f"Permit token id:   {v.token_id}")
    token = v.permit_token

    signature_ok = False
    if token is not None:
        try:
            verifier.verify(token, token.signature)
            signature_ok = True
            print("Infrastructure.verify(): accepted.")
        except Exception as e:
            print(f"Infrastructure.verify() raised unexpectedly: {type(e).__name__}: {e}")
    print(f"Chain length:      {chain.length}")
    print()

    results.append(("Case A: on call SRE gets a permit", v.is_permit))
    results.append(("Case A: Infrastructure verifies the signature", signature_ok))

    # -----------------------------------------------------------------
    # Case B: not on call, refuse.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case B: senior engineer Dev-Ravi tries break glass. Not on call.")
    print("-" * 70)
    print("Ravi's identity provider carries the role 'senior_engineer',")
    print("not 'sre_on_call'. The rule does not match, default deny")
    print("refuses. No permit is issued. The audit chain still records")
    print("the attempt so the post incident review shows who tried what.")
    print()

    ctx = break_glass_ctx("dev-ravi", ["senior_engineer"], "INC-2026-0418-payments")
    v = gate.evaluate(ctx)
    audit_from_verdict(chain, "dev-ravi", "INC-2026-0418-payments", v)

    print(f"Auth verdict: {v.kind}")
    print(f"Is refuse:    {v.is_refuse}")
    print(f"Evaluator:    {v.evaluator}")
    print(f"Code:         {v.code}")
    print(f"Chain length: {chain.length}")
    print()

    ok = v.is_refuse and v.evaluator == "policy" and v.code == "NO_POLICY_MATCH"
    results.append(("Case B: off rotation engineer refused", ok))

    # -----------------------------------------------------------------
    # Case C: on call, but the incident id is not in the active set.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case C: on call SRE, incident id 'INC-LAST-WEEK' (already closed).")
    print("-" * 70)
    print("Role is right, action is right, but param_in on incident_id")
    print("only allows the two currently open incidents. A closed id")
    print("fails the check and the rule does not match. Refuse.")
    print()

    ctx = break_glass_ctx("sre-maya", ["sre_on_call"], "INC-LAST-WEEK")
    v = gate.evaluate(ctx)
    audit_from_verdict(chain, "sre-maya", "INC-LAST-WEEK", v)

    print(f"Auth verdict: {v.kind}")
    print(f"Is refuse:    {v.is_refuse}")
    print(f"Evaluator:    {v.evaluator}")
    print(f"Code:         {v.code}")
    print(f"Chain length: {chain.length}")
    print()

    ok = v.is_refuse and v.evaluator == "policy" and v.code == "NO_POLICY_MATCH"
    results.append(("Case C: closed incident id refused", ok))

    # -----------------------------------------------------------------
    # Case D: rate limit burst on a fresh gate so the rate bucket is
    # isolated from the earlier cases. We fire four attempts in a row
    # and expect the first three to permit, the fourth to refuse.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case D: fresh gate, Rahul fires 4 break glass attempts in a row.")
    print("-" * 70)
    print("We build a fresh gate so the rate bucket is independent of")
    print("the attempts in cases A, B, and C (clean isolation). The rate")
    print("limit is 3 per hour per SRE. We expect the first three calls")
    print("to permit and the fourth to refuse on the rate condition.")
    print("Each of the four attempts still gets audited in the main chain.")
    print()

    burst_gate = Gate.from_dict(POLICIES, token_signer=signer)
    permit_count = 0
    refuse_count = 0
    last_refuse = None
    for i in range(4):
        ctx = break_glass_ctx("sre-rahul", ["sre_on_call"], "INC-2026-0418-auth")
        v = burst_gate.evaluate(ctx)
        audit_from_verdict(chain, "sre-rahul", "INC-2026-0418-auth", v)
        print(f"  attempt {i + 1}: {v.kind}")
        if v.is_permit:
            permit_count += 1
        else:
            refuse_count += 1
            last_refuse = v

    print(f"Permits: {permit_count}")
    print(f"Refuses: {refuse_count}")
    print(f"Last refuse evaluator: {last_refuse.evaluator if last_refuse else None}")
    print(f"Chain length after the burst: {chain.length}")
    print()

    ok = permit_count == 3 and refuse_count == 1
    results.append(("Case D: 3 permit, 4th refuses on rate", ok))

    # -----------------------------------------------------------------
    # Case E: export the chain, reverify, tamper, reverify.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case E: export the chain, reverify, tamper, reverify again.")
    print("-" * 70)
    print("Exports the whole chain to JSONL bytes, one entry per line.")
    print("Reverify against the audit bundle's public keys. Then mutate")
    print("entry 2 (zero indexed) inside the JSONL blob and reverify,")
    print("expecting the verifier to raise and name the exact entry that")
    print("was touched. This is the property the compliance team relies")
    print("on: if one line in the audit log was changed after the fact,")
    print("we know exactly which one.")
    print()

    jsonl = bytes(chain.export_jsonl())
    line_count = len(jsonl.splitlines())
    print(f"JSONL bytes length: {len(jsonl)}")
    print(f"JSONL line count:   {line_count}")
    print(f"Chain length:       {chain.length}")

    audit_bundle = audit_kp.public_keys()

    clean_count = -1
    try:
        clean_count = SignedAuditChain.verify_jsonl(jsonl, audit_bundle)
        print(f"Clean reverify: passed ({clean_count} entries verified).")
    except Exception as e:
        print(f"Clean reverify raised unexpectedly: {type(e).__name__}: {e}")
    print()

    results.append(("Case E: exported chain reverifies cleanly",
                    clean_count == chain.length))
    results.append(("Case E: line count matches chain length",
                    line_count == chain.length))

    # Pick an entry inside the body to mutate. signed_payload.data is
    # a list of bytes (integers 0 to 255) as JSONL serialises it. We
    # flip the first byte, which breaks the ML-DSA signature on that
    # entry without breaking the surrounding JSON.
    def flip_first_data_byte(obj):
        data = list(obj["signed_payload"]["data"])
        data[0] = (data[0] + 7) & 0xFF
        obj["signed_payload"]["data"] = data

    tampered = mutate_line(jsonl, 2, flip_first_data_byte)
    print("Mutating one byte inside entry 2's signed payload and reverifying.")
    tamper_refused = False
    tamper_message = ""
    try:
        SignedAuditChain.verify_jsonl(tampered, audit_bundle)
    except Exception as e:
        tamper_refused = True
        tamper_message = str(e)
    print(f"  raised: {tamper_refused}")
    print(f"  message (first 220 chars): {tamper_message[:220]}")
    print()

    ok = tamper_refused and ("entry" in tamper_message.lower() or "2" in tamper_message)
    results.append(("Case E: tampered entry 2 is refused", ok))

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
