"""
Scenario 16: healthcare PHI access with a signed audit chain.

The story
---------
A regional hospital runs every electronic health record read through
a Kavach gate. The rule for an attending physician is that a PHI
read is allowed only when three conditions all hold:

    1. Country fence. The ActionContext carries a country_code param
       and the policy refuses anything that is not 'US'. A note on
       what this actually catches: Kavach does not look at IP
       addresses, it does not detect VPNs, and it does not resolve
       geography on its own. It enforces the rule you wrote against
       the field you gave it. In production the country code has to
       be filled in upstream, by something the attacker cannot
       forge: the HTTP handler reads the source IP from a trusted
       hop (Cloudflare CF-IPCountry, AWS CloudFront-Viewer-Country,
       MaxMind, IPinfo) and puts that into the context before the
       gate runs. If that upstream resolver is fooled by a VPN that
       egresses in the US, the gate sees country_code='US' and
       permits; the VPN detection is a separate feed (IPQS, Spur,
       MaxMind's anonymous IP DB) whose output lands in its own
       param. We model the upstream resolver as a small stub below,
       to keep the boundary visible.

    2. Day shift. The wall clock must be inside 07:00 to 19:00
       Pacific time. Night shift reads go through a separate RBAC
       path, so any read outside that window from a day shift
       principal must refuse.

    3. Rate cap. At most 50 reads per hour per doctor. A burst
       above that is usually an automated scraper and we want to
       shed it at the gate.

Every read, whether it permits or refuses, is appended to a signed
audit chain so the compliance team can replay the day end to end.
Patient identifiers are hashed before they enter the chain (we keep
the first 16 hex chars of a SHA-256 of the patient id), so a log
dump can never reverse link into PHI. The raw patient id is still
recoverable from the primary EHR database if an investigation needs
it.

Six cases:

    A. In country, in shift, first read, expect PERMIT.
    B. Out of country (caller resolves to IN), expect REFUSE.
    C. Out of shift gate (window excludes 'now'), expect REFUSE.
    D. 51 reads in a row on the in-shift gate. 50 permit, 51st
       refuses.
    E. Export the chain to JSONL, reverify it, line count matches.
    F. Tamper one byte inside entry 2 of the exported blob, verify
       fails and names the exact entry index.

Run this file directly:

    python tier3/16_healthcare_phi.py
"""

import hashlib
import json
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from kavach import (
    ActionContext,
    AuditEntry,
    Gate,
    KavachKeyPair,
    SignedAuditChain,
)


LA = ZoneInfo("America/Los_Angeles")


def in_shift_window() -> str:
    # A window around the current wall clock so the in-shift gate
    # always matches whatever time of day we run the scenario.
    now = datetime.now(tz=LA)
    start = (now - timedelta(minutes=15)).replace(second=0, microsecond=0)
    end = (now + timedelta(minutes=15)).replace(second=0, microsecond=0)
    return f"{start.strftime('%H:%M')}-{end.strftime('%H:%M')} America/Los_Angeles"


def out_of_shift_window() -> str:
    # A window pushed 6 hours into the future so it never contains
    # the current moment, whatever time of day we run.
    anchor = datetime.now(tz=LA) + timedelta(hours=6)
    start = anchor.replace(second=0, microsecond=0)
    end = (anchor + timedelta(minutes=30)).replace(second=0, microsecond=0)
    return f"{start.strftime('%H:%M')}-{end.strftime('%H:%M')} America/Los_Angeles"


def build_policies(shift_window):
    return {
        "policies": [
            {
                "name": "phi_day_shift_read",
                "description": "Attending physicians read PHI, US only, day shift, 50/hour",
                "effect": "permit",
                "priority": 10,
                "conditions": [
                    {"identity_role": "attending_physician"},
                    {"action": "phi.read"},
                    {"param_in": {"field": "country_code", "values": ["US"]}},
                    {"time_window": shift_window},
                    {"rate_limit": {"max": 50, "window": "1h"}},
                ],
            },
        ],
    }


def patient_hash(patient_id: str) -> str:
    return hashlib.sha256(patient_id.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------
# The upstream boundary. REPLACE THIS IN PRODUCTION.
#
# This stub stands in for whatever your HTTP handler actually does to
# turn a raw request into a country code. In real code you might:
#
#   a. Read Cloudflare's CF-IPCountry request header (trusted because
#      Cloudflare terminates TLS and the header cannot be forged by
#      a client).
#   b. Read AWS's CloudFront-Viewer-Country header on an API Gateway
#      or CloudFront-fronted service.
#   c. Look the source IP up in a MaxMind or IPinfo database that
#      ships with your deployment.
#
# The scenario below only exercises what Kavach does once the country
# code is already in the ActionContext. It does not claim Kavach can
# tell you the country on its own.
#
# A 'request' here is a plain dict with a 'trusted_country_header'
# field, simulating the HTTP hop that already did the resolution.
# ---------------------------------------------------------------------
def resolve_country_from_request(request: dict) -> str:
    header = request.get("trusted_country_header")
    if not header:
        # Fail closed: no resolved country means the gate gets a value
        # that no policy rule whitelists, so default deny fires.
        return "UNKNOWN"
    return header


def phi_ctx(principal_id, request):
    country_code = resolve_country_from_request(request)
    ctx = ActionContext(
        principal_id=principal_id,
        principal_kind="user",
        action_name="phi.read",
        roles=["attending_physician"],
    )
    ctx.with_param("country_code", country_code)
    return ctx


def audit_from_verdict(chain, principal_id, patient_id, verdict):
    detail = {
        "patient_hash": patient_hash(patient_id),
        "evaluator": verdict.evaluator,
        "code": verdict.code,
        "reason": verdict.reason,
    }
    chain.append(AuditEntry(
        principal_id=principal_id,
        action_name="phi.read",
        verdict=verdict.kind,
        verdict_detail=json.dumps(detail, separators=(",", ":")),
    ))


def mutate_line(jsonl: bytes, idx: int, mutator) -> bytes:
    lines = jsonl.splitlines()
    obj = json.loads(lines[idx].decode("utf-8"))
    mutator(obj)
    lines[idx] = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return b"\n".join(lines) + (b"\n" if jsonl.endswith(b"\n") else b"")


def main():
    print("=" * 70)
    print("Scenario 16: healthcare PHI access with a signed audit chain")
    print("=" * 70)
    print()
    print("We are going to build an in-shift gate, send one baseline read,")
    print("two refuses (out of country and out of shift), then a 51 call")
    print("burst to trip the rate limit. Every attempt is audited. We")
    print("export the chain, reverify it, and then tamper one entry to")
    print("show the verifier names exactly which entry was touched.")
    print()

    results = []

    # -----------------------------------------------------------------
    # Audit keypair and chain.
    # -----------------------------------------------------------------
    print("Generating an audit keypair and opening a PQ-only signed chain.")
    audit_kp = KavachKeyPair.generate()
    audit_bundle = audit_kp.public_keys()
    chain = SignedAuditChain(audit_kp, hybrid=False)
    print(f"  audit.key_id:    {audit_kp.id}")
    print(f"  chain.is_hybrid: {chain.is_hybrid}")
    print(f"  chain.length:    {chain.length}")
    print(f"  chain.head_hash: {chain.head_hash}")
    print()

    # -----------------------------------------------------------------
    # In-shift gate.
    # -----------------------------------------------------------------
    shift_in = in_shift_window()
    print(f"Building the in-shift gate. Shift window: {shift_in}")
    gate = Gate.from_dict(build_policies(shift_in))
    print(f"  gate.evaluator_count: {gate.evaluator_count}")
    print()

    # -----------------------------------------------------------------
    # Case A: baseline.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case A: dr-smith, US, in shift, opens the EHR for patient P-1042.")
    print("-" * 70)
    print("All three conditions hold. The rate bucket is empty. The rule")
    print("permits and the chain gains its first entry. The patient id")
    print("hashes into the audit entry, never the raw form.")
    print()

    # A "request" here stands in for whatever your HTTP handler
    # already resolved. Cloudflare set CF-IPCountry='US' because the
    # source IP belongs to a US ISP in Portland.
    request_us = {"trusted_country_header": "US"}
    ctx = phi_ctx("dr-smith", request_us)
    v = gate.evaluate(ctx)
    print(f"Resolved country: {resolve_country_from_request(request_us)}")
    print(f"Verdict kind: {v.kind}")
    print(f"Is permit:    {v.is_permit}")
    print(f"Patient hash: {patient_hash('P-1042')}")
    audit_from_verdict(chain, "dr-smith", "P-1042", v)
    print(f"Chain length: {chain.length}")
    print()

    results.append(("Case A: baseline PHI read permits", v.is_permit))
    results.append(("Case A: chain length becomes 1", chain.length == 1))

    # -----------------------------------------------------------------
    # Case B: out of country.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case B: the upstream resolver reports IN (India).")
    print("-" * 70)
    print("Same doctor, same shift, same rate bucket. The difference is")
    print("that whatever sits in front of the gate (Cloudflare header,")
    print("MaxMind lookup on source IP) returned 'IN' this time. Maybe")
    print("dr-smith is travelling and opened a laptop in Bengaluru; maybe")
    print("the clinic's edge network re-routed through an Indian POP;")
    print("maybe it was a genuine bad actor. The gate does not know. It")
    print("sees country_code='IN' and the policy rule does not match,")
    print("so default deny refuses. The audit chain still records the")
    print("attempt so compliance can triage.")
    print()

    # Cloudflare/MaxMind reported IN because the request egressed from
    # an Indian ISP. The gate is only as good as this upstream value.
    request_in = {"trusted_country_header": "IN"}
    ctx = phi_ctx("dr-smith", request_in)
    v = gate.evaluate(ctx)
    print(f"Resolved country: {resolve_country_from_request(request_in)}")
    print(f"Verdict kind: {v.kind}")
    print(f"Is refuse:    {v.is_refuse}")
    print(f"Evaluator:    {v.evaluator}")
    print(f"Code:         {v.code}")
    audit_from_verdict(chain, "dr-smith", "P-1042", v)
    print(f"Chain length: {chain.length}")
    print()

    results.append(("Case B: out of country refuses", v.is_refuse))
    results.append(("Case B: refuse code NO_POLICY_MATCH", v.code == "NO_POLICY_MATCH"))
    results.append(("Case B: chain length becomes 2", chain.length == 2))

    # -----------------------------------------------------------------
    # Case C: out of shift.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case C: a second gate with a window that excludes 'now'.")
    print("-" * 70)
    print("We build a separate gate whose window starts 6 hours in the")
    print("future, to simulate dr-smith trying to use a day shift path")
    print("in the middle of the night. time_window fails, refuses.")
    print()

    shift_out = out_of_shift_window()
    print(f"out of shift window: {shift_out}")
    gate_out = Gate.from_dict(build_policies(shift_out))
    ctx = phi_ctx("dr-smith", {"trusted_country_header": "US"})
    v = gate_out.evaluate(ctx)
    print(f"Verdict kind: {v.kind}")
    print(f"Is refuse:    {v.is_refuse}")
    print(f"Evaluator:    {v.evaluator}")
    print(f"Code:         {v.code}")
    audit_from_verdict(chain, "dr-smith", "P-2007", v)
    print(f"Chain length: {chain.length}")
    print()

    results.append(("Case C: out of shift refuses", v.is_refuse))
    results.append(("Case C: refuse code NO_POLICY_MATCH", v.code == "NO_POLICY_MATCH"))
    results.append(("Case C: chain length becomes 3", chain.length == 3))

    # -----------------------------------------------------------------
    # Case D: 51 call burst.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case D: dr-burst-test fires 51 reads in a row on the in-shift gate.")
    print("-" * 70)
    print("Rate limit is 50 per hour. We expect 50 permits and 1 refuse.")
    print("Each attempt is audited, so the chain grows by 51.")
    print()

    burst_principal = "dr-burst-test"
    BURST_SIZE = 51
    permit_count = 0
    refuse_count = 0
    last_refuse = None
    burst_request = {"trusted_country_header": "US"}
    for i in range(BURST_SIZE):
        ctx = phi_ctx(burst_principal, burst_request)
        v = gate.evaluate(ctx)
        audit_from_verdict(chain, burst_principal, f"P-burst-{i:03d}", v)
        if v.is_permit:
            permit_count += 1
        elif v.is_refuse:
            refuse_count += 1
            last_refuse = v

    print(f"Permits: {permit_count}")
    print(f"Refuses: {refuse_count}")
    print(f"last refuse code: {last_refuse.code if last_refuse else None}")
    print(f"Chain length: {chain.length}")
    print()

    results.append(("Case D: 50 permits", permit_count == 50))
    results.append(("Case D: 1 refuse", refuse_count == 1))
    results.append((
        "Case D: 51st refuse code NO_POLICY_MATCH",
        last_refuse is not None and last_refuse.code == "NO_POLICY_MATCH",
    ))
    results.append((
        "Case D: chain length is 3 + 51 = 54",
        chain.length == 3 + BURST_SIZE,
    ))

    # -----------------------------------------------------------------
    # Case E: export and verify.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case E: export the chain to JSONL and reverify it.")
    print("-" * 70)
    print("Each line is a PQ-signed audit entry. verify_jsonl hashes and")
    print("verifies every line in order. On a clean chain, the verified")
    print("count equals chain.length.")
    print()

    jsonl = bytes(chain.export_jsonl())
    verified = SignedAuditChain.verify_jsonl(jsonl, audit_bundle)
    line_count = jsonl.count(b"\n")
    print(f"JSONL size:       {len(jsonl)} bytes")
    print(f"line count:       {line_count}")
    print(f"verified entries: {verified}")
    print(f"chain.length:     {chain.length}")
    print()

    first_line = jsonl.splitlines()[0]
    first_obj = json.loads(first_line.decode("utf-8"))
    print("First entry outer shape (truncated):")
    print(f"  index:                 {first_obj.get('index')}")
    print(f"  previous_hash[:24]:    {(first_obj.get('previous_hash') or '')[:24]}")
    print(f"  entry_hash[:24]:       {(first_obj.get('entry_hash') or '')[:24]}")
    print(f"  signed_payload.key_id: {first_obj['signed_payload']['key_id']}")
    print()

    results.append(("Case E: verify_jsonl returns chain.length", verified == chain.length))

    # -----------------------------------------------------------------
    # Case F: tamper entry 2.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case F: flip one byte inside entry 2 and reverify.")
    print("-" * 70)
    print("Entry 2 is the out of shift refuse from case C. We flip one")
    print("byte inside signed_payload.data. The ML-DSA signature no")
    print("longer covers the changed bytes, so the chain verifier fails.")
    print("The error message should name 'entry 2', so a forensic tool")
    print("can point directly at the mutated entry.")
    print()

    target_idx = 2

    def flip_first_data_byte(obj):
        data = list(obj["signed_payload"]["data"])
        data[0] = (data[0] + 7) & 0xFF
        obj["signed_payload"]["data"] = data

    tampered = mutate_line(jsonl, target_idx, flip_first_data_byte)
    try:
        SignedAuditChain.verify_jsonl(tampered, audit_bundle)
        print("  verify_jsonl accepted the tampered chain. That is wrong.")
        results.append(("Case F: tampered chain refused", False))
        results.append(("Case F: error message mentions 'entry 2'", False))
    except ValueError as e:
        msg = str(e)
        print(f"  verify_jsonl raised ValueError as expected.")
        print(f"  message: {msg[:220]}")
        results.append(("Case F: tampered chain refused", True))
        results.append((
            f"Case F: error message references entry {target_idx}",
            f"entry {target_idx}" in msg,
        ))
        results.append((
            "Case F: error message names 'signature verification failed'",
            "signature verification failed" in msg,
        ))
    print()

    again = SignedAuditChain.verify_jsonl(jsonl, audit_bundle)
    print(f"  untouched original chain still verifies: {again} of {chain.length}")
    print()
    results.append(("Case F: untouched chain still verifies", again == chain.length))

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
