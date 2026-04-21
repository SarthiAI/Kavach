"""
Scenario 11: e-commerce fraud gate with observe only rollout.

The story
---------
An online storefront turns on Kavach as its checkout fraud gate.
Every card charge passes through four overlapping layers:

    1. Identity tier. New customers charge up to $500 per call.
       KYC verified customers charge up to $10,000 per call.
    2. Rate limit. New customers do at most 3 charges per hour.
    3. Geo drift. Tolerant mode, 500 km threshold. A NYC to Tokyo
       session hop invalidates.
    4. Invariant. Hard $5,000 ceiling above every tier.

The team rolls this out safely. For the first 48 hours, a second
'observe only' gate runs alongside the strict one. Both evaluate
the full chain. The observe gate always returns permit so callers
never see a false reject during calibration; the audit chain
still records what the strict gate WOULD have said.

Seven cases: A normal charge, B new-cap breach, C rate burst,
D cross-continent drift, E invariant, F observe only, G JSONL
round trip.

Run this file directly:

    python tier2/11_ecommerce_fraud.py
"""

from kavach import (
    ActionContext,
    AuditEntry,
    Gate,
    GeoLocation,
    KavachKeyPair,
    SignedAuditChain,
)


POLICIES = {
    "policies": [
        {
            "name": "verified_customer_checkout",
            "effect": "permit",
            "priority": 10,
            "conditions": [
                {"identity_role": "customer.verified"},
                {"action": "checkout.charge"},
                {"param_max": {"field": "amount_usd", "max": 10000.0}},
            ],
        },
        {
            "name": "new_customer_checkout",
            "effect": "permit",
            "priority": 20,
            "conditions": [
                {"identity_role": "customer"},
                {"action": "checkout.charge"},
                {"param_max": {"field": "amount_usd", "max": 500.0}},
                {"rate_limit": {"max": 3, "window": "1h"}},
            ],
        },
    ],
}

INVARIANTS = [("manual_review_threshold", "amount_usd", 5000.0)]
GEO_DRIFT_KM = 500.0

NYC = GeoLocation(country_code="US", city="New York", latitude=40.7128, longitude=-74.0060)
NEWARK = GeoLocation(country_code="US", city="Newark", latitude=40.7357, longitude=-74.1724)
TOKYO = GeoLocation(country_code="JP", city="Tokyo", latitude=35.6762, longitude=139.6503)


def charge(principal, role, amount, origin_geo=NYC, current_geo=NYC,
           origin_ip="203.0.113.10", ip="203.0.113.10"):
    return ActionContext(
        principal_id=principal,
        principal_kind="user",
        action_name="checkout.charge",
        roles=[role],
        params={"amount_usd": amount},
        origin_geo=origin_geo,
        current_geo=current_geo,
        origin_ip=origin_ip,
        ip=ip,
    )


def audit(chain, principal, verdict, phase):
    detail = f"phase={phase} | evaluator={verdict.evaluator or '-'} | code={verdict.code or '-'}"
    if verdict.reason:
        detail += f" | reason={verdict.reason[:80]}"
    chain.append(AuditEntry(
        principal_id=principal,
        action_name="checkout.charge",
        verdict=verdict.kind,
        verdict_detail=detail,
    ))


def run(strict_gate, chain, principal, ctx, phase="enforce"):
    v = strict_gate.evaluate(ctx)
    audit(chain, principal, v, phase)
    return v


def main():
    print("=" * 70)
    print("Scenario 11: e-commerce fraud gate with observe only rollout")
    print("=" * 70)
    print()

    # Two gates from the same policy: one strict, one observe-only.
    strict_gate = Gate.from_dict(POLICIES, invariants=INVARIANTS, geo_drift_max_km=GEO_DRIFT_KM)
    observe_gate = Gate.from_dict(POLICIES, invariants=INVARIANTS,
                                  geo_drift_max_km=GEO_DRIFT_KM, observe_only=True)
    audit_kp = KavachKeyPair.generate()
    chain = SignedAuditChain(audit_kp, hybrid=False)
    print(f"  strict_gate.evaluator_count:  {strict_gate.evaluator_count}")
    print(f"  observe_gate.evaluator_count: {observe_gate.evaluator_count}")
    print(f"  chain.is_hybrid={chain.is_hybrid}  audit.key_id={audit_kp.id}")
    print()

    results = []

    # --- Case A: normal $150 charge.
    print("Case A: new customer alice, $150 from usual IP.")
    v = run(strict_gate, chain, "cust-alice",
            charge("cust-alice", "customer", 150.0))
    print(f"  {v.kind}  token={v.token_id}  chain={chain.length}")
    print()
    results.append(("Case A: $150 permits", v.is_permit))
    results.append(("Case A: carries a permit token", v.permit_token is not None))

    # --- Case B: over new-customer cap.
    print("Case B: new customer bob, $750 (over $500 cap).")
    v = run(strict_gate, chain, "cust-bob",
            charge("cust-bob", "customer", 750.0, origin_ip="203.0.113.11", ip="203.0.113.11"))
    print(f"  {v.kind}  evaluator={v.evaluator}  code={v.code}")
    print()
    results.append(("Case B: $750 refuses on tier cap", v.is_refuse and v.code == "NO_POLICY_MATCH"))

    # --- Case C: rate limit burst.
    print("Case C: new customer claire fires 4 charges of $150 in one hour.")
    permits = refuses = 0
    for i in range(4):
        v = run(strict_gate, chain, "cust-claire.burst",
                charge("cust-claire.burst", "customer", 150.0,
                       origin_ip="198.51.100.22", ip="198.51.100.22"))
        print(f"  burst {i + 1}: {v.kind}  code={v.code or '-'}")
        if v.is_permit:
            permits += 1
        else:
            refuses += 1
    print()
    results.append(("Case C: 3 permit, 4th refuses on rate", permits == 3 and refuses == 1))

    # --- Case D: drift (NYC to Tokyo) and a control (NYC to Newark).
    print("Case D: verified dana, NYC session then Tokyo charge. Then a Newark control.")
    v_hop = run(strict_gate, chain, "cust-dana.verified",
                charge("cust-dana.verified", "customer.verified", 50.0,
                       origin_geo=NYC, current_geo=TOKYO,
                       origin_ip="203.0.113.42", ip="198.51.100.99"))
    v_local = run(strict_gate, chain, "cust-dana2.verified",
                  charge("cust-dana2.verified", "customer.verified", 50.0,
                         origin_geo=NYC, current_geo=NEWARK,
                         origin_ip="203.0.113.43", ip="203.0.113.44"))
    print(f"  Tokyo hop: {v_hop.kind}  evaluator={v_hop.evaluator}")
    print(f"  reason:    {v_hop.reason}")
    print(f"  Newark hop: {v_local.kind}  (control)")
    print()
    results.append(("Case D: Tokyo hop invalidates on drift",
                    v_hop.is_invalidate and v_hop.evaluator == "drift"))
    results.append(("Case D: Newark hop permits", v_local.is_permit))

    # --- Case E: invariant at $5,001 (above policy, below invariant).
    print("Case E: verified ethan, $5,001 (invariant ceiling).")
    v = run(strict_gate, chain, "cust-ethan.verified",
            charge("cust-ethan.verified", "customer.verified", 5001.0,
                   origin_ip="203.0.113.50", ip="203.0.113.50"))
    print(f"  {v.kind}  evaluator={v.evaluator}  code={v.code}")
    print(f"  reason: {v.reason}")
    print()
    results.append(("Case E: $5,001 refuses on invariant",
                    v.is_refuse and v.evaluator == "invariants"
                    and "manual_review_threshold" in (v.reason or "")))

    # --- Case F: observe-only. Strict gate would refuse; caller gets permit.
    print("Case F: observe only, $750 from new customer felix.")
    ctx = charge("cust-felix", "customer", 750.0,
                 origin_ip="203.0.113.60", ip="203.0.113.60")
    would_have = strict_gate.evaluate(ctx)
    audit(chain, "cust-felix", would_have, phase="observe")
    caller_facing = observe_gate.evaluate(ctx)
    print(f"  strict would have: {would_have.kind}  code={would_have.code}")
    print(f"  caller facing:     {caller_facing.kind}  token={caller_facing.token_id}")
    print()
    results.append(("Case F: would-have refuses", would_have.is_refuse))
    results.append(("Case F: caller facing permits", caller_facing.is_permit))

    # --- Case G: JSONL round trip.
    print("Case G: export chain and reverify.")
    exported = bytes(chain.export_jsonl())
    verified = SignedAuditChain.verify_jsonl(exported, audit_kp.public_keys())
    line_count = len([line for line in exported.split(b"\n") if line])
    print(f"  chain.length={chain.length}  exported lines={line_count}  verified={verified}")
    print()
    results.append(("Case G: JSONL line count matches", line_count == chain.length))
    results.append(("Case G: verify_jsonl returns chain length", verified == chain.length))

    # --- Summary.
    print("=" * 70)
    print("Summary")
    print("=" * 70)
    passed = sum(1 for _, ok in results if ok)
    for label, ok in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    print()
    print(f"{passed}/{len(results)} checks passed.")
    print()
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
