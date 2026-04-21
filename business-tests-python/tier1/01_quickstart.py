"""
Scenario 01: quick start, three lines to ship a gate.

The story
---------
The smallest useful program you can write with Kavach. If you are
evaluating the library, read this first: it is the whole happy
path, from policy to verdict, in under 60 lines of code.

Run this file directly:

    python tier1/01_quickstart.py
"""

from kavach import ActionContext, Gate


# One rule. Finance team can move money, capped at $10,000 per
# call. That is the whole policy.
POLICIES = {
    "policies": [
        {
            "name": "finance_can_transfer",
            "effect": "permit",
            "priority": 10,
            "conditions": [
                {"identity_role": "finance"},
                {"action": "treasury.transfer"},
                {"param_max": {"field": "amount_usd", "max": 10000.0}},
            ],
        },
    ],
}


def main():
    print("Kavach quick start")
    print("=" * 40)

    # Build the gate. One line.
    gate = Gate.from_dict(POLICIES)

    # Three calls through the gate: one permitted, two refused.
    cases = [
        ("finance user, $5,000",
         ActionContext(
             principal_id="alice",
             principal_kind="user",
             action_name="treasury.transfer",
             roles=["finance"],
             params={"amount_usd": 5000.0},
         )),
        ("finance user, $50,000 (over cap)",
         ActionContext(
             principal_id="alice",
             principal_kind="user",
             action_name="treasury.transfer",
             roles=["finance"],
             params={"amount_usd": 50000.0},
         )),
        ("engineer, $100 (wrong role)",
         ActionContext(
             principal_id="bob",
             principal_kind="user",
             action_name="treasury.transfer",
             roles=["engineer"],
             params={"amount_usd": 100.0},
         )),
    ]

    results = []
    for label, ctx in cases:
        v = gate.evaluate(ctx)
        print(f"{label:<42}  {v.kind:>6}")
        results.append(v)

    assert results[0].is_permit, "finance $5k should permit"
    assert results[1].is_refuse, "$50k should refuse on cap"
    assert results[2].is_refuse, "engineer should refuse on role"

    print("=" * 40)
    print("3/3 checks passed. You just shipped a gate.")
    print("Read 02_document_access.py next, then 03_reset_geo_drift.py.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
