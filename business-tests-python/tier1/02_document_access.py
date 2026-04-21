"""
Scenario 02: document classification, rate limit, and app side scoping.

The story
---------
A consulting firm runs its workpaper service behind a Kavach gate.
Every read has to satisfy three rules before the document service
even looks at the filesystem:

    1. Role. The caller must be a consultant. Anything else is
       refused by default deny.

    2. Classification tier. Each document is tagged with one of
       'public', 'internal', or 'engagement_workpapers'. A
       consultant may read those three tiers. A separate tier,
       'board_confidential', is off limits to consultants; only
       partners touch those documents and a different rule (not
       in this scenario) would cover them.

    3. Read rate. At most 60 reads per hour per consultant. Bursts
       above that are almost always a script or a page that
       auto-refreshes in a loop.

On top of the gate, the service layers one per user check that
Kavach does not try to do for you: the consultant must actually be
staffed on the engagement the document belongs to. The staffing
list comes from HR and varies per user per day, which is a bad fit
for a static policy file; it is a natural fit for a one line app
side check right after the gate permits.

This is the typical production split: Kavach enforces the rules
every call shares (role, classification, rate), and your service
layers its own per caller check where that makes sense. Both
halves are visible in the cases below.

Five cases:

    A. Alice staffed on E-4471, reads an 'internal' doc on E-4471.
       Gate permits, app permits.
    B. Alice reads an 'internal' doc on E-9001 (not on her list).
       Gate permits (role, classification, rate all fine), app
       refuses because the engagement is not in her staffing.
    C. Alice reads a 'board_confidential' doc on E-4471.
       Gate refuses on classification, the app check never runs.
    D. Alice fires 61 reads in one hour.
       First 60 permit, the 61st refuses on the rate condition.
    E. Alice's client grants temporary access to E-9001. Her
       staffing list is widened for this session and the next
       read on E-9001 now permits at both the gate and the app.

Run this file directly:

    python tier1/02_document_access.py
"""

from kavach import ActionContext, Gate


# Kavach handles role, classification, and rate. The staffing list
# is a per caller per day fact that does not belong in a static
# policy file; the service checks it right after the gate.
POLICIES = {
    "policies": [
        {
            "name": "consultant_reads_documents",
            "description": "Consultants may read public, internal, and engagement workpapers at up to 60 reads per hour",
            "effect": "permit",
            "priority": 10,
            "conditions": [
                {"identity_role": "consultant"},
                {"action": "document.read"},
                {"param_in": {
                    "field": "classification",
                    "values": ["public", "internal", "engagement_workpapers"],
                }},
                {"rate_limit": {"max": 60, "window": "1h"}},
            ],
        },
    ],
}


def read_ctx(user_id, engagement_id, classification):
    ctx = ActionContext(
        principal_id=user_id,
        principal_kind="user",
        action_name="document.read",
        roles=["consultant"],
        resource=f"engagements/{engagement_id}/workpaper.pdf",
    )
    ctx.with_param("engagement_id", engagement_id)
    ctx.with_param("classification", classification)
    return ctx


def app_check(verdict, engagement_id, staffed_on):
    """Per user engagement scoping. Runs only when the gate has
    permitted; Kavach already handled role, classification, rate."""
    if not verdict.is_permit:
        return verdict.kind, "gate refused"
    if engagement_id not in staffed_on:
        return "refuse", "engagement not on the consultant's staffing list"
    return "permit", "gate permitted and engagement is in the staffing list"


def main():
    print("=" * 70)
    print("Scenario 02: document classification, rate limit, and app side scoping")
    print("=" * 70)
    print()
    print("We are going to build a gate that enforces role, classification")
    print("tier, and a 60 per hour rate cap, then layer one small app side")
    print("check on top for per user engagement scoping. The cases show")
    print("both sides: Kavach refusing the wrong classification and the")
    print("runaway rate, and the app refusing engagements that are not on")
    print("the caller's staffing list.")
    print()

    gate = Gate.from_dict(POLICIES)
    print(f"Gate built. It has {gate.evaluator_count} evaluators.")
    print()

    results = []

    # ---- Case A: baseline, everything lines up.
    print("-" * 70)
    print("Case A: alice staffed on E-4471, reads an 'internal' doc on E-4471.")
    print("-" * 70)
    alice_staffing = ["E-4471"]
    v = gate.evaluate(read_ctx("alice", "E-4471", "internal"))
    kind, reason = app_check(v, "E-4471", alice_staffing)
    print(f"  gate verdict: {v.kind}")
    print(f"  app check:    {kind} ({reason})")
    print()
    results.append(("Case A: own engagement, internal doc permits", kind == "permit"))

    # ---- Case B: app refuses, gate permits.
    print("-" * 70)
    print("Case B: alice tries an 'internal' doc on E-9001 (not on her list).")
    print("-" * 70)
    print("Role, classification, and rate are all fine. The gate permits.")
    print("The app side staffing check is the one that catches this, and")
    print("reports 'engagement not on the staffing list'. This is the")
    print("composition pattern: Kavach and the service each own the piece")
    print("they are best at.")
    print()
    v = gate.evaluate(read_ctx("alice", "E-9001", "internal"))
    kind, reason = app_check(v, "E-9001", alice_staffing)
    print(f"  gate verdict: {v.kind}  (gate does not know the staffing list)")
    print(f"  app check:    {kind} ({reason})")
    print()
    results.append(("Case B: gate permits, app refuses on engagement scope",
                    v.is_permit and kind == "refuse"))

    # ---- Case C: gate refuses on classification.
    print("-" * 70)
    print("Case C: alice tries a 'board_confidential' doc on E-4471.")
    print("-" * 70)
    print("Classification is not in the allow list for consultants. The")
    print("gate refuses before the app side check runs. This is Kavach")
    print("doing real enforcement: wrong classification never reaches the")
    print("document service, the staffing check is never consulted.")
    print()
    v = gate.evaluate(read_ctx("alice", "E-4471", "board_confidential"))
    kind, reason = app_check(v, "E-4471", alice_staffing)
    print(f"  gate verdict: {v.kind}  evaluator={v.evaluator}  code={v.code}")
    print(f"  app check:    {kind} ({reason})")
    print()
    results.append(("Case C: wrong classification refused at the gate",
                    v.is_refuse and v.evaluator == "policy"
                    and v.code == "NO_POLICY_MATCH"))

    # ---- Case D: gate rate limit.
    print("-" * 70)
    print("Case D: alice fires 61 reads in one hour.")
    print("-" * 70)
    print("First 60 clear the rate condition. The 61st crosses the cap")
    print("and the rule no longer matches, so default deny refuses. This")
    print("is Kavach keeping a runaway page or script from draining the")
    print("document service, without the app having to implement its own")
    print("rate counter. We build a fresh gate here so the rate bucket")
    print("is isolated from earlier cases.")
    print()
    burst_gate = Gate.from_dict(POLICIES)
    permits = 0
    refuses = 0
    last_refuse = None
    for i in range(61):
        v = burst_gate.evaluate(read_ctx("alice", "E-4471", "internal"))
        if v.is_permit:
            permits += 1
        else:
            refuses += 1
            last_refuse = v
    print(f"  permits: {permits}")
    print(f"  refuses: {refuses}")
    if last_refuse is not None:
        print(f"  last refuse evaluator: {last_refuse.evaluator}  code: {last_refuse.code}")
    print()
    results.append(("Case D: 60 permit, 61st refuses on rate",
                    permits == 60 and refuses == 1))

    # ---- Case E: staffing widens mid session.
    print("-" * 70)
    print("Case E: alice's client grants temporary access to E-9001.")
    print("-" * 70)
    print("The app updates alice's staffing list for this session. No")
    print("policy reload, no gate rebuild, no deploy: Kavach does not")
    print("need to know about the change because the staffing list lives")
    print("on the app side. We build a fresh gate here so the case is")
    print("isolated from case D's rate bucket.")
    print()
    alice_staffing = ["E-4471", "E-9001"]
    fresh_gate = Gate.from_dict(POLICIES)
    v = fresh_gate.evaluate(read_ctx("alice", "E-9001", "internal"))
    kind, reason = app_check(v, "E-9001", alice_staffing)
    print(f"  gate verdict: {v.kind}")
    print(f"  app check:    {kind} ({reason})")
    print()
    results.append(("Case E: widened staffing permits E-9001",
                    v.is_permit and kind == "permit"))

    # ---- Summary
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
