"""
Scenario 04: session hygiene with all four drift detectors.

The story
---------
Business dashboards often hold long sessions. A user might open the
dashboard in the morning and keep it open all day. Over that window,
plenty of things about the session can change for bad reasons:

    The IP address changes. Could be a VPN toggle, could be a
    session cookie stolen and replayed from somewhere else.

    The session is still alive four hours later. Maybe that user
    went for lunch and left the tab open, or maybe someone opened
    a drawer and found an unlocked laptop.

    The device fingerprint changes. Different browser, different
    OS, different screen size. Same cookie.

    The action rate suddenly spikes. A real person clicks a few
    times per minute. Hundreds of actions per minute usually means
    a script is driving the session.

Kavach has four drift detectors, one for each of these signals, and
they all run as part of the evaluator chain. Any one of them can
raise a violation and the gate invalidates the session. Downstream
code should then log the user out.

In this scenario we exercise all four detectors by crafting an
ActionContext that triggers each one in turn.

Six cases:

    A. Same IP, same geo                , expect PERMIT (baseline)
    B. IP changes mid session           , expect INVALIDATE
    C. Cross country hop (US to CN)     , expect INVALIDATE
    D. Session started 6 hours ago      , expect INVALIDATE
    E. Device fingerprint differs       , expect INVALIDATE
    F. 200 actions in a 60 second session, expect INVALIDATE

Run this file directly:

    python tier1/04_session_hygiene.py
"""

import time
import uuid

from kavach import ActionContext, DeviceFingerprint, Gate, GeoLocation


# ---------------------------------------------------------------------
# Step 1. Write the rule as a plain Python dict.
# ---------------------------------------------------------------------
# One simple permit rule for the dashboard read. The drift detectors
# run automatically as part of the evaluator chain; we just need to
# attach the right fields on the ActionContext to exercise each one.

POLICIES = {
    "policies": [
        {
            "name": "dashboard_read",
            "description": "Authenticated ops users may read the dashboard",
            "effect": "permit",
            "priority": 10,
            "conditions": [
                {"identity_role": "ops_user"},
                {"action": "dashboard.read"},
            ],
        },
    ],
}


# ---------------------------------------------------------------------
# Two geo anchors for the geo drift cases.
# ---------------------------------------------------------------------
GEO_NEW_YORK = GeoLocation(
    country_code="US", region="NY", city="New York",
    latitude=40.7128, longitude=-74.0060,
)
GEO_SHANGHAI = GeoLocation(
    country_code="CN", region="Shanghai", city="Shanghai",
    latitude=31.2304, longitude=121.4737,
)


def ops_ctx(session_id, **overrides):
    # Start from a clean baseline context and apply any overrides a
    # case wants. This keeps each case short and easy to read.
    base = dict(
        principal_id="ops-carol",
        principal_kind="user",
        action_name="dashboard.read",
        roles=["ops_user"],
        ip="198.51.100.20",
        origin_ip="198.51.100.20",
        current_geo=GEO_NEW_YORK,
        origin_geo=GEO_NEW_YORK,
        session_id=session_id,
    )
    base.update(overrides)
    return ActionContext(**base)


def main():
    print("=" * 70)
    print("Scenario 04: session hygiene with all four drift detectors")
    print("=" * 70)
    print()
    print("We are going to build a gate with one permit rule for the")
    print("dashboard read action. The drift detectors run automatically")
    print("as part of the evaluator chain, and each one watches a")
    print("different kind of session change. Then we craft six requests")
    print("that each exercise one detector.")
    print()

    # -----------------------------------------------------------------
    # Step 2. Build the gate in strict geo drift mode.
    # -----------------------------------------------------------------
    print("Building the gate from the policy dict.")
    print("We do not set geo_drift_max_km, which puts the geo drift")
    print("detector in strict mode: any mid session IP change counts as")
    print("a violation. The default thresholds for the other detectors")
    print("are:")
    print("  session age    : 4 hours")
    print("  action rate    : 100 per minute")
    print("  device change  : any hash change counts as a violation")
    gate = Gate.from_dict(POLICIES)
    print(f"Gate built. It has {gate.evaluator_count} evaluators chained together.")
    print()

    session_id = str(uuid.uuid4())
    print(f"Cases A through D share this session id: {session_id}")
    print("Cases E and F use fresh session ids to isolate each detector.")
    print()

    results = []

    # -----------------------------------------------------------------
    # Case A: baseline.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case A: same IP, same geo, fresh session.")
    print("-" * 70)
    print("Nothing has changed since the session started. All four drift")
    print("detectors report a stable session. Policy permits. This is")
    print("the baseline that proves the gate does not invalidate every")
    print("call by default. We expect: PERMIT.")
    print()

    v = gate.evaluate(ops_ctx(session_id))

    print(f"Verdict kind: {v.kind}")
    print(f"Is permit:    {v.is_permit}")
    print(f"Token id:     {v.token_id}")
    print()

    results.append(("Case A: stable session permits", v.is_permit))

    # -----------------------------------------------------------------
    # Case B: IP change mid session.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case B: the next request arrives from a different IP.")
    print("-" * 70)
    print("We pass the same session id but change the current IP from")
    print("198.51.100.20 to 203.0.113.77. In strict mode, any mid")
    print("session IP change is a violation and the gate invalidates.")
    print("We expect: INVALIDATE, evaluator 'drift', a reason that names")
    print("both IPs so the incident playbook has the context it needs.")
    print()

    v = gate.evaluate(ops_ctx(session_id, ip="203.0.113.77"))

    print(f"Verdict kind:  {v.kind}")
    print(f"Is invalidate: {v.is_invalidate}")
    print(f"Evaluator:     {v.evaluator}")
    print(f"Reason:        {v.reason}")
    print()

    ok = (
        v.is_invalidate
        and v.evaluator == "drift"
        and "198.51.100.20" in (v.reason or "")
        and "203.0.113.77" in (v.reason or "")
    )
    results.append(("Case B: IP change invalidates", ok))

    # -----------------------------------------------------------------
    # Case C: cross country hop.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case C: IP changes and the geo country code changes too.")
    print("-" * 70)
    print("Same session, new IP, and the geo now reports Shanghai (CN)")
    print("instead of New York (US). Strict geo drift already fires on")
    print("any IP change, so this is going to invalidate anyway. What")
    print("we additionally want to see is that the reason text surfaces")
    print("the new country tag (CN), so the alert is useful.")
    print()

    v = gate.evaluate(ops_ctx(
        session_id,
        ip="192.0.2.200",
        current_geo=GEO_SHANGHAI,
    ))

    print(f"Verdict kind:  {v.kind}")
    print(f"Is invalidate: {v.is_invalidate}")
    print(f"Evaluator:     {v.evaluator}")
    print(f"Reason:        {v.reason}")
    print()

    ok = v.is_invalidate and v.evaluator == "drift" and "CN" in (v.reason or "")
    results.append(("Case C: cross country hop invalidates with country tag", ok))

    # -----------------------------------------------------------------
    # Case D: old session.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case D: session started 6 hours ago.")
    print("-" * 70)
    print("We attach session_started_at set to 6 hours in the past. The")
    print("default session age cap is 4 hours. The session age drift")
    print("detector reports a violation. We expect: INVALIDATE, with a")
    print("reason that mentions 'session age'.")
    print()

    now = int(time.time())
    six_hours_ago = now - 6 * 3600
    v = gate.evaluate(ops_ctx(session_id, session_started_at=six_hours_ago))

    print(f"session_started_at: {six_hours_ago} (about 6 hours ago)")
    print(f"Verdict kind:  {v.kind}")
    print(f"Is invalidate: {v.is_invalidate}")
    print(f"Evaluator:     {v.evaluator}")
    print(f"Reason:        {v.reason}")
    print()

    ok = v.is_invalidate and "session age" in (v.reason or "").lower()
    results.append(("Case D: old session invalidates", ok))

    # -----------------------------------------------------------------
    # Case E: device fingerprint differs.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case E: device fingerprint changed on the same session.")
    print("-" * 70)
    print("We fill in two DeviceFingerprint objects, one for the origin")
    print("of the session and one for the current request. Their hashes")
    print("differ (the origin looks like a Mac desktop, the current")
    print("looks like an unknown Android). Kavach's device drift")
    print("detector reports a violation. We use a fresh session id so")
    print("this is not tangled up with case D's synthetic age.")
    print()

    fingerprint_original = DeviceFingerprint(
        hash="sha256:ORIGINAL-device",
        description="macOS desktop",
    )
    fingerprint_new = DeviceFingerprint(
        hash="sha256:DIFFERENT-device",
        description="unknown Android",
    )
    v = gate.evaluate(ops_ctx(
        str(uuid.uuid4()),
        origin_device=fingerprint_original,
        device=fingerprint_new,
    ))

    print(f"origin_device hash: {fingerprint_original.hash}")
    print(f"current device hash: {fingerprint_new.hash}")
    print(f"Verdict kind:  {v.kind}")
    print(f"Is invalidate: {v.is_invalidate}")
    print(f"Evaluator:     {v.evaluator}")
    print(f"Reason:        {v.reason}")
    print()

    ok = v.is_invalidate and "device" in (v.reason or "").lower()
    results.append(("Case E: device fingerprint change invalidates", ok))

    # -----------------------------------------------------------------
    # Case F: 200 actions in a 60 second old session.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case F: 200 actions in a session that started 60 seconds ago.")
    print("-" * 70)
    print("We synthesise a session with session_started_at set to 60")
    print("seconds in the past, and action_count set to 200. That is a")
    print("rate of 200 per minute, well above the default violation")
    print("threshold of 100 per minute. Behaviour drift reports a")
    print("violation. Again we use a fresh session id to keep this case")
    print("isolated. We expect: INVALIDATE, with a reason that mentions")
    print("the action rate.")
    print()

    sixty_seconds_ago = now - 60
    v = gate.evaluate(ops_ctx(
        str(uuid.uuid4()),
        session_started_at=sixty_seconds_ago,
        action_count=200,
    ))

    print(f"session_started_at: {sixty_seconds_ago} (60 seconds ago)")
    print(f"action_count:       200")
    print(f"Verdict kind:  {v.kind}")
    print(f"Is invalidate: {v.is_invalidate}")
    print(f"Evaluator:     {v.evaluator}")
    print(f"Reason:        {v.reason}")
    print()

    reason_lower = (v.reason or "").lower()
    ok = v.is_invalidate and ("action rate" in reason_lower or "rate" in reason_lower)
    results.append(("Case F: runaway action rate invalidates", ok))

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
