"""
Scenario 03: password reset with geo drift detection.

The story
---------
A consumer product mails password reset links. The flow has two
steps:

    auth.reset.start    : the user clicks "forgot my password". The
                          site emails them a link and records the
                          session origin (the IP the click came from
                          and the geo for that IP).

    auth.reset.confirm  : the user opens the link from their mailbox
                          and submits a new password.

The threat we are defending against is link theft. An attacker
convinces the user to forward the reset email, or steals it off a
mail server, and then opens the link from a completely different
place in the world. If we only check "is this a valid reset token"
the attacker wins. We also want to check "is this reset being
completed from the same region the request started in".

Kavach's built in drift evaluator can do this for us. We run it in
tolerant mode with a 500 km threshold:

    moves shorter than 500 km  , treat as a warning (still permit)
    moves longer than 500 km   , treat as a violation (invalidate)
    unknown distance           , treat as a violation (invalidate)

We also show the invalidation broadcaster. When one gate decides to
invalidate a session, you usually want every other node in the
fleet to know, so they all drop the session at once. We plug an in
memory broadcaster and a listener into the gate, and check that the
listener receives the invalidation event.

Four cases:

    A. Same IP and geo                      , expect PERMIT
    B. 15 km move (New York to Newark)      , expect PERMIT (warning)
    C. 15,000 km move (New York to Singapore), expect INVALIDATE
    D. Any move with no coordinates on the other side, expect INVALIDATE

Run this file directly:

    python tier1/03_reset_geo_drift.py
"""

import time
import uuid

from kavach import (
    ActionContext,
    Gate,
    GeoLocation,
    InMemoryInvalidationBroadcaster,
    spawn_invalidation_listener,
)


# ---------------------------------------------------------------------
# Step 1. Write the rule for confirming a password reset.
# ---------------------------------------------------------------------
# The policy itself is very simple: a customer may confirm a reset.
# The interesting part is the drift detector we attach when building
# the gate below. The policy permits, the drift detector can then
# invalidate on top of the permit.

POLICIES = {
    "policies": [
        {
            "name": "password_reset_confirm",
            "description": "Allow customers to confirm a password reset",
            "effect": "permit",
            "priority": 10,
            "conditions": [
                {"identity_role": "customer"},
                {"action": "auth.reset.confirm"},
            ],
        },
    ],
}


# ---------------------------------------------------------------------
# Geo fixtures used across the cases. GeoLocation takes a country
# code (always required), and optionally a region, city, latitude,
# and longitude. Latitude and longitude are what allow Haversine to
# compute a distance between two points.
# ---------------------------------------------------------------------
GEO_NEW_YORK = GeoLocation(
    country_code="US", region="NY", city="New York",
    latitude=40.7128, longitude=-74.0060,
)
GEO_NEWARK = GeoLocation(
    country_code="US", region="NJ", city="Newark",
    latitude=40.7357, longitude=-74.1724,
)
GEO_SINGAPORE = GeoLocation(
    country_code="SG", region="Central", city="Singapore",
    latitude=1.3521, longitude=103.8198,
)
GEO_SINGAPORE_NO_COORDS = GeoLocation(country_code="SG")


def reset_ctx(session_id, ip, origin_ip, current_geo, origin_geo):
    return ActionContext(
        principal_id="customer-42",
        principal_kind="user",
        action_name="auth.reset.confirm",
        roles=["customer"],
        ip=ip,
        origin_ip=origin_ip,
        current_geo=current_geo,
        origin_geo=origin_geo,
        session_id=session_id,
    )


def main():
    print("=" * 70)
    print("Scenario 03: password reset with geo drift detection")
    print("=" * 70)
    print()
    print("We are going to build a gate with one permit rule plus a drift")
    print("detector in tolerant mode, with a 500 km threshold. We wire an")
    print("in memory broadcaster and a listener so we can see the")
    print("invalidation events the gate emits. Then we run four reset")
    print("confirm calls with different locations and watch the verdicts.")
    print()

    # -----------------------------------------------------------------
    # Step 2. Set up the broadcaster and listener.
    # -----------------------------------------------------------------
    # The broadcaster lets the gate publish invalidation events. The
    # listener is a background task that calls our callback for each
    # event. In a multi node deployment you would use the Redis
    # backed broadcaster instead; the interface is identical.
    print("Setting up the invalidation broadcaster and a listener.")
    print("The listener calls a callback for each event. We point the")
    print("callback at a plain Python list so we can inspect it later.")
    broadcaster = InMemoryInvalidationBroadcaster()
    received = []
    listener = spawn_invalidation_listener(broadcaster, received.append)
    print(f"Broadcaster subscriber count: {broadcaster.subscriber_count}")
    print()

    # -----------------------------------------------------------------
    # Step 3. Build the gate.
    # -----------------------------------------------------------------
    print("Building the gate with the policy, the 500 km geo threshold,")
    print("and the broadcaster.")
    gate = Gate.from_dict(
        POLICIES,
        geo_drift_max_km=500.0,
        broadcaster=broadcaster,
    )
    print(f"Gate built. It has {gate.evaluator_count} evaluators chained together.")
    print("The chain runs in order: identity, policy, drift, invariants.")
    print("For each call, identity and policy should permit. Drift then")
    print("decides whether to let the permit stand or to invalidate.")
    print()

    print("Some distances for context:")
    print(f"  New York to Newark     : {GEO_NEW_YORK.distance_km(GEO_NEWARK):.1f} km")
    print(f"  New York to Singapore  : {GEO_NEW_YORK.distance_km(GEO_SINGAPORE):.0f} km")
    print()

    session_id = str(uuid.uuid4())
    print(f"All four cases share the same session id: {session_id}")
    print()

    results = []

    # -----------------------------------------------------------------
    # Case A: same IP and geo.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case A: the user opens the reset link on the same device.")
    print("-" * 70)
    print("Origin IP matches current IP, origin geo matches current geo.")
    print("Nothing has changed between 'reset start' and 'reset confirm'.")
    print("The drift evaluator sees a stable session. Policy permits.")
    print("We expect: PERMIT, with a valid permit token.")
    print()

    v = gate.evaluate(reset_ctx(
        session_id,
        ip="203.0.113.10",
        origin_ip="203.0.113.10",
        current_geo=GEO_NEW_YORK,
        origin_geo=GEO_NEW_YORK,
    ))

    print(f"Verdict kind: {v.kind}")
    print(f"Is permit:    {v.is_permit}")
    print(f"Token id:     {v.token_id}")
    print()

    ok = v.is_permit and v.permit_token is not None
    results.append(("Case A: same IP and geo permits", ok))

    # -----------------------------------------------------------------
    # Case B: small move within the threshold.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case B: the user crosses from Manhattan to Newark on a new Wi-Fi.")
    print("-" * 70)
    print("The IP changed. The geo coordinates moved about 15 km, well")
    print("under the 500 km threshold. Tolerant mode turns this from a")
    print("violation into a warning. A single warning does not push the")
    print("drift detector into invalidating on its own, so the policy's")
    print("permit stands. We expect: PERMIT.")
    print()

    v = gate.evaluate(reset_ctx(
        session_id,
        ip="198.51.100.55",
        origin_ip="203.0.113.10",
        current_geo=GEO_NEWARK,
        origin_geo=GEO_NEW_YORK,
    ))

    # Snapshot the listener to confirm tolerant mode did not publish
    # an invalidation for this short hop. If drift had been in strict
    # mode, the IP change would have invalidated and the broadcaster
    # would have seen one more event.
    time.sleep(0.05)
    received_after_b = len(received)

    print(f"Verdict kind:   {v.kind}")
    print(f"Is permit:      {v.is_permit}")
    print(f"Token id:       {v.token_id}")
    print(f"Invalidations broadcast so far: {received_after_b}")
    print()

    ok = (
        v.is_permit
        and v.permit_token is not None
        and v.evaluator != "drift"
        and received_after_b == 0
    )
    results.append(("Case B: small 15 km move permits, no invalidation", ok))

    # -----------------------------------------------------------------
    # Case C: large move beyond the threshold.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case C: the reset link is opened from Singapore.")
    print("-" * 70)
    print("Distance from New York to Singapore is around 15,000 km, far")
    print("beyond the 500 km threshold. The drift evaluator reports a")
    print("violation. That beats the policy's permit, and the gate emits")
    print("an invalidate verdict. The broadcaster should also fan this")
    print("out to the listener. We expect: INVALIDATE, evaluator 'drift',")
    print("a reason string that mentions kilometres, no permit token,")
    print("and one invalidation scope delivered to the listener.")
    print()

    v = gate.evaluate(reset_ctx(
        session_id,
        ip="192.0.2.77",
        origin_ip="203.0.113.10",
        current_geo=GEO_SINGAPORE,
        origin_geo=GEO_NEW_YORK,
    ))

    print(f"Verdict kind:   {v.kind}")
    print(f"Is invalidate:  {v.is_invalidate}")
    print(f"Evaluator:      {v.evaluator}")
    print(f"Reason:         {v.reason}")
    print(f"Permit token:   {v.permit_token}")
    print()

    # Let the background listener drain its channel before we read it.
    time.sleep(0.05)
    print(f"Listener received {len(received)} invalidation scope(s) so far.")
    if received:
        scope = received[-1]
        print(f"  scope.target_kind: {scope.target_kind}")
        print(f"  scope.target_id:   {scope.target_id}")
        print(f"  scope.evaluator:   {scope.evaluator}")
        print(f"  scope.reason:      {scope.reason}")
    print()

    ok = (
        v.is_invalidate
        and v.evaluator == "drift"
        and ">" in (v.reason or "")
        and "km" in (v.reason or "")
        and v.permit_token is None
        and len(received) == 1
        and received[0].target_kind == "session"
        and received[0].evaluator == "drift"
    )
    results.append(("Case C: cross ocean move invalidates and broadcasts", ok))

    # -----------------------------------------------------------------
    # Case D: unknown distance.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case D: IP changed, current geo has only a country code.")
    print("-" * 70)
    print("The geo lookup on the current side only resolved a country")
    print("code, no latitude or longitude. We cannot compute a distance,")
    print("so tolerant mode cannot decide 'this is under 500 km'. It")
    print("treats the unknown as a violation. This is the fail closed")
    print("direction: if you cannot verify the move, do not allow it.")
    print("We expect: INVALIDATE, with a reason that mentions the move")
    print("is unverifiable, and a second invalidation scope delivered to")
    print("the listener.")
    print()

    v = gate.evaluate(reset_ctx(
        session_id,
        ip="192.0.2.77",
        origin_ip="203.0.113.10",
        current_geo=GEO_SINGAPORE_NO_COORDS,
        origin_geo=GEO_NEW_YORK,
    ))

    print(f"Verdict kind:  {v.kind}")
    print(f"Is invalidate: {v.is_invalidate}")
    print(f"Evaluator:     {v.evaluator}")
    print(f"Reason:        {v.reason}")
    print()

    time.sleep(0.05)
    print(f"Listener now has {len(received)} invalidation scope(s) in total.")
    print()

    ok = (
        v.is_invalidate
        and v.evaluator == "drift"
        and "unverifiable" in (v.reason or "")
        and len(received) == 2
    )
    results.append(("Case D: unverifiable distance invalidates and broadcasts", ok))

    # -----------------------------------------------------------------
    # Clean up the background listener so the process can exit cleanly.
    # -----------------------------------------------------------------
    listener.abort()

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
