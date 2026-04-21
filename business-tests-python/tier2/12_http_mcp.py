"""
Scenario 12: HTTP middleware and MCP middleware end to end.

Experimental surface
--------------------
The HTTP and MCP middlewares demoed here are shipped but not yet
thoroughly validated through the consumer workflow harness that
covers the rest of the Python SDK. The primitives work (the cases
below run green), and the API surface is stable, but if you are
standing this up in production today, treat these middlewares as
'preview' rather than 'battle tested at scale'. The core gate,
signed permits, audit chains, SecureChannel, and drift detectors
(all other scenarios in this folder) are the battle tested surface.

The story
---------
Two of the most common ways people integrate Kavach are:

    HTTP side. A web API (FastAPI, Starlette, Flask, or any ASGI
    framework) wires HttpKavachMiddleware in front of its routes.
    Every request is evaluated by the gate before the handler runs.
    If the gate permits, the handler returns normally. If not, the
    middleware short circuits and returns a 403.

    MCP side. An MCP server hosts tools that agents can call.
    McpKavachMiddleware wraps those tool calls and decides whether
    an agent is allowed to invoke a particular tool. It also tracks
    per session state so a session can be invalidated from outside
    (say, by an admin), and the next call on that session is
    rejected before the gate even runs.

We will exercise both sides in this one scenario, with real
framework machinery and no mocks. The FastAPI part runs through
starlette's TestClient so we get real HTTP parsing without needing
a running server.

One extra thing we want to pin: HttpKavachMiddleware can take a
geo_resolver function. That function gets called to look up a geo
location for the caller's IP when the request does not carry an
explicit geo. The rule is: explicit beats resolver. If the caller
(or the app) already passed current_geo or origin_geo, the resolver
is not called. We count resolver invocations to prove this.

Eight cases:

    A. FastAPI POST with role=customer        , expect 200
    B. FastAPI POST with role=guest           , expect 403
    C. Resolver call counter after A and B    , expect 2
    D. Direct evaluate with current_geo set   , resolver count unchanged
    E. Direct evaluate with origin_geo set    , resolver count unchanged
    F. MCP check_tool_call on a whitelisted tool, no exception raised
    G. MCP check_tool_call on an unknown tool  , raises Refused
    H. invalidate_session, next call on that sid raises Invalidated,
       a fresh session still works.

Run this file directly:

    python tier2/12_http_mcp.py
"""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.testclient import TestClient

from kavach import (
    Gate,
    GeoLocation,
    HttpKavachMiddleware,
    InMemorySessionStore,
    Invalidated,
    McpKavachMiddleware,
    Refused,
)


# ---------------------------------------------------------------------
# HTTP side: a single permit rule for 'customers posting orders'.
# The HTTP middleware derives the action name from the method and path
# (POST /api/v1/orders becomes 'orders.create'), so the rule matches
# action = 'orders.create'.
# ---------------------------------------------------------------------
HTTP_POLICIES = {
    "policies": [
        {
            "name": "customer_places_order",
            "description": "Authenticated customers may POST /api/v1/orders",
            "effect": "permit",
            "priority": 10,
            "conditions": [
                {"identity_role": "customer"},
                {"action": "orders.create"},
            ],
        },
    ],
}


# ---------------------------------------------------------------------
# MCP side: two permit rules, one for list_files and one for read_file.
# 'danger_exec' is intentionally not in this list, so calls to it will
# fall through to default deny and the middleware will raise Refused.
# ---------------------------------------------------------------------
MCP_POLICIES = {
    "policies": [
        {
            "name": "agent_list_files",
            "description": "Agents may call list_files",
            "effect": "permit",
            "priority": 10,
            "conditions": [
                {"identity_role": "agent"},
                {"action": "list_files"},
            ],
        },
        {
            "name": "agent_read_file",
            "description": "Agents may call read_file",
            "effect": "permit",
            "priority": 10,
            "conditions": [
                {"identity_role": "agent"},
                {"action": "read_file"},
            ],
        },
    ],
}


# Two geo anchors used in the resolver fallback cases.
NYC = GeoLocation(country_code="US", city="New York", latitude=40.7128, longitude=-74.0060)
TOKYO = GeoLocation(country_code="JP", city="Tokyo", latitude=35.6762, longitude=139.6503)


class CountingResolver:
    # A tiny IP to geo resolver that records every call. The middleware
    # only calls this when neither origin_geo nor current_geo is set
    # on the evaluate call. We use the counter to prove that rule.
    def __init__(self):
        self.calls = []

    def __call__(self, *, method, path, ip, **_ignored):
        self.calls.append({"method": method, "path": path, "ip": ip})
        return {"current_geo": NYC}


def build_app(middleware: HttpKavachMiddleware) -> FastAPI:
    app = FastAPI()

    @app.post("/api/v1/orders")
    async def create_order(request: Request):
        verdict = middleware.evaluate_fastapi(request)
        if not verdict.is_permit:
            return JSONResponse(
                status_code=403,
                content={
                    "error": verdict.reason or "refused",
                    "code": verdict.code,
                    "evaluator": verdict.evaluator,
                },
            )
        return {"ok": True, "order_id": "ord_abc123"}

    return app


def main():
    print("=" * 70)
    print("Scenario 12: HTTP middleware and MCP middleware end to end")
    print("=" * 70)
    print()
    print("We are going to build two gates, wire each one through its")
    print("matching middleware (HTTP and MCP), and run real requests")
    print("through them. The HTTP half uses FastAPI and a test client.")
    print("The MCP half uses the in memory session store so we can show")
    print("cross session invalidation.")
    print()

    results = []

    # -----------------------------------------------------------------
    # Step 2. HTTP side setup.
    # -----------------------------------------------------------------
    print("Building the HTTP gate and middleware.")
    http_gate = Gate.from_dict(HTTP_POLICIES, geo_drift_max_km=500.0)
    resolver = CountingResolver()
    http_mw = HttpKavachMiddleware(http_gate, geo_resolver=resolver)
    print(f"  http_gate.evaluator_count: {http_gate.evaluator_count}")
    print(f"  resolver class:            {type(resolver).__name__}")
    print(f"  mw.excluded_paths:         {http_mw.excluded_paths}")
    print()

    print("Mounting the FastAPI app and opening a test client.")
    app = build_app(http_mw)
    client = TestClient(app)
    print()

    # -----------------------------------------------------------------
    # Case A: FastAPI permit.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case A: POST /api/v1/orders with role=customer.")
    print("-" * 70)
    print("The middleware reads X-Principal-Id and X-Roles from the")
    print("request headers, builds an action name from the method and")
    print("path, and evaluates through the gate. The rule permits")
    print("role=customer on orders.create. The handler returns 200.")
    print("No explicit geo is passed, so the resolver should be called.")
    print()

    r = client.post(
        "/api/v1/orders",
        headers={"X-Principal-Id": "alice", "X-Roles": "customer"},
        json={"amount_usd": 250.0},
    )

    print(f"HTTP status:       {r.status_code}")
    print(f"Response body:     {r.json()}")
    print(f"resolver.calls so far: {len(resolver.calls)}")
    print()

    results.append(("Case A: status 200", r.status_code == 200))
    results.append(("Case A: body ok is True", r.json().get("ok") is True))
    results.append(("Case A: resolver was called once", len(resolver.calls) == 1))

    # -----------------------------------------------------------------
    # Case B: FastAPI refuse.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case B: POST /api/v1/orders with role=guest.")
    print("-" * 70)
    print("Same endpoint, but the role does not match the rule. The")
    print("gate falls through to default deny. The middleware returns")
    print("a verdict, and our handler turns it into an HTTP 403.")
    print("The resolver still fires for this call. The counter goes up")
    print("to 2.")
    print()

    r = client.post(
        "/api/v1/orders",
        headers={"X-Principal-Id": "mallory", "X-Roles": "guest"},
        json={"amount_usd": 250.0},
    )

    print(f"HTTP status:       {r.status_code}")
    print(f"Response body:     {r.json()}")
    print(f"resolver.calls so far: {len(resolver.calls)}")
    print()

    results.append(("Case B: status 403", r.status_code == 403))
    results.append(("Case B: error evaluator is 'policy'", r.json().get("evaluator") == "policy"))
    results.append(("Case B: error code is NO_POLICY_MATCH", r.json().get("code") == "NO_POLICY_MATCH"))
    results.append(("Case B: resolver now called twice", len(resolver.calls) == 2))

    # -----------------------------------------------------------------
    # Case C: resolver counter summary.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case C: confirming the resolver counter is at 2.")
    print("-" * 70)
    print("We also peek at the first recorded resolver call to confirm")
    print("the middleware passed the right method and path into it.")
    print()

    first_call = resolver.calls[0] if resolver.calls else {}
    print(f"resolver.calls length: {len(resolver.calls)}")
    print(f"first call method:     {first_call.get('method')}")
    print(f"first call path:       {first_call.get('path')}")
    print(f"first call ip:         {first_call.get('ip')}")
    print()

    results.append(("Case C: resolver called exactly twice", len(resolver.calls) == 2))
    results.append((
        "Case C: resolver saw the /api/v1/orders path",
        first_call.get("path") == "/api/v1/orders",
    ))

    # -----------------------------------------------------------------
    # Case D: explicit current_geo skips the resolver.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case D: direct evaluate call with explicit current_geo=TOKYO.")
    print("-" * 70)
    print("We call middleware.evaluate directly (not through FastAPI)")
    print("with current_geo already set. The middleware only falls back")
    print("to the resolver when both origin_geo and current_geo are")
    print("missing, so it should NOT call the resolver here. We check")
    print("that the counter does not move.")
    print()

    before = len(resolver.calls)
    v = http_mw.evaluate(
        method="POST", path="/api/v1/orders",
        principal_id="explicit-geo-alice",
        principal_kind="user",
        roles=["customer"],
        ip="198.51.100.50",
        current_geo=TOKYO,
    )
    after = len(resolver.calls)
    print(f"Verdict kind: {v.kind}")
    print(f"Is permit:    {v.is_permit}")
    print(f"resolver.calls before: {before}")
    print(f"resolver.calls after:  {after}")
    print()

    results.append(("Case D: direct evaluate permits", v.is_permit))
    results.append(("Case D: resolver counter unchanged (explicit current_geo wins)", after == before))

    # -----------------------------------------------------------------
    # Case E: explicit origin_geo also skips the resolver.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case E: direct evaluate call with explicit origin_geo=NYC.")
    print("-" * 70)
    print("Same idea, but this time only origin_geo is set. The rule is")
    print("'either explicit is enough to skip the resolver'. Counter")
    print("should not move.")
    print()

    before = len(resolver.calls)
    v = http_mw.evaluate(
        method="POST", path="/api/v1/orders",
        principal_id="explicit-origin-bob",
        principal_kind="user",
        roles=["customer"],
        ip="198.51.100.51",
        origin_geo=NYC,
    )
    after = len(resolver.calls)
    print(f"Verdict kind: {v.kind}")
    print(f"Is permit:    {v.is_permit}")
    print(f"resolver.calls before: {before}")
    print(f"resolver.calls after:  {after}")
    print()

    results.append(("Case E: direct evaluate permits", v.is_permit))
    results.append(("Case E: resolver counter unchanged (explicit origin_geo wins)", after == before))

    # -----------------------------------------------------------------
    # Step 3. MCP side setup.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Now the MCP side.")
    print("-" * 70)
    print("Building the MCP gate, the in memory session store, and the")
    print("MCP middleware. The session store is what lets us invalidate")
    print("a session from outside; the middleware consults it at the")
    print("start of every tool call.")
    print()

    mcp_gate = Gate.from_dict(MCP_POLICIES)
    mcp_store = InMemorySessionStore()
    mcp_mw = McpKavachMiddleware(mcp_gate, session_store=mcp_store)
    print(f"  mcp_gate.evaluator_count: {mcp_gate.evaluator_count}")
    print(f"  store type:               {type(mcp_store).__name__}")
    print(f"  store.len (initial):      {mcp_store.len}")
    print()

    SESSION_A = "sess-aa11bbcc"
    SESSION_B = "sess-ffeedd99"

    # -----------------------------------------------------------------
    # Case F: MCP permit.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case F: check_tool_call('list_files') from an agent.")
    print("-" * 70)
    print("list_files is on the whitelist. The middleware evaluates")
    print("through the gate, gets a permit, and returns without")
    print("raising. The middleware also records this session in the")
    print("store so we can track it. We expect: no exception raised,")
    print("and the session is not invalidated.")
    print()

    raised = None
    try:
        mcp_mw.check_tool_call(
            tool_name="list_files",
            params={},
            caller_id="tool-runner-01",
            caller_kind="agent",
            roles=["agent"],
            session_id=SESSION_A,
        )
    except Exception as e:
        raised = e

    session_local = mcp_mw.get_session(SESSION_A)
    print(f"raised:                    {type(raised).__name__ if raised else None}")
    print(f"store.is_invalidated:      {mcp_store.is_invalidated(SESSION_A)}")
    print(f"local session invalidated: {session_local.invalidated if session_local else None}")
    print(f"local session.action_count: {session_local.action_count if session_local else None}")
    print()

    results.append(("Case F: check_tool_call did not raise", raised is None))
    results.append((
        "Case F: local session tracked and not invalidated",
        session_local is not None and not session_local.invalidated,
    ))

    # -----------------------------------------------------------------
    # Case G: MCP refuse.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case G: check_tool_call('danger_exec') from the same agent.")
    print("-" * 70)
    print("danger_exec is not on the whitelist. The gate returns a")
    print("refuse verdict. The middleware turns that into a kavach")
    print("Refused exception. We expect: kavach.Refused raised.")
    print()

    refused_ok = False
    try:
        mcp_mw.check_tool_call(
            tool_name="danger_exec",
            params={},
            caller_id="tool-runner-01",
            caller_kind="agent",
            roles=["agent"],
            session_id=SESSION_A,
        )
    except Refused as e:
        refused_ok = True
        print(f"raised kavach.Refused as expected: {e}")
    except Exception as e:
        print(f"raised wrong exception type: {type(e).__name__}: {e}")
    print()

    results.append(("Case G: danger_exec raised kavach.Refused", refused_ok))

    # -----------------------------------------------------------------
    # Case H: invalidation fan out.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case H: invalidate_session, then next call raises Invalidated.")
    print("-" * 70)
    print("An admin calls invalidate_session(SESSION_A). That writes to")
    print("the store and flips the local session's invalidated flag.")
    print("The next call on the same session, even for an otherwise")
    print("whitelisted tool, short circuits in the middleware before")
    print("the gate runs and raises kavach.Invalidated. A call on a")
    print("different session still works, because invalidation is")
    print("scoped to that one session id.")
    print()

    mcp_mw.invalidate_session(SESSION_A)
    session_local = mcp_mw.get_session(SESSION_A)
    print(f"store.is_invalidated(A):      {mcp_store.is_invalidated(SESSION_A)}")
    print(f"local session A invalidated:  {session_local.invalidated if session_local else None}")
    print()

    results.append((
        "Case H: store reports session A invalidated",
        mcp_store.is_invalidated(SESSION_A),
    ))
    results.append((
        "Case H: local session A view shows invalidated",
        session_local is not None and session_local.invalidated,
    ))

    invalidated_ok = False
    try:
        mcp_mw.check_tool_call(
            tool_name="list_files",
            params={},
            caller_id="tool-runner-01",
            caller_kind="agent",
            roles=["agent"],
            session_id=SESSION_A,
        )
    except Invalidated as e:
        invalidated_ok = True
        print(f"raised kavach.Invalidated as expected: {e}")
    except Exception as e:
        print(f"raised wrong exception type: {type(e).__name__}: {e}")
    print()

    results.append(("Case H: next call on session A raises Invalidated", invalidated_ok))

    # Fresh session B should still work.
    raised_b = None
    try:
        mcp_mw.check_tool_call(
            tool_name="list_files",
            params={},
            caller_id="tool-runner-01",
            caller_kind="agent",
            roles=["agent"],
            session_id=SESSION_B,
        )
    except Exception as e:
        raised_b = e
    print(f"Session B raised: {type(raised_b).__name__ if raised_b else None}")
    print(f"store.is_invalidated(B): {mcp_store.is_invalidated(SESSION_B)}")
    print()

    results.append(("Case H: fresh session B still permits", raised_b is None))
    results.append((
        "Case H: store reports session B not invalidated",
        not mcp_store.is_invalidated(SESSION_B),
    ))

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
