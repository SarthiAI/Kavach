"""
Scenario 14: invalidation broadcast fan out across replicas.

The story
---------
A gaming platform runs its account service behind three replicas of
the same gate, sitting behind a load balancer. Player sessions are
pinned to a replica by sticky routing. Everything works fine until a
fraud detector somewhere else in the system flags session S as
compromised and raises the "kill this session everywhere, now" flag.

The problem: the fraud signal reached replica R1. But replicas R2
and R3 know nothing about it. If the attacker's next API call lands
on R2 because of a brief load balancer reshuffle, R2 still treats
the session as healthy, and the attacker walks back in.

What most services do to close this gap:

    a. Wait for a short-lived cache TTL to expire (minutes of
       attacker time).
    b. Put a flag in the database and have every replica hit the
       database on every single call (latency tax on every call,
       forever).
    c. Build a pub/sub side channel that every replica subscribes
       to (weeks of plumbing, your own ack/retry semantics).

Kavach ships the third option as a first class primitive:
InvalidationBroadcaster. A replica publishes a scoped
"session S is dead" event; every subscribed replica wakes up
within a few milliseconds and drops the session from its local
store. There is no cache TTL to wait for, no per-call database
round trip, no infrastructure to rebuild per project.

SDK pieces:

    InMemoryInvalidationBroadcaster       for single-node / tests
    RedisInvalidationBroadcaster          for multi-node production
    spawn_invalidation_listener           registers a callback
    InvalidationScope                     the event's target / reason

In production the per replica "is this session invalid?" cache is
Kavach's InMemorySessionStore or RedisSessionStore, wired into the
HTTP or MCP middleware. In this scenario we use a small thread safe
set (ReplicaSessionState, defined below) instead, because those
stores rely on tokio internals that cannot nest inside the async
listener callback the way a toy scenario would want them to. The
contract we are demonstrating (publish once, every replica's local
state converges) is the same.

Four cases:

    A. Three replicas listening on the same broadcaster. One
       publish. All three receive the same scope, synchronously
       within a short poll window.
    B. Session store fan out. Every replica holds its own
       ReplicaSessionState. When the broadcaster fires, each
       replica's listener invalidates the session locally. After
       that, is_invalidated returns True on all three.
    C. A second unrelated session on the same replica is NOT
       invalidated by the scoped event. The broadcast targets a
       specific session id.
    D. Listener exception isolation. One replica's callback raises.
       The broadcaster and the other two replicas keep working. A
       buggy handler cannot take the fleet down.

Run this file directly:

    python tier3/14_invalidation_fanout.py
"""

import threading
import time
import uuid

from kavach import (
    InMemoryInvalidationBroadcaster,
    InvalidationScope,
    spawn_invalidation_listener,
)


# A tiny thread safe set per replica, standing in for the session
# store the middleware uses in production (InMemorySessionStore or
# RedisSessionStore). The listener callback runs on a tokio worker
# thread and the SDK session stores nest tokio calls internally, so
# we keep the demo state in a plain Python set plus a lock. The fan
# out contract we are demonstrating is the same either way.
class ReplicaSessionState:
    def __init__(self):
        self._lock = threading.Lock()
        self._invalidated = set()

    def invalidate(self, session_id: str):
        with self._lock:
            self._invalidated.add(session_id)

    def is_invalidated(self, session_id: str) -> bool:
        with self._lock:
            return session_id in self._invalidated


def wait_for(predicate, timeout=2.0, step=0.01):
    # Small polling helper so we don't depend on the broadcaster's
    # internal timing. The listener is async; we give it up to a
    # couple of seconds to deliver, checking frequently.
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(step)
    return False


def main():
    print("=" * 70)
    print("Scenario 14: invalidation broadcast fan out across replicas")
    print("=" * 70)
    print()
    print("We are going to build one broadcaster, three replicas, each")
    print("with their own session store. Every replica subscribes to the")
    print("same broadcaster. Then we fire one publish and confirm every")
    print("replica sees it and updates its local session state.")
    print()

    results = []

    # -----------------------------------------------------------------
    # Set up the broadcaster and three replicas.
    # -----------------------------------------------------------------
    print("Building the broadcaster.")
    broadcaster = InMemoryInvalidationBroadcaster()
    print(f"  subscriber_count (before spawn): {broadcaster.subscriber_count}")
    print()

    replicas = []
    handles = []
    received = {"R1": [], "R2": [], "R3": []}
    stores = {"R1": ReplicaSessionState(), "R2": ReplicaSessionState(), "R3": ReplicaSessionState()}

    def make_handler(name):
        def handler(scope: InvalidationScope):
            received[name].append(scope)
            if scope.target_kind == "session":
                stores[name].invalidate(scope.target_id)
        return handler

    for name in ["R1", "R2", "R3"]:
        handle = spawn_invalidation_listener(broadcaster, make_handler(name))
        handles.append(handle)
        replicas.append(name)

    # Give the event loop a tick to register subscribers.
    wait_for(lambda: broadcaster.subscriber_count >= 3, timeout=1.0)

    print(f"  replicas wired:                    {replicas}")
    print(f"  subscriber_count (after spawn):    {broadcaster.subscriber_count}")
    print()

    results.append(("Setup: three replicas are subscribed",
                    broadcaster.subscriber_count == 3))

    # -----------------------------------------------------------------
    # Pre-populate each replica with two sessions to watch.
    # -----------------------------------------------------------------
    # We will invalidate "sess-compromised" later and check the other
    # session ("sess-healthy") stays healthy. We do not need to
    # "create" sessions in the store; is_invalidated just reports
    # whether invalidate has been called on it, false otherwise.
    # Session ids must be UUIDs because the broadcaster validates
    # target_id shape. In production these come from the session
    # manager; here we generate a stable pair so the narrative is
    # still easy to follow.
    compromised = str(uuid.UUID("aaaaaaaa-0000-4000-8000-000000000001"))
    healthy = str(uuid.UUID("bbbbbbbb-0000-4000-8000-000000000002"))

    for name in replicas:
        store = stores[name]
        print(f"  {name}.is_invalidated('{compromised}') = {store.is_invalidated(compromised)}")
        print(f"  {name}.is_invalidated('{healthy}')     = {store.is_invalidated(healthy)}")
    print()

    # -----------------------------------------------------------------
    # Case A: one publish, all three receive.
    # -----------------------------------------------------------------
    print("-" * 70)
    print(f"Case A: fraud detector publishes 'session {compromised} compromised'.")
    print("-" * 70)
    print("The publish is one call on one broadcaster. Every subscribed")
    print("replica's callback wakes up and receives the same scope with")
    print("target_kind='session', target_id='<compromised>'. We poll")
    print("briefly (up to 2 s) to give the async listeners time, but")
    print("in practice fan out completes in milliseconds.")
    print()

    broadcaster.publish(
        "session",
        compromised,
        "fraud detector flagged a stolen session cookie from a new IP",
        "fraud_external",
    )

    all_received = wait_for(lambda: all(len(received[name]) >= 1 for name in replicas), timeout=2.0)
    print(f"  all three replicas received the scope: {all_received}")
    for name in replicas:
        scopes = received[name]
        if scopes:
            s = scopes[0]
            print(f"    {name}: target_kind={s.target_kind!r} target_id={s.target_id!r}")
            print(f"         evaluator={s.evaluator!r} reason={s.reason!r}")
    print()

    results.append(("Case A: all three replicas received the broadcast",
                    all_received))

    # -----------------------------------------------------------------
    # Case B: each replica's session store now marks the session as
    # invalidated.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case B: each replica's session store reflects the invalidation.")
    print("-" * 70)
    print("The listener callback we registered calls invalidate() on the")
    print("per-replica session store when it sees a session scope. So a")
    print("later call on any replica (is_invalidated(sid)) returns True")
    print("without having to ask the source replica or the database.")
    print()

    all_invalid = all(stores[name].is_invalidated(compromised) for name in replicas)
    for name in replicas:
        print(f"  {name}.is_invalidated('{compromised}'): {stores[name].is_invalidated(compromised)}")
    print()

    results.append(("Case B: every replica's store marks session as invalid",
                    all_invalid))

    # -----------------------------------------------------------------
    # Case C: scope is precise. A different session is not touched.
    # -----------------------------------------------------------------
    print("-" * 70)
    print(f"Case C: an unrelated session ('{healthy}') is not invalidated.")
    print("-" * 70)
    print("The scope named the compromised session id specifically. A")
    print("different session on the same replica should be unaffected.")
    print("This is what lets invalidation be aggressive without being a")
    print("blunt instrument: one bad session dies, the rest of the user")
    print("population is fine.")
    print()

    none_healthy_invalid = all(not stores[name].is_invalidated(healthy) for name in replicas)
    for name in replicas:
        print(f"  {name}.is_invalidated('{healthy}'): {stores[name].is_invalidated(healthy)}")
    print()

    results.append(("Case C: unrelated session stays valid on every replica",
                    none_healthy_invalid))

    # -----------------------------------------------------------------
    # Case D: listener exception isolation.
    # -----------------------------------------------------------------
    print("-" * 70)
    print("Case D: a buggy replica's callback raises on every event.")
    print("-" * 70)
    print("We spawn a fourth listener whose callback always raises. We")
    print("then fire a second publish for a different session. The")
    print("broadcaster and the original three replicas keep working:")
    print("they receive the new event and invalidate the new session.")
    print("The buggy handler's exception is caught and logged by the")
    print("listener scaffolding, it does not propagate.")
    print()

    def broken_handler(scope):
        raise RuntimeError("simulated bad deploy on replica R4")

    broken_handle = spawn_invalidation_listener(broadcaster, broken_handler)
    wait_for(lambda: broadcaster.subscriber_count >= 4, timeout=1.0)
    print(f"  subscriber_count after buggy replica: {broadcaster.subscriber_count}")

    second_sid = str(uuid.UUID("cccccccc-0000-4000-8000-000000000003"))
    baseline_counts = {name: len(received[name]) for name in replicas}

    broadcaster.publish(
        "session",
        second_sid,
        "different incident on a different session",
        "fraud_external",
    )

    all_got_second = wait_for(
        lambda: all(len(received[name]) > baseline_counts[name] for name in replicas),
        timeout=2.0,
    )
    print(f"  the three good replicas received the second event: {all_got_second}")
    all_second_invalid = all(stores[name].is_invalidated(second_sid) for name in replicas)
    for name in replicas:
        print(f"  {name}.is_invalidated('{second_sid}'): {stores[name].is_invalidated(second_sid)}")
    print()

    results.append(("Case D: buggy listener did not break the fan out",
                    all_got_second and all_second_invalid))

    # -----------------------------------------------------------------
    # Tear down. Abort every listener so the scenario exits cleanly.
    # -----------------------------------------------------------------
    for h in handles:
        h.abort()
    broken_handle.abort()
    print("Listeners aborted, scenario complete.")
    print()

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
