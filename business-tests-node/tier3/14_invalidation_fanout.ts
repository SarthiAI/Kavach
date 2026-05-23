/**
 * Scenario 14: invalidation broadcast fan out across replicas.
 *
 * The story
 * ---------
 * A gaming platform runs its account service behind three replicas of
 * the same gate, sitting behind a load balancer. Player sessions are
 * pinned to a replica by sticky routing. Everything works fine until a
 * fraud detector somewhere else in the system flags session S as
 * compromised and raises the "kill this session everywhere, now" flag.
 *
 * The problem: the fraud signal reached replica R1. But replicas R2
 * and R3 know nothing about it. If the attacker's next API call lands
 * on R2 because of a brief load balancer reshuffle, R2 still treats
 * the session as healthy, and the attacker walks back in.
 *
 * What most services do to close this gap:
 *
 *     a. Wait for a short-lived cache TTL to expire (minutes of
 *        attacker time).
 *     b. Put a flag in the database and have every replica hit the
 *        database on every single call (latency tax on every call,
 *        forever).
 *     c. Build a pub/sub side channel that every replica subscribes
 *        to (weeks of plumbing, your own ack/retry semantics).
 *
 * Kavach ships the third option as a first class primitive:
 * InvalidationBroadcaster. A replica publishes a scoped
 * "session S is dead" event; every subscribed replica wakes up
 * within a few milliseconds and drops the session from its local
 * store. There is no cache TTL to wait for, no per-call database
 * round trip, no infrastructure to rebuild per project.
 *
 * SDK pieces:
 *
 *     InMemoryInvalidationBroadcaster       for single-node / tests
 *     RedisInvalidationBroadcaster          for multi-node production
 *     spawnInvalidationListener             registers a callback
 *     InvalidationScopeView                 the event's target / reason
 *
 * In production the per replica "is this session invalid?" cache is
 * Kavach's InMemorySessionStore or RedisSessionStore, wired into the
 * HTTP or MCP middleware. In this scenario we use a small in-memory
 * set (ReplicaSessionState, defined below) instead, because the
 * scenario only needs to demonstrate the publish-once-fan-out-to-all
 * contract, not the full middleware path.
 *
 * Four cases:
 *
 *     A. Three replicas listening on the same broadcaster. One
 *        publish. All three receive the same scope, synchronously
 *        within a short poll window.
 *     B. Session store fan out. Every replica holds its own
 *        ReplicaSessionState. When the broadcaster fires, each
 *        replica's listener invalidates the session locally. After
 *        that, isInvalidated returns true on all three.
 *     C. A second unrelated session on the same replica is NOT
 *        invalidated by the scoped event. The broadcast targets a
 *        specific session id.
 *     D. Listener exception isolation. One replica's callback raises.
 *        The broadcaster and the other two replicas keep working. A
 *        buggy handler cannot take the fleet down.
 *
 * Run this file directly:
 *
 *   node dist/tier3/14_invalidation_fanout.js
 */

import {
  InMemoryInvalidationBroadcaster,
  spawnInvalidationListener,
  type InvalidationScopeView,
} from 'kavach-sdk';

// A tiny in-memory set per replica, standing in for the session
// store the middleware uses in production (InMemorySessionStore or
// RedisSessionStore). The listener callback runs on the Node event
// loop, so a plain Set is enough for the fan-out demonstration.
class ReplicaSessionState {
  private invalidated = new Set<string>();

  invalidate(sessionId: string): void {
    this.invalidated.add(sessionId);
  }

  isInvalidated(sessionId: string): boolean {
    return this.invalidated.has(sessionId);
  }
}

async function waitFor(
  predicate: () => boolean,
  timeoutMs = 2000,
  stepMs = 10,
): Promise<boolean> {
  // Small polling helper so we don't depend on the broadcaster's
  // internal timing. The listener is async; we give it up to a
  // couple of seconds to deliver, checking frequently.
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) {
      return true;
    }
    await new Promise(r => setTimeout(r, stepMs));
  }
  return false;
}

async function main(): Promise<number> {
  console.log('='.repeat(70));
  console.log('Scenario 14: invalidation broadcast fan out across replicas');
  console.log('='.repeat(70));
  console.log();
  console.log('We are going to build one broadcaster, three replicas, each');
  console.log("with their own session store. Every replica subscribes to the");
  console.log('same broadcaster. Then we fire one publish and confirm every');
  console.log('replica sees it and updates its local session state.');
  console.log();

  const results: [string, boolean][] = [];

  // -----------------------------------------------------------------
  // Set up the broadcaster and three replicas.
  // -----------------------------------------------------------------
  console.log('Building the broadcaster.');
  const broadcaster = new InMemoryInvalidationBroadcaster();
  console.log(`  subscriberCount (before spawn): ${broadcaster.subscriberCount}`);
  console.log();

  const replicaNames = ['R1', 'R2', 'R3'];
  const received: Record<string, InvalidationScopeView[]> = {
    R1: [],
    R2: [],
    R3: [],
  };
  const stores: Record<string, ReplicaSessionState> = {
    R1: new ReplicaSessionState(),
    R2: new ReplicaSessionState(),
    R3: new ReplicaSessionState(),
  };

  function makeHandler(name: string): (scope: InvalidationScopeView) => void {
    return (scope: InvalidationScopeView) => {
      received[name]!.push(scope);
      if (scope.targetKind === 'session') {
        stores[name]!.invalidate(scope.targetId);
      }
    };
  }

  const handles = replicaNames.map(name =>
    spawnInvalidationListener(broadcaster, makeHandler(name)),
  );

  // Give the event loop a tick to register subscribers.
  await waitFor(() => broadcaster.subscriberCount >= 3, 1000);

  console.log(`  replicas wired:                    [${replicaNames.join(', ')}]`);
  console.log(`  subscriberCount (after spawn):     ${broadcaster.subscriberCount}`);
  console.log();

  results.push([
    'Setup: three replicas are subscribed',
    broadcaster.subscriberCount === 3,
  ]);

  // -----------------------------------------------------------------
  // Pre-populate each replica with two sessions to watch.
  // -----------------------------------------------------------------
  // We will invalidate "compromised" later and check the other
  // session ("healthy") stays healthy. We do not need to "create"
  // sessions in the store; isInvalidated just reports whether
  // invalidate has been called on it, false otherwise.
  // Session ids must be UUIDs because the broadcaster validates
  // targetId shape. In production these come from the session
  // manager; here we hard-code a stable pair so the narrative is
  // still easy to follow.
  const compromised = 'aaaaaaaa-0000-4000-8000-000000000001';
  const healthy = 'bbbbbbbb-0000-4000-8000-000000000002';

  for (const name of replicaNames) {
    const store = stores[name]!;
    console.log(`  ${name}.isInvalidated('${compromised}') = ${store.isInvalidated(compromised)}`);
    console.log(`  ${name}.isInvalidated('${healthy}')     = ${store.isInvalidated(healthy)}`);
  }
  console.log();

  // -----------------------------------------------------------------
  // Case A: one publish, all three receive.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log(`Case A: fraud detector publishes 'session ${compromised} compromised'.`);
  console.log('-'.repeat(70));
  console.log('The publish is one call on one broadcaster. Every subscribed');
  console.log("replica's callback wakes up and receives the same scope with");
  console.log("targetKind='session', targetId='<compromised>'. We poll");
  console.log('briefly (up to 2 s) to give the async listeners time, but');
  console.log('in practice fan out completes in milliseconds.');
  console.log();

  broadcaster.publish(
    'session',
    compromised,
    'fraud detector flagged a stolen session cookie from a new IP',
    'fraud_external',
  );

  const allReceived = await waitFor(
    () => replicaNames.every(name => received[name]!.length >= 1),
    2000,
  );
  console.log(`  all three replicas received the scope: ${allReceived}`);
  for (const name of replicaNames) {
    const scopes = received[name]!;
    if (scopes.length > 0) {
      const s = scopes[0]!;
      console.log(`    ${name}: targetKind='${s.targetKind}' targetId='${s.targetId}'`);
      console.log(`         evaluator='${s.evaluator}' reason='${s.reason}'`);
    }
  }
  console.log();

  results.push([
    'Case A: all three replicas received the broadcast',
    allReceived,
  ]);

  // -----------------------------------------------------------------
  // Case B: each replica's session store now marks the session as
  // invalidated.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log("Case B: each replica's session store reflects the invalidation.");
  console.log('-'.repeat(70));
  console.log('The listener callback we registered calls invalidate() on the');
  console.log('per-replica session store when it sees a session scope. So a');
  console.log('later call on any replica (isInvalidated(sid)) returns true');
  console.log('without having to ask the source replica or the database.');
  console.log();

  const allInvalid = replicaNames.every(name =>
    stores[name]!.isInvalidated(compromised),
  );
  for (const name of replicaNames) {
    console.log(`  ${name}.isInvalidated('${compromised}'): ${stores[name]!.isInvalidated(compromised)}`);
  }
  console.log();

  results.push([
    "Case B: every replica's store marks session as invalid",
    allInvalid,
  ]);

  // -----------------------------------------------------------------
  // Case C: scope is precise. A different session is not touched.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log(`Case C: an unrelated session ('${healthy}') is not invalidated.`);
  console.log('-'.repeat(70));
  console.log('The scope named the compromised session id specifically. A');
  console.log('different session on the same replica should be unaffected.');
  console.log('This is what lets invalidation be aggressive without being a');
  console.log('blunt instrument: one bad session dies, the rest of the user');
  console.log('population is fine.');
  console.log();

  const noneHealthyInvalid = replicaNames.every(
    name => !stores[name]!.isInvalidated(healthy),
  );
  for (const name of replicaNames) {
    console.log(`  ${name}.isInvalidated('${healthy}'): ${stores[name]!.isInvalidated(healthy)}`);
  }
  console.log();

  results.push([
    'Case C: unrelated session stays valid on every replica',
    noneHealthyInvalid,
  ]);

  // -----------------------------------------------------------------
  // Case D: listener exception isolation.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log("Case D: a buggy replica's callback raises on every event.");
  console.log('-'.repeat(70));
  console.log('We spawn a fourth listener whose callback always raises. We');
  console.log('then fire a second publish for a different session. The');
  console.log('broadcaster and the original three replicas keep working:');
  console.log('they receive the new event and invalidate the new session.');
  console.log("The buggy handler's exception is caught and logged by the");
  console.log('listener scaffolding, it does not propagate.');
  console.log();

  const brokenHandler = (_scope: InvalidationScopeView): void => {
    throw new Error('simulated bad deploy on replica R4');
  };

  const brokenHandle = spawnInvalidationListener(broadcaster, brokenHandler);
  await waitFor(() => broadcaster.subscriberCount >= 4, 1000);
  console.log(`  subscriberCount after buggy replica: ${broadcaster.subscriberCount}`);

  const secondSid = 'cccccccc-0000-4000-8000-000000000003';
  const baselineCounts: Record<string, number> = {};
  for (const name of replicaNames) {
    baselineCounts[name] = received[name]!.length;
  }

  broadcaster.publish(
    'session',
    secondSid,
    'different incident on a different session',
    'fraud_external',
  );

  const allGotSecond = await waitFor(
    () =>
      replicaNames.every(
        name => received[name]!.length > (baselineCounts[name] ?? 0),
      ),
    2000,
  );
  console.log(`  the three good replicas received the second event: ${allGotSecond}`);
  const allSecondInvalid = replicaNames.every(name =>
    stores[name]!.isInvalidated(secondSid),
  );
  for (const name of replicaNames) {
    console.log(`  ${name}.isInvalidated('${secondSid}'): ${stores[name]!.isInvalidated(secondSid)}`);
  }
  console.log();

  results.push([
    'Case D: buggy listener did not break the fan out',
    allGotSecond && allSecondInvalid,
  ]);

  // -----------------------------------------------------------------
  // Tear down. Abort every listener so the scenario exits cleanly.
  // -----------------------------------------------------------------
  for (const h of handles) {
    h.abort();
  }
  brokenHandle.abort();
  console.log('Listeners aborted, scenario complete.');
  console.log();

  // -----------------------------------------------------------------
  // Summary
  // -----------------------------------------------------------------
  console.log('='.repeat(70));
  console.log('Summary');
  console.log('='.repeat(70));
  const passed = results.filter(([, ok]) => ok).length;
  for (const [label, ok] of results) {
    const mark = ok ? 'PASS' : 'FAIL';
    console.log(`  [${mark}] ${label}`);
  }
  console.log();
  console.log(`${passed}/${results.length} checks passed.`);
  console.log();

  return passed === results.length ? 0 : 1;
}

main()
  .then(rc => process.exit(rc))
  .catch(e => {
    console.error(e);
    process.exit(1);
  });
