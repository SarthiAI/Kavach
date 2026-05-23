/**
 * Scenario 03: password reset with geo drift detection.
 *
 * The story
 * ---------
 * A consumer product mails password reset links. The flow has two
 * steps:
 *
 *     auth.reset.start    : the user clicks "forgot my password". The
 *                           site emails them a link and records the
 *                           session origin (the IP the click came from
 *                           and the geo for that IP).
 *
 *     auth.reset.confirm  : the user opens the link from their mailbox
 *                           and submits a new password.
 *
 * The threat we are defending against is link theft. An attacker
 * convinces the user to forward the reset email, or steals it off a
 * mail server, and then opens the link from a completely different
 * place in the world. If we only check "is this a valid reset token"
 * the attacker wins. We also want to check "is this reset being
 * completed from the same region the request started in".
 *
 * Kavach's built in drift evaluator can do this for us. We run it in
 * tolerant mode with a 500 km threshold:
 *
 *     moves shorter than 500 km  , treat as a warning (still permit)
 *     moves longer than 500 km   , treat as a violation (invalidate)
 *     unknown distance           , treat as a violation (invalidate)
 *
 * We also show the invalidation broadcaster. When one gate decides to
 * invalidate a session, you usually want every other node in the
 * fleet to know, so they all drop the session at once. We plug an in
 * memory broadcaster and a listener into the gate, and check that the
 * listener receives the invalidation event.
 *
 * Four cases:
 *
 *     A. Same IP and geo                      , expect PERMIT
 *     B. 15 km move (New York to Newark)      , expect PERMIT (warning)
 *     C. 15,000 km move (New York to Singapore), expect INVALIDATE
 *     D. Any move with no coordinates on the other side, expect INVALIDATE
 *
 * Run this file directly:
 *
 *   node dist/tier1/03_reset_geo_drift.js
 */

import { randomUUID } from 'node:crypto';

import {
  Gate,
  InMemoryInvalidationBroadcaster,
  spawnInvalidationListener,
  type EvaluateOptions,
  type GeoLocationInput,
  type InvalidationScopeView,
} from 'kavach-sdk';

// ---------------------------------------------------------------------
// Step 1. Write the rule for confirming a password reset.
// ---------------------------------------------------------------------
// The policy itself is very simple: a customer may confirm a reset.
// The interesting part is the drift detector we attach when building
// the gate below. The policy permits, the drift detector can then
// invalidate on top of the permit.

const POLICIES = {
  policies: [
    {
      name: 'password_reset_confirm',
      description: 'Allow customers to confirm a password reset',
      effect: 'permit',
      priority: 10,
      conditions: [
        { identity_role: 'customer' },
        { action: 'auth.reset.confirm' },
      ],
    },
  ],
};

// ---------------------------------------------------------------------
// Geo fixtures used across the cases. GeoLocationInput takes a country
// code (always required), and optionally a region, city, latitude,
// and longitude. Latitude and longitude are what allow Haversine to
// compute a distance between two points.
// ---------------------------------------------------------------------
const GEO_NEW_YORK: GeoLocationInput = {
  countryCode: 'US',
  region: 'NY',
  city: 'New York',
  latitude: 40.7128,
  longitude: -74.006,
};
const GEO_NEWARK: GeoLocationInput = {
  countryCode: 'US',
  region: 'NJ',
  city: 'Newark',
  latitude: 40.7357,
  longitude: -74.1724,
};
const GEO_SINGAPORE: GeoLocationInput = {
  countryCode: 'SG',
  region: 'Central',
  city: 'Singapore',
  latitude: 1.3521,
  longitude: 103.8198,
};
const GEO_SINGAPORE_NO_COORDS: GeoLocationInput = { countryCode: 'SG' };

function resetCtx(
  sessionId: string,
  ip: string,
  originIp: string,
  currentGeo: GeoLocationInput,
  originGeo: GeoLocationInput,
): EvaluateOptions {
  return {
    principalId: 'customer-42',
    principalKind: 'user',
    actionName: 'auth.reset.confirm',
    roles: ['customer'],
    ip: ip,
    originIp: originIp,
    currentGeo: currentGeo,
    originGeo: originGeo,
    sessionId: sessionId,
  };
}

async function main(): Promise<number> {
  console.log('='.repeat(70));
  console.log('Scenario 03: password reset with geo drift detection');
  console.log('='.repeat(70));
  console.log();
  console.log('We are going to build a gate with one permit rule plus a drift');
  console.log('detector in tolerant mode, with a 500 km threshold. We wire an');
  console.log('in memory broadcaster and a listener so we can see the');
  console.log('invalidation events the gate emits. Then we run four reset');
  console.log('confirm calls with different locations and watch the verdicts.');
  console.log();

  // -----------------------------------------------------------------
  // Step 2. Set up the broadcaster and listener.
  // -----------------------------------------------------------------
  // The broadcaster lets the gate publish invalidation events. The
  // listener is a background task that calls our callback for each
  // event. In a multi node deployment you would use the Redis
  // backed broadcaster instead; the interface is identical.
  console.log('Setting up the invalidation broadcaster and a listener.');
  console.log('The listener calls a callback for each event. We point the');
  console.log('callback at a plain array so we can inspect it later.');
  const broadcaster = new InMemoryInvalidationBroadcaster();
  const received: InvalidationScopeView[] = [];
  const listener = spawnInvalidationListener(broadcaster, (scope) => {
    received.push(scope);
  });
  console.log(`Broadcaster subscriber count: ${broadcaster.subscriberCount}`);
  console.log();

  // -----------------------------------------------------------------
  // Step 3. Build the gate.
  // -----------------------------------------------------------------
  console.log('Building the gate with the policy, the 500 km geo threshold,');
  console.log('and the broadcaster.');
  const gate = Gate.fromObject(POLICIES, {
    geoDriftMaxKm: 500.0,
    broadcaster: broadcaster,
  });
  console.log(
    `Gate built. It has ${gate.evaluatorCount} evaluators chained together.`,
  );
  console.log('The chain runs in order: identity, policy, drift, invariants.');
  console.log('For each call, identity and policy should permit. Drift then');
  console.log('decides whether to let the permit stand or to invalidate.');
  console.log();

  console.log('Some distances for context:');
  console.log('  New York to Newark     : about 15 km');
  console.log('  New York to Singapore  : about 15,344 km');
  console.log();

  const sessionId = randomUUID();
  console.log(`All four cases share the same session id: ${sessionId}`);
  console.log();

  const results: [string, boolean][] = [];

  // -----------------------------------------------------------------
  // Case A: same IP and geo.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case A: the user opens the reset link on the same device.');
  console.log('-'.repeat(70));
  console.log('Origin IP matches current IP, origin geo matches current geo.');
  console.log("Nothing has changed between 'reset start' and 'reset confirm'.");
  console.log('The drift evaluator sees a stable session. Policy permits.');
  console.log('We expect: PERMIT, with a valid permit token.');
  console.log();

  let v = gate.evaluate(
    resetCtx(sessionId, '203.0.113.10', '203.0.113.10', GEO_NEW_YORK, GEO_NEW_YORK),
  );

  console.log(`Verdict kind: ${v.kind}`);
  console.log(`Is permit:    ${v.isPermit}`);
  console.log(`Token id:     ${v.tokenId}`);
  console.log();

  let ok = v.isPermit && v.permitToken != null;
  results.push(['Case A: same IP and geo permits', ok]);

  // -----------------------------------------------------------------
  // Case B: small move within the threshold.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case B: the user crosses from Manhattan to Newark on a new Wi-Fi.');
  console.log('-'.repeat(70));
  console.log('The IP changed. The geo coordinates moved about 15 km, well');
  console.log('under the 500 km threshold. Tolerant mode turns this from a');
  console.log('violation into a warning. A single warning does not push the');
  console.log('drift detector into invalidating on its own, so the policy\'s');
  console.log('permit stands. We expect: PERMIT.');
  console.log();

  v = gate.evaluate(
    resetCtx(sessionId, '198.51.100.55', '203.0.113.10', GEO_NEWARK, GEO_NEW_YORK),
  );

  // Snapshot the listener to confirm tolerant mode did not publish
  // an invalidation for this short hop. If drift had been in strict
  // mode, the IP change would have invalidated and the broadcaster
  // would have seen one more event.
  await new Promise((r) => setTimeout(r, 50));
  const receivedAfterB = received.length;

  console.log(`Verdict kind:   ${v.kind}`);
  console.log(`Is permit:      ${v.isPermit}`);
  console.log(`Token id:       ${v.tokenId}`);
  console.log(`Invalidations broadcast so far: ${receivedAfterB}`);
  console.log();

  ok =
    v.isPermit &&
    v.permitToken != null &&
    v.evaluator !== 'drift' &&
    receivedAfterB === 0;
  results.push(['Case B: small 15 km move permits, no invalidation', ok]);

  // -----------------------------------------------------------------
  // Case C: large move beyond the threshold.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case C: the reset link is opened from Singapore.');
  console.log('-'.repeat(70));
  console.log('Distance from New York to Singapore is around 15,000 km, far');
  console.log('beyond the 500 km threshold. The drift evaluator reports a');
  console.log('violation. That beats the policy\'s permit, and the gate emits');
  console.log('an invalidate verdict. The broadcaster should also fan this');
  console.log("out to the listener. We expect: INVALIDATE, evaluator 'drift',");
  console.log('a reason string that mentions kilometres, no permit token,');
  console.log('and one invalidation scope delivered to the listener.');
  console.log();

  v = gate.evaluate(
    resetCtx(sessionId, '192.0.2.77', '203.0.113.10', GEO_SINGAPORE, GEO_NEW_YORK),
  );

  console.log(`Verdict kind:   ${v.kind}`);
  console.log(`Is invalidate:  ${v.isInvalidate}`);
  console.log(`Evaluator:      ${v.evaluator}`);
  console.log(`Reason:         ${v.reason}`);
  console.log(`Permit token:   ${v.permitToken}`);
  console.log();

  // Let the background listener drain its channel before we read it.
  await new Promise((r) => setTimeout(r, 50));
  console.log(
    `Listener received ${received.length} invalidation scope(s) so far.`,
  );
  if (received.length > 0) {
    const scope = received[received.length - 1]!;
    console.log(`  scope.target_kind: ${scope.targetKind}`);
    console.log(`  scope.target_id:   ${scope.targetId}`);
    console.log(`  scope.evaluator:   ${scope.evaluator}`);
    console.log(`  scope.reason:      ${scope.reason}`);
  }
  console.log();

  ok =
    v.isInvalidate &&
    v.evaluator === 'drift' &&
    (v.reason ?? '').includes('>') &&
    (v.reason ?? '').includes('km') &&
    v.permitToken == null &&
    received.length === 1 &&
    received[0]!.targetKind === 'session' &&
    received[0]!.evaluator === 'drift';
  results.push(['Case C: cross ocean move invalidates and broadcasts', ok]);

  // -----------------------------------------------------------------
  // Case D: unknown distance.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case D: IP changed, current geo has only a country code.');
  console.log('-'.repeat(70));
  console.log('The geo lookup on the current side only resolved a country');
  console.log('code, no latitude or longitude. We cannot compute a distance,');
  console.log("so tolerant mode cannot decide 'this is under 500 km'. It");
  console.log('treats the unknown as a violation. This is the fail closed');
  console.log('direction: if you cannot verify the move, do not allow it.');
  console.log('We expect: INVALIDATE, with a reason that mentions the move');
  console.log('is unverifiable, and a second invalidation scope delivered to');
  console.log('the listener.');
  console.log();

  v = gate.evaluate(
    resetCtx(
      sessionId,
      '192.0.2.77',
      '203.0.113.10',
      GEO_SINGAPORE_NO_COORDS,
      GEO_NEW_YORK,
    ),
  );

  console.log(`Verdict kind:  ${v.kind}`);
  console.log(`Is invalidate: ${v.isInvalidate}`);
  console.log(`Evaluator:     ${v.evaluator}`);
  console.log(`Reason:        ${v.reason}`);
  console.log();

  await new Promise((r) => setTimeout(r, 50));
  console.log(
    `Listener now has ${received.length} invalidation scope(s) in total.`,
  );
  console.log();

  ok =
    v.isInvalidate &&
    v.evaluator === 'drift' &&
    (v.reason ?? '').includes('unverifiable') &&
    received.length === 2;
  results.push([
    'Case D: unverifiable distance invalidates and broadcasts',
    ok,
  ]);

  // -----------------------------------------------------------------
  // Clean up the background listener so the process can exit cleanly.
  // -----------------------------------------------------------------
  listener.abort();

  // -----------------------------------------------------------------
  // Summary
  // -----------------------------------------------------------------
  console.log('='.repeat(70));
  console.log('Summary');
  console.log('='.repeat(70));
  const passed = results.filter(([, isOk]) => isOk).length;
  for (const [label, isOk] of results) {
    const mark = isOk ? 'PASS' : 'FAIL';
    console.log(`  [${mark}] ${label}`);
  }
  console.log();
  console.log(`${passed}/${results.length} checks passed.`);
  console.log();

  return passed === results.length ? 0 : 1;
}

main()
  .then((rc) => process.exit(rc))
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });
