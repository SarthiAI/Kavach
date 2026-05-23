/**
 * Scenario 04: session hygiene with all four drift detectors.
 *
 * The story
 * ---------
 * Business dashboards often hold long sessions. A user might open the
 * dashboard in the morning and keep it open all day. Over that window,
 * plenty of things about the session can change for bad reasons:
 *
 *     The IP address changes. Could be a VPN toggle, could be a
 *     session cookie stolen and replayed from somewhere else.
 *
 *     The session is still alive four hours later. Maybe that user
 *     went for lunch and left the tab open, or maybe someone opened
 *     a drawer and found an unlocked laptop.
 *
 *     The device fingerprint changes. Different browser, different
 *     OS, different screen size. Same cookie.
 *
 *     The action rate suddenly spikes. A real person clicks a few
 *     times per minute. Hundreds of actions per minute usually means
 *     a script is driving the session.
 *
 * Kavach has four drift detectors, one for each of these signals, and
 * they all run as part of the evaluator chain. Any one of them can
 * raise a violation and the gate invalidates the session. Downstream
 * code should then log the user out.
 *
 * In this scenario we exercise all four detectors by crafting an
 * ActionContext that triggers each one in turn.
 *
 * Six cases:
 *
 *     A. Same IP, same geo                , expect PERMIT (baseline)
 *     B. IP changes mid session           , expect INVALIDATE
 *     C. Cross country hop (US to CN)     , expect INVALIDATE
 *     D. Session started 6 hours ago      , expect INVALIDATE
 *     E. Device fingerprint differs       , expect INVALIDATE
 *     F. 200 actions in a 60 second session, expect INVALIDATE
 *
 * Run this file directly:
 *
 *   node dist/tier1/04_session_hygiene.js
 */

import { randomUUID } from 'node:crypto';

import {
  Gate,
  type DeviceFingerprintInput,
  type EvaluateOptions,
  type GeoLocationInput,
} from 'kavach-sdk';

// ---------------------------------------------------------------------
// Step 1. Write the rule as a plain object.
// ---------------------------------------------------------------------
// One simple permit rule for the dashboard read. The drift detectors
// run automatically as part of the evaluator chain; we just need to
// attach the right fields on the EvaluateOptions to exercise each one.

const POLICIES = {
  policies: [
    {
      name: 'dashboard_read',
      description: 'Authenticated ops users may read the dashboard',
      effect: 'permit',
      priority: 10,
      conditions: [
        { identity_role: 'ops_user' },
        { action: 'dashboard.read' },
      ],
    },
  ],
};

// ---------------------------------------------------------------------
// Two geo anchors for the geo drift cases.
// ---------------------------------------------------------------------
const GEO_NEW_YORK: GeoLocationInput = {
  countryCode: 'US',
  region: 'NY',
  city: 'New York',
  latitude: 40.7128,
  longitude: -74.006,
};
const GEO_SHANGHAI: GeoLocationInput = {
  countryCode: 'CN',
  region: 'Shanghai',
  city: 'Shanghai',
  latitude: 31.2304,
  longitude: 121.4737,
};

function opsCtx(
  sessionId: string,
  overrides: Partial<EvaluateOptions> = {},
): EvaluateOptions {
  // Start from a clean baseline context and apply any overrides a
  // case wants. This keeps each case short and easy to read.
  const base: EvaluateOptions = {
    principalId: 'ops-carol',
    principalKind: 'user',
    actionName: 'dashboard.read',
    roles: ['ops_user'],
    ip: '198.51.100.20',
    originIp: '198.51.100.20',
    currentGeo: GEO_NEW_YORK,
    originGeo: GEO_NEW_YORK,
    sessionId: sessionId,
  };
  return { ...base, ...overrides };
}

function main(): number {
  console.log('='.repeat(70));
  console.log('Scenario 04: session hygiene with all four drift detectors');
  console.log('='.repeat(70));
  console.log();
  console.log('We are going to build a gate with one permit rule for the');
  console.log('dashboard read action. The drift detectors run automatically');
  console.log('as part of the evaluator chain, and each one watches a');
  console.log('different kind of session change. Then we craft six requests');
  console.log('that each exercise one detector.');
  console.log();

  // -----------------------------------------------------------------
  // Step 2. Build the gate in strict geo drift mode.
  // -----------------------------------------------------------------
  console.log('Building the gate from the policy object.');
  console.log('We do not set geoDriftMaxKm, which puts the geo drift');
  console.log('detector in strict mode: any mid session IP change counts as');
  console.log('a violation. The default thresholds for the other detectors');
  console.log('are:');
  console.log('  session age    : 4 hours');
  console.log('  action rate    : 100 per minute');
  console.log('  device change  : any hash change counts as a violation');
  const gate = Gate.fromObject(POLICIES);
  console.log(
    `Gate built. It has ${gate.evaluatorCount} evaluators chained together.`,
  );
  console.log();

  const sessionId = randomUUID();
  console.log(`Cases A through D share this session id: ${sessionId}`);
  console.log('Cases E and F use fresh session ids to isolate each detector.');
  console.log();

  const results: [string, boolean][] = [];

  // -----------------------------------------------------------------
  // Case A: baseline.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case A: same IP, same geo, fresh session.');
  console.log('-'.repeat(70));
  console.log('Nothing has changed since the session started. All four drift');
  console.log('detectors report a stable session. Policy permits. This is');
  console.log('the baseline that proves the gate does not invalidate every');
  console.log('call by default. We expect: PERMIT.');
  console.log();

  let v = gate.evaluate(opsCtx(sessionId));

  console.log(`Verdict kind: ${v.kind}`);
  console.log(`Is permit:    ${v.isPermit}`);
  console.log(`Token id:     ${v.tokenId}`);
  console.log();

  results.push(['Case A: stable session permits', v.isPermit]);

  // -----------------------------------------------------------------
  // Case B: IP change mid session.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case B: the next request arrives from a different IP.');
  console.log('-'.repeat(70));
  console.log('We pass the same session id but change the current IP from');
  console.log('198.51.100.20 to 203.0.113.77. In strict mode, any mid');
  console.log('session IP change is a violation and the gate invalidates.');
  console.log("We expect: INVALIDATE, evaluator 'drift', a reason that names");
  console.log('both IPs so the incident playbook has the context it needs.');
  console.log();

  v = gate.evaluate(opsCtx(sessionId, { ip: '203.0.113.77' }));

  console.log(`Verdict kind:  ${v.kind}`);
  console.log(`Is invalidate: ${v.isInvalidate}`);
  console.log(`Evaluator:     ${v.evaluator}`);
  console.log(`Reason:        ${v.reason}`);
  console.log();

  let ok =
    v.isInvalidate &&
    v.evaluator === 'drift' &&
    (v.reason ?? '').includes('198.51.100.20') &&
    (v.reason ?? '').includes('203.0.113.77');
  results.push(['Case B: IP change invalidates', ok]);

  // -----------------------------------------------------------------
  // Case C: cross country hop.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case C: IP changes and the geo country code changes too.');
  console.log('-'.repeat(70));
  console.log('Same session, new IP, and the geo now reports Shanghai (CN)');
  console.log('instead of New York (US). Strict geo drift already fires on');
  console.log('any IP change, so this is going to invalidate anyway. What');
  console.log('we additionally want to see is that the reason text surfaces');
  console.log('the new country tag (CN), so the alert is useful.');
  console.log();

  v = gate.evaluate(
    opsCtx(sessionId, { ip: '192.0.2.200', currentGeo: GEO_SHANGHAI }),
  );

  console.log(`Verdict kind:  ${v.kind}`);
  console.log(`Is invalidate: ${v.isInvalidate}`);
  console.log(`Evaluator:     ${v.evaluator}`);
  console.log(`Reason:        ${v.reason}`);
  console.log();

  ok =
    v.isInvalidate &&
    v.evaluator === 'drift' &&
    (v.reason ?? '').includes('CN');
  results.push([
    'Case C: cross country hop invalidates with country tag',
    ok,
  ]);

  // -----------------------------------------------------------------
  // Case D: old session.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case D: session started 6 hours ago.');
  console.log('-'.repeat(70));
  console.log('We attach sessionStartedAt set to 6 hours in the past. The');
  console.log('default session age cap is 4 hours. The session age drift');
  console.log('detector reports a violation. We expect: INVALIDATE, with a');
  console.log("reason that mentions 'session age'.");
  console.log();

  const now = Math.floor(Date.now() / 1000);
  const sixHoursAgo = now - 6 * 3600;
  v = gate.evaluate(opsCtx(sessionId, { sessionStartedAt: sixHoursAgo }));

  console.log(`sessionStartedAt: ${sixHoursAgo} (about 6 hours ago)`);
  console.log(`Verdict kind:  ${v.kind}`);
  console.log(`Is invalidate: ${v.isInvalidate}`);
  console.log(`Evaluator:     ${v.evaluator}`);
  console.log(`Reason:        ${v.reason}`);
  console.log();

  ok =
    v.isInvalidate &&
    (v.reason ?? '').toLowerCase().includes('session age');
  results.push(['Case D: old session invalidates', ok]);

  // -----------------------------------------------------------------
  // Case E: device fingerprint differs.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case E: device fingerprint changed on the same session.');
  console.log('-'.repeat(70));
  console.log('We fill in two DeviceFingerprint objects, one for the origin');
  console.log('of the session and one for the current request. Their hashes');
  console.log('differ (the origin looks like a Mac desktop, the current');
  console.log("looks like an unknown Android). Kavach's device drift");
  console.log('detector reports a violation. We use a fresh session id so');
  console.log("this is not tangled up with case D's synthetic age.");
  console.log();

  const fingerprintOriginal: DeviceFingerprintInput = {
    hash: 'sha256:ORIGINAL-device',
    description: 'macOS desktop',
  };
  const fingerprintNew: DeviceFingerprintInput = {
    hash: 'sha256:DIFFERENT-device',
    description: 'unknown Android',
  };
  v = gate.evaluate(
    opsCtx(randomUUID(), {
      originDevice: fingerprintOriginal,
      device: fingerprintNew,
    }),
  );

  console.log(`origin_device hash: ${fingerprintOriginal.hash}`);
  console.log(`current device hash: ${fingerprintNew.hash}`);
  console.log(`Verdict kind:  ${v.kind}`);
  console.log(`Is invalidate: ${v.isInvalidate}`);
  console.log(`Evaluator:     ${v.evaluator}`);
  console.log(`Reason:        ${v.reason}`);
  console.log();

  ok =
    v.isInvalidate &&
    (v.reason ?? '').toLowerCase().includes('device');
  results.push(['Case E: device fingerprint change invalidates', ok]);

  // -----------------------------------------------------------------
  // Case F: 200 actions in a 60 second old session.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case F: 200 actions in a session that started 60 seconds ago.');
  console.log('-'.repeat(70));
  console.log('We synthesise a session with sessionStartedAt set to 60');
  console.log('seconds in the past, and actionCount set to 200. That is a');
  console.log('rate of 200 per minute, well above the default violation');
  console.log('threshold of 100 per minute. Behaviour drift reports a');
  console.log('violation. Again we use a fresh session id to keep this case');
  console.log('isolated. We expect: INVALIDATE, with a reason that mentions');
  console.log('the action rate.');
  console.log();

  const sixtySecondsAgo = now - 60;
  v = gate.evaluate(
    opsCtx(randomUUID(), {
      sessionStartedAt: sixtySecondsAgo,
      actionCount: 200,
    }),
  );

  console.log(`sessionStartedAt: ${sixtySecondsAgo} (60 seconds ago)`);
  console.log(`actionCount:       200`);
  console.log(`Verdict kind:  ${v.kind}`);
  console.log(`Is invalidate: ${v.isInvalidate}`);
  console.log(`Evaluator:     ${v.evaluator}`);
  console.log(`Reason:        ${v.reason}`);
  console.log();

  const reasonLower = (v.reason ?? '').toLowerCase();
  ok =
    v.isInvalidate &&
    (reasonLower.includes('action rate') || reasonLower.includes('rate'));
  results.push(['Case F: runaway action rate invalidates', ok]);

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

process.exit(main());
