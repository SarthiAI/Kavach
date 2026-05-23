/**
 * Scenario 02: document classification, rate limit, and app side scoping.
 *
 * The story
 * ---------
 * A consulting firm runs its workpaper service behind a Kavach gate.
 * Every read has to satisfy three rules before the document service
 * even looks at the filesystem:
 *
 *     1. Role. The caller must be a consultant. Anything else is
 *        refused by default deny.
 *
 *     2. Classification tier. Each document is tagged with one of
 *        'public', 'internal', or 'engagement_workpapers'. A
 *        consultant may read those three tiers. A separate tier,
 *        'board_confidential', is off limits to consultants; only
 *        partners touch those documents and a different rule (not
 *        in this scenario) would cover them.
 *
 *     3. Read rate. At most 60 reads per hour per consultant. Bursts
 *        above that are almost always a script or a page that
 *        auto-refreshes in a loop.
 *
 * On top of the gate, the service layers one per user check that
 * Kavach does not try to do for you: the consultant must actually be
 * staffed on the engagement the document belongs to. The staffing
 * list comes from HR and varies per user per day, which is a bad fit
 * for a static policy file; it is a natural fit for a one line app
 * side check right after the gate permits.
 *
 * This is the typical production split: Kavach enforces the rules
 * every call shares (role, classification, rate), and your service
 * layers its own per caller check where that makes sense. Both
 * halves are visible in the cases below.
 *
 * Five cases:
 *
 *     A. Alice staffed on E-4471, reads an 'internal' doc on E-4471.
 *        Gate permits, app permits.
 *     B. Alice reads an 'internal' doc on E-9001 (not on her list).
 *        Gate permits (role, classification, rate all fine), app
 *        refuses because the engagement is not in her staffing.
 *     C. Alice reads a 'board_confidential' doc on E-4471.
 *        Gate refuses on classification, the app check never runs.
 *     D. Alice fires 61 reads in one hour.
 *        First 60 permit, the 61st refuses on the rate condition.
 *     E. Alice's client grants temporary access to E-9001. Her
 *        staffing list is widened for this session and the next
 *        read on E-9001 now permits at both the gate and the app.
 *
 * Run this file directly:
 *
 *   node dist/tier1/02_document_access.js
 */

import { Gate, type EvaluateOptions, type Verdict } from 'kavach-sdk';

// Kavach handles role, classification, and rate. The staffing list
// is a per caller per day fact that does not belong in a static
// policy file; the service checks it right after the gate.
const POLICIES = {
  policies: [
    {
      name: 'consultant_reads_documents',
      description:
        'Consultants may read public, internal, and engagement workpapers at up to 60 reads per hour',
      effect: 'permit',
      priority: 10,
      conditions: [
        { identity_role: 'consultant' },
        { action: 'document.read' },
        {
          param_in: {
            field: 'classification',
            values: ['public', 'internal', 'engagement_workpapers'],
          },
        },
        { rate_limit: { max: 60, window: '1h' } },
      ],
    },
  ],
};

function readCtx(
  userId: string,
  engagementId: string,
  classification: string,
): EvaluateOptions {
  return {
    principalId: userId,
    principalKind: 'user',
    actionName: 'document.read',
    roles: ['consultant'],
    resource: `engagements/${engagementId}/workpaper.pdf`,
    params: {
      engagement_id: engagementId,
      classification: classification,
    },
  };
}

/**
 * Per user engagement scoping. Runs only when the gate has
 * permitted; Kavach already handled role, classification, rate.
 */
function appCheck(
  verdict: Verdict,
  engagementId: string,
  staffedOn: string[],
): [string, string] {
  if (!verdict.isPermit) {
    return [verdict.kind, 'gate refused'];
  }
  if (!staffedOn.includes(engagementId)) {
    return ['refuse', "engagement not on the consultant's staffing list"];
  }
  return ['permit', 'gate permitted and engagement is in the staffing list'];
}

function main(): number {
  console.log('='.repeat(70));
  console.log(
    'Scenario 02: document classification, rate limit, and app side scoping',
  );
  console.log('='.repeat(70));
  console.log();
  console.log('We are going to build a gate that enforces role, classification');
  console.log('tier, and a 60 per hour rate cap, then layer one small app side');
  console.log('check on top for per user engagement scoping. The cases show');
  console.log('both sides: Kavach refusing the wrong classification and the');
  console.log("runaway rate, and the app refusing engagements that are not on");
  console.log("the caller's staffing list.");
  console.log();

  const gate = Gate.fromObject(POLICIES);
  console.log(`Gate built. It has ${gate.evaluatorCount} evaluators.`);
  console.log();

  const results: [string, boolean][] = [];

  // ---- Case A: baseline, everything lines up.
  console.log('-'.repeat(70));
  console.log(
    "Case A: alice staffed on E-4471, reads an 'internal' doc on E-4471.",
  );
  console.log('-'.repeat(70));
  let aliceStaffing = ['E-4471'];
  let v = gate.evaluate(readCtx('alice', 'E-4471', 'internal'));
  let [kind, reason] = appCheck(v, 'E-4471', aliceStaffing);
  console.log(`  gate verdict: ${v.kind}`);
  console.log(`  app check:    ${kind} (${reason})`);
  console.log();
  results.push([
    'Case A: own engagement, internal doc permits',
    kind === 'permit',
  ]);

  // ---- Case B: app refuses, gate permits.
  console.log('-'.repeat(70));
  console.log(
    "Case B: alice tries an 'internal' doc on E-9001 (not on her list).",
  );
  console.log('-'.repeat(70));
  console.log('Role, classification, and rate are all fine. The gate permits.');
  console.log('The app side staffing check is the one that catches this, and');
  console.log("reports 'engagement not on the staffing list'. This is the");
  console.log('composition pattern: Kavach and the service each own the piece');
  console.log('they are best at.');
  console.log();
  v = gate.evaluate(readCtx('alice', 'E-9001', 'internal'));
  [kind, reason] = appCheck(v, 'E-9001', aliceStaffing);
  console.log(
    `  gate verdict: ${v.kind}  (gate does not know the staffing list)`,
  );
  console.log(`  app check:    ${kind} (${reason})`);
  console.log();
  results.push([
    'Case B: gate permits, app refuses on engagement scope',
    v.isPermit && kind === 'refuse',
  ]);

  // ---- Case C: gate refuses on classification.
  console.log('-'.repeat(70));
  console.log("Case C: alice tries a 'board_confidential' doc on E-4471.");
  console.log('-'.repeat(70));
  console.log('Classification is not in the allow list for consultants. The');
  console.log('gate refuses before the app side check runs. This is Kavach');
  console.log('doing real enforcement: wrong classification never reaches the');
  console.log('document service, the staffing check is never consulted.');
  console.log();
  v = gate.evaluate(readCtx('alice', 'E-4471', 'board_confidential'));
  [kind, reason] = appCheck(v, 'E-4471', aliceStaffing);
  console.log(
    `  gate verdict: ${v.kind}  evaluator=${v.evaluator}  code=${v.code}`,
  );
  console.log(`  app check:    ${kind} (${reason})`);
  console.log();
  results.push([
    'Case C: wrong classification refused at the gate',
    v.isRefuse && v.evaluator === 'policy' && v.code === 'NO_POLICY_MATCH',
  ]);

  // ---- Case D: gate rate limit.
  console.log('-'.repeat(70));
  console.log('Case D: alice fires 61 reads in one hour.');
  console.log('-'.repeat(70));
  console.log('First 60 clear the rate condition. The 61st crosses the cap');
  console.log('and the rule no longer matches, so default deny refuses. This');
  console.log('is Kavach keeping a runaway page or script from draining the');
  console.log('document service, without the app having to implement its own');
  console.log('rate counter. We build a fresh gate here so the rate bucket');
  console.log('is isolated from earlier cases.');
  console.log();
  const burstGate = Gate.fromObject(POLICIES);
  let permits = 0;
  let refuses = 0;
  let lastRefuse: Verdict | null = null;
  for (let i = 0; i < 61; i++) {
    const rv = burstGate.evaluate(readCtx('alice', 'E-4471', 'internal'));
    if (rv.isPermit) {
      permits += 1;
    } else {
      refuses += 1;
      lastRefuse = rv;
    }
  }
  console.log(`  permits: ${permits}`);
  console.log(`  refuses: ${refuses}`);
  if (lastRefuse !== null) {
    console.log(
      `  last refuse evaluator: ${lastRefuse.evaluator}  code: ${lastRefuse.code}`,
    );
  }
  console.log();
  results.push([
    'Case D: 60 permit, 61st refuses on rate',
    permits === 60 && refuses === 1,
  ]);

  // ---- Case E: staffing widens mid session.
  console.log('-'.repeat(70));
  console.log("Case E: alice's client grants temporary access to E-9001.");
  console.log('-'.repeat(70));
  console.log("The app updates alice's staffing list for this session. No");
  console.log('policy reload, no gate rebuild, no deploy: Kavach does not');
  console.log('need to know about the change because the staffing list lives');
  console.log('on the app side. We build a fresh gate here so the case is');
  console.log("isolated from case D's rate bucket.");
  console.log();
  aliceStaffing = ['E-4471', 'E-9001'];
  const freshGate = Gate.fromObject(POLICIES);
  v = freshGate.evaluate(readCtx('alice', 'E-9001', 'internal'));
  [kind, reason] = appCheck(v, 'E-9001', aliceStaffing);
  console.log(`  gate verdict: ${v.kind}`);
  console.log(`  app check:    ${kind} (${reason})`);
  console.log();
  results.push([
    'Case E: widened staffing permits E-9001',
    v.isPermit && kind === 'permit',
  ]);

  // ---- Summary
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

process.exit(main());
