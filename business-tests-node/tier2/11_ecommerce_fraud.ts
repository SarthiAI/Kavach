/**
 * Scenario 11: e-commerce fraud gate with observe only rollout.
 *
 * The story
 * ---------
 * An online storefront turns on Kavach as its checkout fraud gate.
 * Every card charge passes through four overlapping layers:
 *
 *     1. Identity tier. New customers charge up to $500 per call.
 *        KYC verified customers charge up to $10,000 per call.
 *     2. Rate limit. New customers do at most 3 charges per hour.
 *     3. Geo drift. Tolerant mode, 500 km threshold. A NYC to Tokyo
 *        session hop invalidates.
 *     4. Invariant. Hard $5,000 ceiling above every tier.
 *
 * The team rolls this out safely. For the first 48 hours, a second
 * 'observe only' gate runs alongside the strict one. Both evaluate
 * the full chain. The observe gate always returns permit so callers
 * never see a false reject during calibration; the audit chain
 * still records what the strict gate WOULD have said.
 *
 * Seven cases: A normal charge, B new-cap breach, C rate burst,
 * D cross-continent drift, E invariant, F observe only, G JSONL
 * round trip.
 *
 * Run this file directly:
 *
 *   node dist/tier2/11_ecommerce_fraud.js
 */

import {
  AuditEntry,
  Gate,
  KavachKeyPair,
  SignedAuditChain,
  type EvaluateOptions,
  type GeoLocationInput,
  type Invariant,
  type Verdict,
} from 'kavach-sdk';

const POLICIES = {
  policies: [
    {
      name: 'verified_customer_checkout',
      effect: 'permit',
      priority: 10,
      conditions: [
        { identity_role: 'customer.verified' },
        { action: 'checkout.charge' },
        { param_max: { field: 'amount_usd', max: 10000.0 } },
      ],
    },
    {
      name: 'new_customer_checkout',
      effect: 'permit',
      priority: 20,
      conditions: [
        { identity_role: 'customer' },
        { action: 'checkout.charge' },
        { param_max: { field: 'amount_usd', max: 500.0 } },
        { rate_limit: { max: 3, window: '1h' } },
      ],
    },
  ],
};

const INVARIANTS: Invariant[] = [
  { name: 'manual_review_threshold', field: 'amount_usd', maxValue: 5000.0 },
];
const GEO_DRIFT_KM = 500.0;

const NYC: GeoLocationInput = {
  countryCode: 'US',
  city: 'New York',
  latitude: 40.7128,
  longitude: -74.006,
};
const NEWARK: GeoLocationInput = {
  countryCode: 'US',
  city: 'Newark',
  latitude: 40.7357,
  longitude: -74.1724,
};
const TOKYO: GeoLocationInput = {
  countryCode: 'JP',
  city: 'Tokyo',
  latitude: 35.6762,
  longitude: 139.6503,
};

interface ChargeOpts {
  originGeo?: GeoLocationInput;
  currentGeo?: GeoLocationInput;
  originIp?: string;
  ip?: string;
}

function charge(
  principal: string,
  role: string,
  amount: number,
  opts: ChargeOpts = {},
): EvaluateOptions {
  return {
    principalId: principal,
    principalKind: 'user',
    actionName: 'checkout.charge',
    roles: [role],
    params: { amount_usd: amount },
    originGeo: opts.originGeo ?? NYC,
    currentGeo: opts.currentGeo ?? NYC,
    originIp: opts.originIp ?? '203.0.113.10',
    ip: opts.ip ?? '203.0.113.10',
  };
}

function audit(
  chain: SignedAuditChain,
  principal: string,
  verdict: Verdict,
  phase: string,
): void {
  let detail = `phase=${phase} | evaluator=${verdict.evaluator ?? '-'} | code=${verdict.code ?? '-'}`;
  if (verdict.reason) {
    detail += ` | reason=${verdict.reason.slice(0, 80)}`;
  }
  chain.append(
    AuditEntry.new(principal, 'checkout.charge', verdict.kind, detail),
  );
}

function run(
  strictGate: Gate,
  chain: SignedAuditChain,
  principal: string,
  ctx: EvaluateOptions,
  phase = 'enforce',
): Verdict {
  const v = strictGate.evaluate(ctx);
  audit(chain, principal, v, phase);
  return v;
}

function main(): number {
  console.log('='.repeat(70));
  console.log('Scenario 11: e-commerce fraud gate with observe only rollout');
  console.log('='.repeat(70));
  console.log();

  // Two gates from the same policy: one strict, one observe-only.
  const strictGate = Gate.fromObject(POLICIES, {
    invariants: INVARIANTS,
    geoDriftMaxKm: GEO_DRIFT_KM,
  });
  const observeGate = Gate.fromObject(POLICIES, {
    invariants: INVARIANTS,
    geoDriftMaxKm: GEO_DRIFT_KM,
    observeOnly: true,
  });
  const auditKp = KavachKeyPair.generate();
  const chain = new SignedAuditChain(auditKp, false);
  console.log(`  strictGate.evaluatorCount:  ${strictGate.evaluatorCount}`);
  console.log(`  observeGate.evaluatorCount: ${observeGate.evaluatorCount}`);
  console.log(`  chain.isHybrid=${chain.isHybrid}  audit.key_id=${auditKp.id}`);
  console.log();

  const results: [string, boolean][] = [];

  // --- Case A: normal $150 charge.
  console.log('Case A: new customer alice, $150 from usual IP.');
  let v = run(
    strictGate,
    chain,
    'cust-alice',
    charge('cust-alice', 'customer', 150.0),
  );
  console.log(`  ${v.kind}  token=${v.tokenId}  chain=${chain.length}`);
  console.log();
  results.push(['Case A: $150 permits', v.isPermit]);
  results.push([
    'Case A: carries a permit token',
    v.permitToken !== null && v.permitToken !== undefined,
  ]);

  // --- Case B: over new-customer cap.
  console.log('Case B: new customer bob, $750 (over $500 cap).');
  v = run(
    strictGate,
    chain,
    'cust-bob',
    charge('cust-bob', 'customer', 750.0, {
      originIp: '203.0.113.11',
      ip: '203.0.113.11',
    }),
  );
  console.log(`  ${v.kind}  evaluator=${v.evaluator}  code=${v.code}`);
  console.log();
  results.push([
    'Case B: $750 refuses on tier cap',
    v.isRefuse && v.code === 'NO_POLICY_MATCH',
  ]);

  // --- Case C: rate limit burst.
  console.log('Case C: new customer claire fires 4 charges of $150 in one hour.');
  let permits = 0;
  let refuses = 0;
  for (let i = 0; i < 4; i++) {
    const bv = run(
      strictGate,
      chain,
      'cust-claire.burst',
      charge('cust-claire.burst', 'customer', 150.0, {
        originIp: '198.51.100.22',
        ip: '198.51.100.22',
      }),
    );
    console.log(`  burst ${i + 1}: ${bv.kind}  code=${bv.code ?? '-'}`);
    if (bv.isPermit) permits += 1;
    else refuses += 1;
  }
  console.log();
  results.push([
    'Case C: 3 permit, 4th refuses on rate',
    permits === 3 && refuses === 1,
  ]);

  // --- Case D: drift (NYC to Tokyo) and a control (NYC to Newark).
  console.log('Case D: verified dana, NYC session then Tokyo charge. Then a Newark control.');
  const vHop = run(
    strictGate,
    chain,
    'cust-dana.verified',
    charge('cust-dana.verified', 'customer.verified', 50.0, {
      originGeo: NYC,
      currentGeo: TOKYO,
      originIp: '203.0.113.42',
      ip: '198.51.100.99',
    }),
  );
  const vLocal = run(
    strictGate,
    chain,
    'cust-dana2.verified',
    charge('cust-dana2.verified', 'customer.verified', 50.0, {
      originGeo: NYC,
      currentGeo: NEWARK,
      originIp: '203.0.113.43',
      ip: '203.0.113.44',
    }),
  );
  console.log(`  Tokyo hop: ${vHop.kind}  evaluator=${vHop.evaluator}`);
  console.log(`  reason:    ${vHop.reason}`);
  console.log(`  Newark hop: ${vLocal.kind}  (control)`);
  console.log();
  results.push([
    'Case D: Tokyo hop invalidates on drift',
    vHop.isInvalidate && vHop.evaluator === 'drift',
  ]);
  results.push(['Case D: Newark hop permits', vLocal.isPermit]);

  // --- Case E: invariant at $5,001 (above policy, below invariant).
  console.log('Case E: verified ethan, $5,001 (invariant ceiling).');
  v = run(
    strictGate,
    chain,
    'cust-ethan.verified',
    charge('cust-ethan.verified', 'customer.verified', 5001.0, {
      originIp: '203.0.113.50',
      ip: '203.0.113.50',
    }),
  );
  console.log(`  ${v.kind}  evaluator=${v.evaluator}  code=${v.code}`);
  console.log(`  reason: ${v.reason}`);
  console.log();
  results.push([
    'Case E: $5,001 refuses on invariant',
    v.isRefuse &&
      v.evaluator === 'invariants' &&
      (v.reason ?? '').includes('manual_review_threshold'),
  ]);

  // --- Case F: observe-only. Strict gate would refuse; caller gets permit.
  console.log('Case F: observe only, $750 from new customer felix.');
  const ctxF = charge('cust-felix', 'customer', 750.0, {
    originIp: '203.0.113.60',
    ip: '203.0.113.60',
  });
  const wouldHave = strictGate.evaluate(ctxF);
  audit(chain, 'cust-felix', wouldHave, 'observe');
  const callerFacing = observeGate.evaluate(ctxF);
  console.log(`  strict would have: ${wouldHave.kind}  code=${wouldHave.code}`);
  console.log(`  caller facing:     ${callerFacing.kind}  token=${callerFacing.tokenId}`);
  console.log();
  results.push(['Case F: would-have refuses', wouldHave.isRefuse]);
  results.push(['Case F: caller facing permits', callerFacing.isPermit]);

  // --- Case G: JSONL round trip.
  console.log('Case G: export chain and reverify.');
  const exported = chain.exportJsonl();
  const verified = SignedAuditChain.verifyJsonl(exported, auditKp.publicKeys());
  const lineCount = exported
    .toString('utf-8')
    .split('\n')
    .filter((s) => s.length > 0).length;
  console.log(`  chain.length=${chain.length}  exported lines=${lineCount}  verified=${verified}`);
  console.log();
  results.push(['Case G: JSONL line count matches', lineCount === chain.length]);
  results.push([
    'Case G: verifyJsonl returns chain length',
    verified === chain.length,
  ]);

  // --- Summary.
  console.log('='.repeat(70));
  console.log('Summary');
  console.log('='.repeat(70));
  const passed = results.filter(([, k]) => k).length;
  for (const [label, k] of results) {
    console.log(`  [${k ? 'PASS' : 'FAIL'}] ${label}`);
  }
  console.log();
  console.log(`${passed}/${results.length} checks passed.`);
  console.log();
  return passed === results.length ? 0 : 1;
}

process.exit(main());
