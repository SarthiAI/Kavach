/**
 * Scenario 01: quick start, three lines to ship a gate.
 *
 * The story
 * ---------
 * The smallest useful program you can write with Kavach. If you are
 * evaluating the library, read this first: it is the whole happy
 * path, from policy to verdict, in under 80 lines of code.
 *
 * Run this file directly:
 *
 *   node dist/tier1/01_quickstart.js
 */

import { Gate, type EvaluateOptions } from 'kavach-sdk';

// One rule. Finance team can move money, capped at $10,000 per
// call. That is the whole policy.
const POLICIES = {
  policies: [
    {
      name: 'finance_can_transfer',
      effect: 'permit',
      priority: 10,
      conditions: [
        { identity_role: 'finance' },
        { action: 'treasury.transfer' },
        { param_max: { field: 'amount_usd', max: 10000.0 } },
      ],
    },
  ],
};

function main(): number {
  console.log('Kavach quick start');
  console.log('='.repeat(40));

  // Build the gate. One line.
  const gate = Gate.fromObject(POLICIES);

  // Three calls through the gate: one permitted, two refused.
  const cases: [string, EvaluateOptions][] = [
    [
      'finance user, $5,000',
      {
        principalId: 'alice',
        principalKind: 'user',
        actionName: 'treasury.transfer',
        roles: ['finance'],
        params: { amount_usd: 5000.0 },
      },
    ],
    [
      'finance user, $50,000 (over cap)',
      {
        principalId: 'alice',
        principalKind: 'user',
        actionName: 'treasury.transfer',
        roles: ['finance'],
        params: { amount_usd: 50000.0 },
      },
    ],
    [
      'engineer, $100 (wrong role)',
      {
        principalId: 'bob',
        principalKind: 'user',
        actionName: 'treasury.transfer',
        roles: ['engineer'],
        params: { amount_usd: 100.0 },
      },
    ],
  ];

  const verdicts = cases.map(([label, ctx]) => {
    const v = gate.evaluate(ctx);
    console.log(`${label.padEnd(42)}  ${v.kind.padStart(6)}`);
    return v;
  });

  const checks = [
    verdicts[0]!.isPermit, // finance $5k should permit
    verdicts[1]!.isRefuse, // $50k should refuse on cap
    verdicts[2]!.isRefuse, // engineer should refuse on role
  ];

  console.log('='.repeat(40));
  if (checks.every(Boolean)) {
    console.log('3/3 checks passed. You just shipped a gate.');
    console.log('Read 02_document_access.ts next, then 03_reset_geo_drift.ts.');
    return 0;
  }
  console.log(`${checks.filter(Boolean).length}/3 checks passed.`);
  return 1;
}

process.exit(main());
