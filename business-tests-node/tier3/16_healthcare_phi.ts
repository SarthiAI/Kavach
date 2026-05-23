/**
 * Scenario 16: healthcare PHI access with a signed audit chain.
 *
 * The story
 * ---------
 * A regional hospital runs every electronic health record read through
 * a Kavach gate. The rule for an attending physician is that a PHI
 * read is allowed only when three conditions all hold:
 *
 *     1. Country fence. The ActionContext carries a country_code param
 *        and the policy refuses anything that is not 'US'. A note on
 *        what this actually catches: Kavach does not look at IP
 *        addresses, it does not detect VPNs, and it does not resolve
 *        geography on its own. It enforces the rule you wrote against
 *        the field you gave it. In production the country code has to
 *        be filled in upstream, by something the attacker cannot
 *        forge: the HTTP handler reads the source IP from a trusted
 *        hop (Cloudflare CF-IPCountry, AWS CloudFront-Viewer-Country,
 *        MaxMind, IPinfo) and puts that into the context before the
 *        gate runs. If that upstream resolver is fooled by a VPN that
 *        egresses in the US, the gate sees country_code='US' and
 *        permits; the VPN detection is a separate feed (IPQS, Spur,
 *        MaxMind's anonymous IP DB) whose output lands in its own
 *        param. We model the upstream resolver as a small stub below,
 *        to keep the boundary visible.
 *
 *     2. Day shift. The wall clock must be inside 07:00 to 19:00
 *        Pacific time. Night shift reads go through a separate RBAC
 *        path, so any read outside that window from a day shift
 *        principal must refuse.
 *
 *     3. Rate cap. At most 50 reads per hour per doctor. A burst
 *        above that is usually an automated scraper and we want to
 *        shed it at the gate.
 *
 * Every read, whether it permits or refuses, is appended to a signed
 * audit chain so the compliance team can replay the day end to end.
 * Patient identifiers are hashed before they enter the chain (we keep
 * the first 16 hex chars of a SHA-256 of the patient id), so a log
 * dump can never reverse link into PHI. The raw patient id is still
 * recoverable from the primary EHR database if an investigation needs
 * it.
 *
 * Six cases:
 *
 *     A. In country, in shift, first read, expect PERMIT.
 *     B. Out of country (caller resolves to IN), expect REFUSE.
 *     C. Out of shift gate (window excludes 'now'), expect REFUSE.
 *     D. 51 reads in a row on the in-shift gate. 50 permit, 51st
 *        refuses.
 *     E. Export the chain to JSONL, reverify it, line count matches.
 *     F. Tamper one byte inside entry 2 of the exported blob, verify
 *        fails and names the exact entry index.
 *
 * Run this file directly:
 *
 *   node dist/tier3/16_healthcare_phi.js
 */

import { createHash } from 'node:crypto';

import {
  AuditEntry,
  Gate,
  KavachKeyPair,
  SignedAuditChain,
  type EvaluateOptions,
  type Verdict as VerdictResult,
} from 'kavach-sdk';

const TZ = 'America/Los_Angeles';

function laHhMm(date: Date): string {
  // Render `date` as HH:MM in America/Los_Angeles.
  return new Intl.DateTimeFormat('en-GB', {
    timeZone: TZ,
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
  }).format(date);
}

function inShiftWindow(): string {
  // A window around the current wall clock so the in-shift gate
  // always matches whatever time of day we run the scenario.
  const now = new Date();
  const fifteenMin = 15 * 60 * 1000;
  const start = laHhMm(new Date(now.getTime() - fifteenMin));
  const end = laHhMm(new Date(now.getTime() + fifteenMin));
  return `${start}-${end} America/Los_Angeles`;
}

function outOfShiftWindow(): string {
  // A window pushed 6 hours into the future so it never contains
  // the current moment, whatever time of day we run.
  const anchor = new Date(Date.now() + 6 * 60 * 60 * 1000);
  const start = laHhMm(anchor);
  const end = laHhMm(new Date(anchor.getTime() + 30 * 60 * 1000));
  return `${start}-${end} America/Los_Angeles`;
}

interface PolicyDoc {
  policies: Array<{
    name: string;
    description: string;
    effect: string;
    priority: number;
    conditions: Array<Record<string, unknown>>;
  }>;
}

function buildPolicies(shiftWindow: string): PolicyDoc {
  return {
    policies: [
      {
        name: 'phi_day_shift_read',
        description: 'Attending physicians read PHI, US only, day shift, 50/hour',
        effect: 'permit',
        priority: 10,
        conditions: [
          { identity_role: 'attending_physician' },
          { action: 'phi.read' },
          { param_in: { field: 'country_code', values: ['US'] } },
          { time_window: shiftWindow },
          { rate_limit: { max: 50, window: '1h' } },
        ],
      },
    ],
  };
}

function patientHash(patientId: string): string {
  return createHash('sha256').update(patientId, 'utf-8').digest('hex').slice(0, 16);
}

// ---------------------------------------------------------------------
// The upstream boundary. REPLACE THIS IN PRODUCTION.
//
// This stub stands in for whatever your HTTP handler actually does to
// turn a raw request into a country code. In real code you might:
//
//   a. Read Cloudflare's CF-IPCountry request header (trusted because
//      Cloudflare terminates TLS and the header cannot be forged by
//      a client).
//   b. Read AWS's CloudFront-Viewer-Country header on an API Gateway
//      or CloudFront-fronted service.
//   c. Look the source IP up in a MaxMind or IPinfo database that
//      ships with your deployment.
//
// The scenario below only exercises what Kavach does once the country
// code is already in the ActionContext. It does not claim Kavach can
// tell you the country on its own.
//
// A 'request' here is a plain object with a 'trustedCountryHeader'
// field, simulating the HTTP hop that already did the resolution.
// ---------------------------------------------------------------------
interface Request {
  trustedCountryHeader?: string;
}

function resolveCountryFromRequest(request: Request): string {
  const header = request.trustedCountryHeader;
  if (!header) {
    // Fail closed: no resolved country means the gate gets a value
    // that no policy rule whitelists, so default deny fires.
    return 'UNKNOWN';
  }
  return header;
}

function phiCtx(principalId: string, request: Request): EvaluateOptions {
  const countryCode = resolveCountryFromRequest(request);
  return {
    principalId,
    principalKind: 'user',
    actionName: 'phi.read',
    roles: ['attending_physician'],
    params: { country_code: countryCode },
  };
}

function auditFromVerdict(
  chain: SignedAuditChain,
  principalId: string,
  patientId: string,
  verdict: VerdictResult,
): void {
  const detail = {
    patient_hash: patientHash(patientId),
    evaluator: verdict.evaluator ?? null,
    code: verdict.code ?? null,
    reason: verdict.reason ?? null,
  };
  chain.append(
    AuditEntry.new(
      principalId,
      'phi.read',
      verdict.kind,
      JSON.stringify(detail),
    ),
  );
}

function mutateLine(
  jsonl: Buffer,
  idx: number,
  mutator: (obj: Record<string, unknown>) => void,
): Buffer {
  const trailingNewline = jsonl.length > 0 && jsonl[jsonl.length - 1] === 0x0a;
  const text = jsonl.toString('utf-8');
  const stripped = trailingNewline ? text.slice(0, -1) : text;
  const lines = stripped.split('\n');
  const obj = JSON.parse(lines[idx]!) as Record<string, unknown>;
  mutator(obj);
  lines[idx] = JSON.stringify(obj);
  const joined = lines.join('\n') + (trailingNewline ? '\n' : '');
  return Buffer.from(joined, 'utf-8');
}

function main(): number {
  console.log('='.repeat(70));
  console.log('Scenario 16: healthcare PHI access with a signed audit chain');
  console.log('='.repeat(70));
  console.log();
  console.log('We are going to build an in-shift gate, send one baseline read,');
  console.log('two refuses (out of country and out of shift), then a 51 call');
  console.log('burst to trip the rate limit. Every attempt is audited. We');
  console.log('export the chain, reverify it, and then tamper one entry to');
  console.log('show the verifier names exactly which entry was touched.');
  console.log();

  const results: [string, boolean][] = [];

  // -----------------------------------------------------------------
  // Audit keypair and chain.
  // -----------------------------------------------------------------
  console.log('Generating an audit keypair and opening a PQ-only signed chain.');
  const auditKp = KavachKeyPair.generate();
  const auditBundle = auditKp.publicKeys();
  const chain = new SignedAuditChain(auditKp, false);
  console.log(`  audit.key_id:    ${auditKp.id}`);
  console.log(`  chain.isHybrid:  ${chain.isHybrid}`);
  console.log(`  chain.length:    ${chain.length}`);
  console.log(`  chain.headHash:  ${chain.headHash}`);
  console.log();

  // -----------------------------------------------------------------
  // In-shift gate.
  // -----------------------------------------------------------------
  const shiftIn = inShiftWindow();
  console.log(`Building the in-shift gate. Shift window: ${shiftIn}`);
  const gate = Gate.fromObject(buildPolicies(shiftIn) as unknown as Record<string, unknown>);
  console.log(`  gate.evaluatorCount: ${gate.evaluatorCount}`);
  console.log();

  // -----------------------------------------------------------------
  // Case A: baseline.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case A: dr-smith, US, in shift, opens the EHR for patient P-1042.');
  console.log('-'.repeat(70));
  console.log('All three conditions hold. The rate bucket is empty. The rule');
  console.log('permits and the chain gains its first entry. The patient id');
  console.log('hashes into the audit entry, never the raw form.');
  console.log();

  // A "request" here stands in for whatever your HTTP handler
  // already resolved. Cloudflare set CF-IPCountry='US' because the
  // source IP belongs to a US ISP in Portland.
  const requestUs: Request = { trustedCountryHeader: 'US' };
  {
    const ctx = phiCtx('dr-smith', requestUs);
    const v = gate.evaluate(ctx);
    console.log(`Resolved country: ${resolveCountryFromRequest(requestUs)}`);
    console.log(`Verdict kind: ${v.kind}`);
    console.log(`Is permit:    ${v.isPermit}`);
    console.log(`Patient hash: ${patientHash('P-1042')}`);
    auditFromVerdict(chain, 'dr-smith', 'P-1042', v);
    console.log(`Chain length: ${chain.length}`);
    console.log();

    results.push(['Case A: baseline PHI read permits', v.isPermit]);
    results.push(['Case A: chain length becomes 1', chain.length === 1]);
  }

  // -----------------------------------------------------------------
  // Case B: out of country.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case B: the upstream resolver reports IN (India).');
  console.log('-'.repeat(70));
  console.log('Same doctor, same shift, same rate bucket. The difference is');
  console.log('that whatever sits in front of the gate (Cloudflare header,');
  console.log("MaxMind lookup on source IP) returned 'IN' this time. Maybe");
  console.log('dr-smith is travelling and opened a laptop in Bengaluru; maybe');
  console.log("the clinic's edge network re-routed through an Indian POP;");
  console.log('maybe it was a genuine bad actor. The gate does not know. It');
  console.log("sees country_code='IN' and the policy rule does not match,");
  console.log('so default deny refuses. The audit chain still records the');
  console.log('attempt so compliance can triage.');
  console.log();

  // Cloudflare/MaxMind reported IN because the request egressed from
  // an Indian ISP. The gate is only as good as this upstream value.
  const requestIn: Request = { trustedCountryHeader: 'IN' };
  {
    const ctx = phiCtx('dr-smith', requestIn);
    const v = gate.evaluate(ctx);
    console.log(`Resolved country: ${resolveCountryFromRequest(requestIn)}`);
    console.log(`Verdict kind: ${v.kind}`);
    console.log(`Is refuse:    ${v.isRefuse}`);
    console.log(`Evaluator:    ${v.evaluator}`);
    console.log(`Code:         ${v.code}`);
    auditFromVerdict(chain, 'dr-smith', 'P-1042', v);
    console.log(`Chain length: ${chain.length}`);
    console.log();

    results.push(['Case B: out of country refuses', v.isRefuse]);
    results.push(['Case B: refuse code NO_POLICY_MATCH', v.code === 'NO_POLICY_MATCH']);
    results.push(['Case B: chain length becomes 2', chain.length === 2]);
  }

  // -----------------------------------------------------------------
  // Case C: out of shift.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log("Case C: a second gate with a window that excludes 'now'.");
  console.log('-'.repeat(70));
  console.log('We build a separate gate whose window starts 6 hours in the');
  console.log('future, to simulate dr-smith trying to use a day shift path');
  console.log('in the middle of the night. time_window fails, refuses.');
  console.log();

  const shiftOut = outOfShiftWindow();
  console.log(`out of shift window: ${shiftOut}`);
  const gateOut = Gate.fromObject(buildPolicies(shiftOut) as unknown as Record<string, unknown>);
  {
    const ctx = phiCtx('dr-smith', { trustedCountryHeader: 'US' });
    const v = gateOut.evaluate(ctx);
    console.log(`Verdict kind: ${v.kind}`);
    console.log(`Is refuse:    ${v.isRefuse}`);
    console.log(`Evaluator:    ${v.evaluator}`);
    console.log(`Code:         ${v.code}`);
    auditFromVerdict(chain, 'dr-smith', 'P-2007', v);
    console.log(`Chain length: ${chain.length}`);
    console.log();

    results.push(['Case C: out of shift refuses', v.isRefuse]);
    results.push(['Case C: refuse code NO_POLICY_MATCH', v.code === 'NO_POLICY_MATCH']);
    results.push(['Case C: chain length becomes 3', chain.length === 3]);
  }

  // -----------------------------------------------------------------
  // Case D: 51 call burst.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case D: dr-burst-test fires 51 reads in a row on the in-shift gate.');
  console.log('-'.repeat(70));
  console.log('Rate limit is 50 per hour. We expect 50 permits and 1 refuse.');
  console.log('Each attempt is audited, so the chain grows by 51.');
  console.log();

  const burstPrincipal = 'dr-burst-test';
  const BURST_SIZE = 51;
  let permitCount = 0;
  let refuseCount = 0;
  let lastRefuse: VerdictResult | null = null;
  const burstRequest: Request = { trustedCountryHeader: 'US' };
  for (let i = 0; i < BURST_SIZE; i++) {
    const ctx = phiCtx(burstPrincipal, burstRequest);
    const v = gate.evaluate(ctx);
    auditFromVerdict(chain, burstPrincipal, `P-burst-${String(i).padStart(3, '0')}`, v);
    if (v.isPermit) {
      permitCount++;
    } else if (v.isRefuse) {
      refuseCount++;
      lastRefuse = v;
    }
  }

  console.log(`Permits: ${permitCount}`);
  console.log(`Refuses: ${refuseCount}`);
  console.log(`last refuse code: ${lastRefuse !== null ? lastRefuse.code : null}`);
  console.log(`Chain length: ${chain.length}`);
  console.log();

  results.push(['Case D: 50 permits', permitCount === 50]);
  results.push(['Case D: 1 refuse', refuseCount === 1]);
  results.push([
    'Case D: 51st refuse code NO_POLICY_MATCH',
    lastRefuse !== null && lastRefuse.code === 'NO_POLICY_MATCH',
  ]);
  results.push([
    'Case D: chain length is 3 + 51 = 54',
    chain.length === 3 + BURST_SIZE,
  ]);

  // -----------------------------------------------------------------
  // Case E: export and verify.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case E: export the chain to JSONL and reverify it.');
  console.log('-'.repeat(70));
  console.log('Each line is a PQ-signed audit entry. verifyJsonl hashes and');
  console.log('verifies every line in order. On a clean chain, the verified');
  console.log('count equals chain.length.');
  console.log();

  const jsonl = chain.exportJsonl();
  const verified = SignedAuditChain.verifyJsonl(jsonl, auditBundle);
  let lineCount = 0;
  for (let i = 0; i < jsonl.length; i++) {
    if (jsonl[i] === 0x0a) lineCount++;
  }
  console.log(`JSONL size:       ${jsonl.length} bytes`);
  console.log(`line count:       ${lineCount}`);
  console.log(`verified entries: ${verified}`);
  console.log(`chain.length:     ${chain.length}`);
  console.log();

  const text = jsonl.toString('utf-8');
  const trailingNewline = text.endsWith('\n');
  const firstLineStr = (trailingNewline ? text.slice(0, -1) : text).split('\n')[0]!;
  const firstObj = JSON.parse(firstLineStr) as Record<string, unknown>;
  const signedPayload = firstObj.signed_payload as Record<string, unknown> | undefined;
  console.log('First entry outer shape (truncated):');
  console.log(`  index:                 ${firstObj.index}`);
  console.log(`  previous_hash[:24]:    ${(firstObj.previous_hash as string | undefined ?? '').slice(0, 24)}`);
  console.log(`  entry_hash[:24]:       ${(firstObj.entry_hash as string | undefined ?? '').slice(0, 24)}`);
  console.log(`  signed_payload.key_id: ${signedPayload?.key_id}`);
  console.log();

  results.push(['Case E: verifyJsonl returns chain.length', verified === chain.length]);

  // -----------------------------------------------------------------
  // Case F: tamper entry 2.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case F: flip one byte inside entry 2 and reverify.');
  console.log('-'.repeat(70));
  console.log('Entry 2 is the out of shift refuse from case C. We flip one');
  console.log('byte inside signed_payload.data. The ML-DSA signature no');
  console.log('longer covers the changed bytes, so the chain verifier fails.');
  console.log("The error message should name 'entry 2', so a forensic tool");
  console.log('can point directly at the mutated entry.');
  console.log();

  const targetIdx = 2;

  const flipFirstDataByte = (obj: Record<string, unknown>): void => {
    const payload = obj.signed_payload as Record<string, unknown>;
    const data = payload.data as number[];
    data[0] = (data[0]! + 7) & 0xff;
    payload.data = data;
  };

  const tampered = mutateLine(jsonl, targetIdx, flipFirstDataByte);
  try {
    SignedAuditChain.verifyJsonl(tampered, auditBundle);
    console.log('  verifyJsonl accepted the tampered chain. That is wrong.');
    results.push(['Case F: tampered chain refused', false]);
    results.push(["Case F: error message mentions 'entry 2'", false]);
  } catch (e) {
    const msg = (e as Error).message;
    console.log('  verifyJsonl raised as expected.');
    console.log(`  message: ${msg.slice(0, 220)}`);
    results.push(['Case F: tampered chain refused', true]);
    results.push([
      `Case F: error message references entry ${targetIdx}`,
      msg.includes(`entry ${targetIdx}`),
    ]);
    results.push([
      "Case F: error message names 'signature verification failed'",
      msg.includes('signature verification failed'),
    ]);
  }
  console.log();

  const again = SignedAuditChain.verifyJsonl(jsonl, auditBundle);
  console.log(`  untouched original chain still verifies: ${again} of ${chain.length}`);
  console.log();
  results.push(['Case F: untouched chain still verifies', again === chain.length]);

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

process.exit(main());
