/**
 * Scenario 15: zero-trust agent marketplace with vendor rotation.
 *
 * The story
 * ---------
 * A platform coordinates three vendor agents from different
 * suppliers. Each has its own Kavach keypair. A root keypair signs
 * a manifest listing the three vendor bundles; the orchestrator
 * pins that manifest at startup.
 *
 *     agent-alpha  : billing automation, capped at $250 per call.
 *     agent-beta   : data enrichment, only for US or CA callers.
 *     agent-gamma  : maintenance, only during Pacific day shift.
 *
 * For each vendor call:
 *     1. Central Kavach gate evaluates the request. If it refuses,
 *        no network traffic happens.
 *     2. Orchestrator opens a SecureChannel to the vendor and sends
 *        a signed request.
 *     3. Vendor signs its own PermitToken and returns it.
 *     4. Orchestrator verifies the returned permit against the root
 *        signed directory.
 *
 * We also exercise two ops levers that come built in: an
 * empty-policy kill switch (reload the central gate with ""), and
 * directory rotation (rebuild the manifest without one vendor;
 * their permits stop verifying instantly).
 *
 * Seven cases: A/B/C happy paths per vendor, D/E policy refuses
 * that never reach the channel, F kill switch across all vendors,
 * G directory rotation that kicks beta out.
 *
 * Run this file directly:
 *
 *   node dist/tier3/15_agent_marketplace.js
 */

import { randomUUID } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  DirectoryTokenVerifier,
  Gate,
  KavachKeyPair,
  PqTokenSigner,
  PublicKeyDirectory,
  SecureChannel,
  type EvaluateOptions,
  type PermitTokenInput,
} from 'kavach-sdk';

const ALPHA = 'agent-alpha';
const BETA = 'agent-beta';
const GAMMA = 'agent-gamma';

// Build a shift window string that contains "now" in America/Los_Angeles
// time, matching the Python helper's behaviour.
function shiftWindowNow(): string {
  const fmt = new Intl.DateTimeFormat('en-GB', {
    timeZone: 'America/Los_Angeles',
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
  });
  const now = new Date();
  const fifteenMin = 15 * 60 * 1000;
  const startTime = fmt.format(new Date(now.getTime() - fifteenMin));
  const endTime = fmt.format(new Date(now.getTime() + fifteenMin));
  return `${startTime}-${endTime} America/Los_Angeles`;
}

interface PolicyDoc {
  policies: Array<{
    name: string;
    effect: string;
    priority: number;
    conditions: Array<Record<string, unknown>>;
  }>;
}

function buildPolicies(shiftWindow: string): PolicyDoc {
  return {
    policies: [
      {
        name: 'alpha_billing',
        effect: 'permit',
        priority: 10,
        conditions: [
          { identity_id: ALPHA },
          { action: 'agent.run_task' },
          { param_max: { field: 'amount_usd', max: 250.0 } },
        ],
      },
      {
        name: 'beta_us_fence',
        effect: 'permit',
        priority: 10,
        conditions: [
          { identity_id: BETA },
          { action: 'agent.run_task' },
          { param_in: { field: 'country_code', values: ['US', 'CA'] } },
        ],
      },
      {
        name: 'gamma_day_shift',
        effect: 'permit',
        priority: 10,
        conditions: [
          { identity_id: GAMMA },
          { action: 'agent.run_task' },
          { time_window: shiftWindow },
        ],
      },
    ],
  };
}

// Vendor signs its own PermitToken to return to the orchestrator.
function vendorSignPermit(signer: PqTokenSigner, ttlS = 3600): {
  token: PermitTokenInput;
  signature: Buffer;
} {
  const now = Math.floor(Date.now() / 1000);
  const base: PermitTokenInput = {
    tokenId: randomUUID(),
    evaluationId: randomUUID(),
    issuedAt: now,
    expiresAt: now + ttlS,
    actionName: 'agent.run_task',
  };
  const signature = signer.sign(base);
  return { token: base, signature };
}

function pack(token: PermitTokenInput, signature: Buffer): Buffer {
  return Buffer.from(
    JSON.stringify({
      token_id: token.tokenId,
      evaluation_id: token.evaluationId,
      issued_at: token.issuedAt,
      expires_at: token.expiresAt,
      action_name: token.actionName,
      signature_b64: signature.toString('base64'),
    }),
    'utf-8',
  );
}

function unpack(raw: Buffer): { token: PermitTokenInput; signature: Buffer } {
  const obj = JSON.parse(raw.toString('utf-8'));
  const token: PermitTokenInput = {
    tokenId: obj.token_id,
    evaluationId: obj.evaluation_id,
    issuedAt: obj.issued_at,
    expiresAt: obj.expires_at,
    actionName: obj.action_name,
  };
  const signature = Buffer.from(obj.signature_b64, 'base64');
  return { token, signature };
}

interface RoundTripRequest {
  action: string;
  amount_usd?: number;
  country_code?: string;
  worker_id?: string;
}

function vendorRoundTrip(
  label: string,
  ocChannel: SecureChannel,
  vendorChannel: SecureChannel,
  vendorSigner: PqTokenSigner,
  verifier: DirectoryTokenVerifier,
  request: RoundTripRequest,
): { token: PermitTokenInput; signature: Buffer } {
  // Orchestrator -> vendor -> orchestrator, one round trip. Returns
  // the verified permit.
  const contextId = `orch-${label}-${randomUUID()}`;
  const correlationId = randomUUID();
  const sealedReq = ocChannel.sendSigned(
    Buffer.from(JSON.stringify(request), 'utf-8'),
    contextId,
    correlationId,
  );
  vendorChannel.receiveSigned(sealedReq, contextId);
  const { token: permit, signature } = vendorSignPermit(vendorSigner);
  const sealedPermit = vendorChannel.sendSigned(
    pack(permit, signature),
    contextId,
    `${correlationId}:resp`,
  );
  const { token: returned, signature: returnedSig } = unpack(
    ocChannel.receiveSigned(sealedPermit, contextId),
  );
  verifier.verify(returned, returnedSig);
  console.log(`  ${label}: round trip ok, returned permit ${returned.tokenId}`);
  return { token: returned, signature: returnedSig };
}

interface CtxParams {
  amount_usd?: number;
  country_code?: string;
  worker_id?: string;
}

function buildCtx(agent: string, params: CtxParams = {}): EvaluateOptions {
  const merged: Record<string, number | string> = {};
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined) {
      merged[k] = v;
    }
  }
  return {
    principalId: agent,
    principalKind: 'agent',
    actionName: 'agent.run_task',
    roles: ['agent'],
    params: Object.keys(merged).length > 0 ? merged : undefined,
  };
}

function main(): number {
  console.log('='.repeat(70));
  console.log('Scenario 15: zero-trust agent marketplace with vendor rotation');
  console.log('='.repeat(70));
  console.log();

  // Keypairs.
  const rootKp = KavachKeyPair.generate();
  const orchestratorKp = KavachKeyPair.generate();
  const alphaKp = KavachKeyPair.generate();
  const betaKp = KavachKeyPair.generate();
  const gammaKp = KavachKeyPair.generate();
  const alphaBundle = alphaKp.publicKeys();
  const betaBundle = betaKp.publicKeys();
  const gammaBundle = gammaKp.publicKeys();
  const orchestratorBundle = orchestratorKp.publicKeys();
  console.log(`  root=${rootKp.id}`);
  console.log(`  orchestrator=${orchestratorKp.id}`);
  for (const [name, kp] of [
    ['alpha', alphaKp],
    ['beta', betaKp],
    ['gamma', gammaKp],
  ] as [string, KavachKeyPair][]) {
    console.log(`  ${name}=${kp.id}`);
  }
  console.log();

  // Root signs a v1 manifest with all three vendors.
  const manifestV1 = rootKp.buildSignedManifest([
    alphaBundle,
    betaBundle,
    gammaBundle,
  ]);
  const tmp = mkdtempSync(join(tmpdir(), 'kavach-15-'));
  const manifestPath = join(tmp, 'trusted_vendors.json');
  writeFileSync(manifestPath, manifestV1);
  const directory = PublicKeyDirectory.fromSignedFile(
    manifestPath,
    Buffer.from(rootKp.publicKeys().mlDsaVerifyingKey),
  );
  const verifier = new DirectoryTokenVerifier(directory, false);
  console.log(
    `  manifest_v1: ${manifestV1.length} bytes, directory.length=${directory.length}`,
  );
  console.log();

  // SecureChannels per vendor, both sides.
  const channels: Record<string, [SecureChannel, SecureChannel]> = {
    [ALPHA]: [
      new SecureChannel(orchestratorKp, alphaBundle),
      new SecureChannel(alphaKp, orchestratorBundle),
    ],
    [BETA]: [
      new SecureChannel(orchestratorKp, betaBundle),
      new SecureChannel(betaKp, orchestratorBundle),
    ],
    [GAMMA]: [
      new SecureChannel(orchestratorKp, gammaBundle),
      new SecureChannel(gammaKp, orchestratorBundle),
    ],
  };
  const signers: Record<string, PqTokenSigner> = {
    [ALPHA]: PqTokenSigner.fromKeypairPqOnly(alphaKp),
    [BETA]: PqTokenSigner.fromKeypairPqOnly(betaKp),
    [GAMMA]: PqTokenSigner.fromKeypairPqOnly(gammaKp),
  };

  const gate = Gate.fromObject(buildPolicies(shiftWindowNow()) as unknown as Record<string, unknown>);
  console.log(`  gate.evaluatorCount=${gate.evaluatorCount}`);
  console.log();

  const results: [string, boolean][] = [];
  const permits: Record<string, { token: PermitTokenInput; signature: Buffer }> = {};

  // --- Cases A/B/C: three vendor happy paths.
  console.log('Cases A/B/C: one happy round trip per vendor.');
  const callSpecs: Array<[string, string, EvaluateOptions, RoundTripRequest]> = [
    [
      'A',
      ALPHA,
      buildCtx(ALPHA, { amount_usd: 100.0 }),
      { action: 'agent.run_task', amount_usd: 100.0 },
    ],
    [
      'B',
      BETA,
      buildCtx(BETA, { country_code: 'US' }),
      { action: 'agent.run_task', country_code: 'US' },
    ],
    [
      'C',
      GAMMA,
      buildCtx(GAMMA),
      { action: 'agent.run_task', worker_id: 'gamma-07' },
    ],
  ];
  for (const [caseId, agent, ctx, req] of callSpecs) {
    const v = gate.evaluate(ctx);
    console.log(`  Case ${caseId}: gate.${v.kind} for ${agent}`);
    results.push([`Case ${caseId}: gate permits ${agent}`, v.isPermit]);
    if (v.isPermit) {
      const [oc, ac] = channels[agent]!;
      const permit = vendorRoundTrip(
        `Case ${caseId}/${agent}`,
        oc,
        ac,
        signers[agent]!,
        verifier,
        req,
      );
      permits[agent] = permit;
      results.push([
        `Case ${caseId}: permit round trips with correct actionName`,
        permit.token.actionName === 'agent.run_task',
      ]);
    }
  }
  console.log();

  // --- Cases D/E: policy refuses, no channel.
  console.log('Case D: alpha $500 (over $250 cap).');
  {
    const v = gate.evaluate(buildCtx(ALPHA, { amount_usd: 500.0 }));
    console.log(`  ${v.kind}  evaluator=${v.evaluator}  code=${v.code}`);
    results.push([
      'Case D: alpha $500 refuses on policy',
      v.isRefuse && v.evaluator === 'policy',
    ]);
  }
  console.log();

  console.log('Case E: beta country_code=RU (not in US/CA allow list).');
  {
    const v = gate.evaluate(buildCtx(BETA, { country_code: 'RU' }));
    console.log(`  ${v.kind}  evaluator=${v.evaluator}  code=${v.code}`);
    results.push([
      'Case E: beta RU refuses on policy',
      v.isRefuse && v.evaluator === 'policy',
    ]);
  }
  console.log();

  // --- Case F: kill switch.
  console.log('Case F: kill switch. Reload gate with empty string.');
  gate.reload('');
  const budgetMs = 200.0;
  for (const [name, ctx] of [
    ['alpha', buildCtx(ALPHA, { amount_usd: 100.0 })],
    ['beta', buildCtx(BETA, { country_code: 'US' })],
    ['gamma', buildCtx(GAMMA)],
  ] as [string, EvaluateOptions][]) {
    const t0 = process.hrtime.bigint();
    const v = gate.evaluate(ctx);
    const elapsed = Number(process.hrtime.bigint() - t0) / 1_000_000;
    console.log(`  ${name}: ${v.kind}  code=${v.code}  elapsed=${elapsed.toFixed(3)}ms`);
    results.push([`Case F: ${name} refuses after empty reload`, v.isRefuse]);
    results.push([`Case F: ${name} under ${Math.trunc(budgetMs)}ms`, elapsed < budgetMs]);
  }
  console.log();

  // --- Case G: directory rotation, beta removed.
  console.log('Case G: operator removes beta, rebuilds manifest, reloads directory.');
  const manifestV2 = rootKp.buildSignedManifest([alphaBundle, gammaBundle]);
  writeFileSync(manifestPath, manifestV2);
  directory.reload();
  console.log(`  directory.length now ${directory.length}`);
  results.push([
    'Case G: directory length 2 after rotation',
    directory.length === 2,
  ]);

  let refused = false;
  try {
    const p = permits[BETA]!;
    verifier.verify(p.token, p.signature);
  } catch (e) {
    const msg = (e as Error).message;
    refused = msg.includes('public key not found');
    console.log(`  beta verify raised: ${msg.slice(0, 140)}`);
  }
  results.push(['Case G: beta permit refused after rotation', refused]);

  for (const [name, key] of [
    ['alpha', ALPHA],
    ['gamma', GAMMA],
  ] as [string, string][]) {
    let ok = true;
    try {
      const p = permits[key]!;
      verifier.verify(p.token, p.signature);
    } catch {
      ok = false;
    }
    console.log(`  ${name} permit still verifies: ${ok}`);
    results.push([`Case G: ${name} permit still verifies`, ok]);
  }
  console.log();

  // --- Summary.
  console.log('='.repeat(70));
  console.log('Summary');
  console.log('='.repeat(70));
  const passed = results.filter(([, ok]) => ok).length;
  for (const [label, ok] of results) {
    console.log(`  [${ok ? 'PASS' : 'FAIL'}] ${label}`);
  }
  console.log();
  console.log(`${passed}/${results.length} checks passed.`);
  console.log();
  return passed === results.length ? 0 : 1;
}

process.exit(main());
