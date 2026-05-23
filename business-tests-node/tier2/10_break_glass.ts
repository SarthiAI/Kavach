/**
 * Scenario 10: break glass emergency prod console access.
 *
 * The story
 * ---------
 * A SaaS company locks down production almost all the time. The only
 * way an on call SRE can pop a shell on a prod database host is through
 * a break glass flow. The business wants three things from that flow:
 *
 *     1. Only a currently on call SRE can even attempt it. People not
 *        on rotation get refused immediately, no matter how senior.
 *
 *     2. Every attempt is pinned to a live incident ticket. The caller
 *        has to pass the incident id as a param, and the ticket id has
 *        to sit inside the company's active incident window. This
 *        prevents "I'll just claim there was an incident last Tuesday"
 *        after the fact.
 *
 *     3. A hard rate limit of 3 attempts per hour per SRE, because
 *        real break glass is rare. More than three in an hour almost
 *        always means an automation gone wrong or someone poking at
 *        the gate.
 *
 * And two things from the pipeline around it:
 *
 *     4. Every granted permit is signed by the Auth service using an
 *        ML-DSA-65 keypair. Infrastructure receives the permit, looks
 *        up the Auth bundle in a root signed directory, verifies the
 *        signature, and only then opens the session. This keeps prod
 *        console access to "only things Auth permitted in the last
 *        few seconds", no shared secrets on disk.
 *
 *     5. Every attempt, permitted or refused, is appended to a signed
 *        audit chain so the security team can replay the week during
 *        post incident review. The chain is hash linked, so tamper in
 *        the middle is detected by the verifier and points at the
 *        exact entry that was touched.
 *
 * Five cases:
 *
 *     A. On call SRE, valid open incident, first attempt. PERMIT, the
 *        permit is signed, Infrastructure verifies, session opens.
 *     B. Senior engineer NOT on call tries. REFUSE on identity role.
 *     C. On call SRE with a fabricated incident id (not in the active
 *        set). REFUSE on identity. Policy rule does not match because
 *        the param_in on incident_id fails.
 *     D. Fourth attempt in the same hour. REFUSE on rate.
 *     E. After the dust settles, export the audit chain to JSONL,
 *        reverify it, and then tamper one byte inside entry 2 to show
 *        the verifier names the exact broken entry.
 *
 * Run this file directly:
 *
 *   node dist/tier2/10_break_glass.js
 */

import {
  AuditEntry,
  DirectoryTokenVerifier,
  Gate,
  KavachKeyPair,
  PqTokenSigner,
  PublicKeyDirectory,
  SignedAuditChain,
  type EvaluateOptions,
  type Verdict,
} from 'kavach-sdk';
import { mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// ---------------------------------------------------------------------
// Step 1. Policy. One permit rule, four conditions.
// ---------------------------------------------------------------------
// identity_role = sre_on_call. Carried as a runtime role by an
// identity provider that knows who is actually paging at this minute.
//
// action = infra.break_glass_session.
//
// param_in on incident_id restricts accepted ids to the currently
// open incident set. A fabricated id or an id for an already closed
// incident fails this check and the rule does not match.
//
// rate_limit = 3 per hour. Break glass is not something anyone runs
// at volume; 3 is plenty of headroom for real incidents.
// ---------------------------------------------------------------------

const OPEN_INCIDENTS = ['INC-2026-0418-payments', 'INC-2026-0418-auth'];

const POLICIES = {
  policies: [
    {
      name: 'sre_break_glass',
      description: 'On call SRE may open a break glass session against a live incident',
      effect: 'permit',
      priority: 10,
      conditions: [
        { identity_role: 'sre_on_call' },
        { action: 'infra.break_glass_session' },
        { param_in: { field: 'incident_id', values: OPEN_INCIDENTS } },
        { rate_limit: { max: 3, window: '1h' } },
      ],
    },
  ],
};

function breakGlassCtx(
  principalId: string,
  roles: string[],
  incidentId: string,
): EvaluateOptions {
  return {
    principalId: principalId,
    principalKind: 'user',
    actionName: 'infra.break_glass_session',
    roles: roles,
    resource: 'prod/region-use1/db-primary',
    params: {
      incident_id: incidentId,
    },
  };
}

function auditFromVerdict(
  chain: SignedAuditChain,
  principalId: string,
  incidentId: string,
  verdict: Verdict,
): void {
  const detail = JSON.stringify({
    incident_id: incidentId,
    evaluator: verdict.evaluator ?? null,
    code: verdict.code ?? null,
    reason: verdict.reason ?? null,
  });
  chain.append(
    AuditEntry.new(
      principalId,
      'infra.break_glass_session',
      verdict.kind,
      detail,
    ),
  );
}

function mutateLine(
  jsonl: Buffer,
  idx: number,
  mutator: (obj: Record<string, unknown>) => void,
): Buffer {
  // Load, mutate, and re-serialise a single JSONL line so we can
  // build a deliberately broken blob for the tamper test.
  const endsWithNewline = jsonl.length > 0 && jsonl[jsonl.length - 1] === 0x0a;
  const text = jsonl.toString('utf-8');
  const lines = text.split('\n');
  // Drop trailing empty token if the blob ends with a newline.
  if (endsWithNewline && lines.length > 0 && lines[lines.length - 1] === '') {
    lines.pop();
  }
  const obj = JSON.parse(lines[idx]!) as Record<string, unknown>;
  mutator(obj);
  lines[idx] = JSON.stringify(obj);
  let out = lines.join('\n');
  if (endsWithNewline) out += '\n';
  return Buffer.from(out, 'utf-8');
}

function main(): number {
  console.log('='.repeat(70));
  console.log('Scenario 10: break glass emergency prod console access');
  console.log('='.repeat(70));
  console.log();
  console.log('We are going to set up an Auth service that signs break glass');
  console.log('permits, an Infrastructure service that verifies them against');
  console.log('a root signed directory, and a signed audit chain that records');
  console.log('every attempt. Then we walk five real cases through it.');
  console.log();

  const results: [string, boolean][] = [];

  // -----------------------------------------------------------------
  // Keypairs: one for Auth (signs permits), one for the directory
  // root (signs the list of trusted Auth bundles), and one for the
  // audit chain.
  // -----------------------------------------------------------------
  console.log('Generating three keypairs.');
  const authKp = KavachKeyPair.generate();
  const rootKp = KavachKeyPair.generate();
  const auditKp = KavachKeyPair.generate();
  const authBundle = authKp.publicKeys();
  const rootBundle = rootKp.publicKeys();
  console.log(`  auth.key_id:  ${authKp.id}`);
  console.log(`  root.key_id:  ${rootKp.id}`);
  console.log(`  audit.key_id: ${auditKp.id}`);
  console.log();

  // -----------------------------------------------------------------
  // Directory: the root signs a manifest that says "Auth's bundle is
  // trusted". Infrastructure pins the root verifying key, loads the
  // manifest, and now trusts Auth's bundle.
  // -----------------------------------------------------------------
  console.log('Building a root signed directory and loading it into Infrastructure.');
  const manifestBytes = rootKp.buildSignedManifest([authBundle]);
  const tmp = mkdtempSync(join(tmpdir(), 'kavach-17-'));
  const manifestPath = join(tmp, 'trusted_signers.json');
  writeFileSync(manifestPath, manifestBytes);
  const directory = PublicKeyDirectory.fromSignedFile(
    manifestPath,
    rootBundle.mlDsaVerifyingKey,
  );
  const verifier = new DirectoryTokenVerifier(directory, false);
  console.log(`  manifest path:      ${manifestPath}`);
  console.log(`  directory.length:   ${directory.length}`);
  console.log(`  directory.isEmpty:  ${directory.isEmpty}`);
  console.log();

  // -----------------------------------------------------------------
  // Audit chain.
  // -----------------------------------------------------------------
  console.log('Opening the audit chain (PQ only signing).');
  const chain = new SignedAuditChain(auditKp, false);
  console.log(`  chain.isHybrid:  ${chain.isHybrid}`);
  console.log(`  chain.length:    ${chain.length}`);
  console.log(`  chain.headHash:  ${chain.headHash}`);
  console.log();

  // -----------------------------------------------------------------
  // Auth gate.
  // -----------------------------------------------------------------
  console.log("Building Auth's gate with its token signer attached.");
  const signer = PqTokenSigner.fromKeypairPqOnly(authKp);
  const gate = Gate.fromObject(POLICIES, { tokenSigner: signer });
  console.log(`  gate.evaluatorCount: ${gate.evaluatorCount}`);
  console.log(`  signer.keyId:        ${signer.keyId}`);
  console.log();

  // -----------------------------------------------------------------
  // Case A: on call SRE, valid incident, first attempt.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case A: on call SRE Maya opens a shell for INC-2026-0418-payments.');
  console.log('-'.repeat(70));
  console.log("Role is 'sre_on_call'. Incident id is in the active set. The");
  console.log('rate bucket is fresh. Auth permits and signs the permit.');
  console.log('Infrastructure calls verifier.verify(permit, permit.signature)');
  console.log('and accepts. The audit chain records the permit.');
  console.log();

  let ctx = breakGlassCtx('sre-maya', ['sre_on_call'], 'INC-2026-0418-payments');
  let v = gate.evaluate(ctx);
  auditFromVerdict(chain, 'sre-maya', 'INC-2026-0418-payments', v);

  console.log(`Auth verdict:      ${v.kind}`);
  console.log(`Is permit:         ${v.isPermit}`);
  console.log(`Permit token id:   ${v.tokenId}`);
  const token = v.permitToken;

  let signatureOk = false;
  if (token && token.signature) {
    try {
      verifier.verify(
        {
          tokenId: token.tokenId,
          evaluationId: token.evaluationId,
          issuedAt: token.issuedAt,
          expiresAt: token.expiresAt,
          actionName: token.actionName,
        },
        token.signature,
      );
      signatureOk = true;
      console.log('Infrastructure.verify(): accepted.');
    } catch (e) {
      console.log(`Infrastructure.verify() raised unexpectedly: ${(e as Error).name}: ${(e as Error).message}`);
    }
  }
  console.log(`Chain length:      ${chain.length}`);
  console.log();

  results.push(['Case A: on call SRE gets a permit', v.isPermit]);
  results.push(['Case A: Infrastructure verifies the signature', signatureOk]);

  // -----------------------------------------------------------------
  // Case B: not on call, refuse.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case B: senior engineer Dev-Ravi tries break glass. Not on call.');
  console.log('-'.repeat(70));
  console.log("Ravi's identity provider carries the role 'senior_engineer',");
  console.log("not 'sre_on_call'. The rule does not match, default deny");
  console.log('refuses. No permit is issued. The audit chain still records');
  console.log('the attempt so the post incident review shows who tried what.');
  console.log();

  ctx = breakGlassCtx('dev-ravi', ['senior_engineer'], 'INC-2026-0418-payments');
  v = gate.evaluate(ctx);
  auditFromVerdict(chain, 'dev-ravi', 'INC-2026-0418-payments', v);

  console.log(`Auth verdict: ${v.kind}`);
  console.log(`Is refuse:    ${v.isRefuse}`);
  console.log(`Evaluator:    ${v.evaluator}`);
  console.log(`Code:         ${v.code}`);
  console.log(`Chain length: ${chain.length}`);
  console.log();

  let ok = v.isRefuse && v.evaluator === 'policy' && v.code === 'NO_POLICY_MATCH';
  results.push(['Case B: off rotation engineer refused', ok]);

  // -----------------------------------------------------------------
  // Case C: on call, but the incident id is not in the active set.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log("Case C: on call SRE, incident id 'INC-LAST-WEEK' (already closed).");
  console.log('-'.repeat(70));
  console.log('Role is right, action is right, but param_in on incident_id');
  console.log('only allows the two currently open incidents. A closed id');
  console.log('fails the check and the rule does not match. Refuse.');
  console.log();

  ctx = breakGlassCtx('sre-maya', ['sre_on_call'], 'INC-LAST-WEEK');
  v = gate.evaluate(ctx);
  auditFromVerdict(chain, 'sre-maya', 'INC-LAST-WEEK', v);

  console.log(`Auth verdict: ${v.kind}`);
  console.log(`Is refuse:    ${v.isRefuse}`);
  console.log(`Evaluator:    ${v.evaluator}`);
  console.log(`Code:         ${v.code}`);
  console.log(`Chain length: ${chain.length}`);
  console.log();

  ok = v.isRefuse && v.evaluator === 'policy' && v.code === 'NO_POLICY_MATCH';
  results.push(['Case C: closed incident id refused', ok]);

  // -----------------------------------------------------------------
  // Case D: rate limit burst on a fresh gate so the rate bucket is
  // isolated from the earlier cases. We fire four attempts in a row
  // and expect the first three to permit, the fourth to refuse.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case D: fresh gate, Rahul fires 4 break glass attempts in a row.');
  console.log('-'.repeat(70));
  console.log('We build a fresh gate so the rate bucket is independent of');
  console.log('the attempts in cases A, B, and C (clean isolation). The rate');
  console.log('limit is 3 per hour per SRE. We expect the first three calls');
  console.log('to permit and the fourth to refuse on the rate condition.');
  console.log('Each of the four attempts still gets audited in the main chain.');
  console.log();

  const burstGate = Gate.fromObject(POLICIES, { tokenSigner: signer });
  let permitCount = 0;
  let refuseCount = 0;
  let lastRefuse: Verdict | null = null;
  for (let i = 0; i < 4; i++) {
    const burstCtx = breakGlassCtx('sre-rahul', ['sre_on_call'], 'INC-2026-0418-auth');
    const bv = burstGate.evaluate(burstCtx);
    auditFromVerdict(chain, 'sre-rahul', 'INC-2026-0418-auth', bv);
    console.log(`  attempt ${i + 1}: ${bv.kind}`);
    if (bv.isPermit) {
      permitCount += 1;
    } else {
      refuseCount += 1;
      lastRefuse = bv;
    }
  }

  console.log(`Permits: ${permitCount}`);
  console.log(`Refuses: ${refuseCount}`);
  console.log(`Last refuse evaluator: ${lastRefuse ? lastRefuse.evaluator : null}`);
  console.log(`Chain length after the burst: ${chain.length}`);
  console.log();

  ok = permitCount === 3 && refuseCount === 1;
  results.push(['Case D: 3 permit, 4th refuses on rate', ok]);

  // -----------------------------------------------------------------
  // Case E: export the chain, reverify, tamper, reverify.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case E: export the chain, reverify, tamper, reverify again.');
  console.log('-'.repeat(70));
  console.log('Exports the whole chain to JSONL bytes, one entry per line.');
  console.log("Reverify against the audit bundle's public keys. Then mutate");
  console.log('entry 2 (zero indexed) inside the JSONL blob and reverify,');
  console.log('expecting the verifier to raise and name the exact entry that');
  console.log('was touched. This is the property the compliance team relies');
  console.log('on: if one line in the audit log was changed after the fact,');
  console.log('we know exactly which one.');
  console.log();

  const jsonl = chain.exportJsonl();
  const lineCount = jsonl
    .toString('utf-8')
    .split('\n')
    .filter((s) => s.length > 0).length;
  console.log(`JSONL bytes length: ${jsonl.length}`);
  console.log(`JSONL line count:   ${lineCount}`);
  console.log(`Chain length:       ${chain.length}`);

  const auditBundle = auditKp.publicKeys();

  let cleanCount = -1;
  try {
    cleanCount = SignedAuditChain.verifyJsonl(jsonl, auditBundle);
    console.log(`Clean reverify: passed (${cleanCount} entries verified).`);
  } catch (e) {
    console.log(`Clean reverify raised unexpectedly: ${(e as Error).name}: ${(e as Error).message}`);
  }
  console.log();

  results.push([
    'Case E: exported chain reverifies cleanly',
    cleanCount === chain.length,
  ]);
  results.push([
    'Case E: line count matches chain length',
    lineCount === chain.length,
  ]);

  // Pick an entry inside the body to mutate. signed_payload.data is
  // a list of bytes (integers 0 to 255) as JSONL serialises it. We
  // flip the first byte, which breaks the ML-DSA signature on that
  // entry without breaking the surrounding JSON.
  const flipFirstDataByte = (obj: Record<string, unknown>): void => {
    const payload = obj['signed_payload'] as Record<string, unknown>;
    const data = (payload['data'] as number[]).slice();
    data[0] = (data[0]! + 7) & 0xff;
    payload['data'] = data;
  };

  const tampered = mutateLine(jsonl, 2, flipFirstDataByte);
  console.log("Mutating one byte inside entry 2's signed payload and reverifying.");
  let tamperRefused = false;
  let tamperMessage = '';
  try {
    SignedAuditChain.verifyJsonl(tampered, auditBundle);
  } catch (e) {
    tamperRefused = true;
    tamperMessage = (e as Error).message;
  }
  console.log(`  raised: ${tamperRefused}`);
  console.log(`  message (first 220 chars): ${tamperMessage.slice(0, 220)}`);
  console.log();

  ok =
    tamperRefused &&
    (tamperMessage.toLowerCase().includes('entry') || tamperMessage.includes('2'));
  results.push(['Case E: tampered entry 2 is refused', ok]);

  // -----------------------------------------------------------------
  // Summary
  // -----------------------------------------------------------------
  console.log('='.repeat(70));
  console.log('Summary');
  console.log('='.repeat(70));
  const passed = results.filter(([, k]) => k).length;
  for (const [label, k] of results) {
    const mark = k ? 'PASS' : 'FAIL';
    console.log(`  [${mark}] ${label}`);
  }
  console.log();
  console.log(`${passed}/${results.length} checks passed.`);
  console.log();

  return passed === results.length ? 0 : 1;
}

process.exit(main());
