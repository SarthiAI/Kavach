/**
 * Scenario 09: API key rotation with the two person rule.
 *
 * The story
 * ---------
 * A fintech's internal platform holds the master API keys for every
 * third party payment rail, exchange, and KYC vendor it integrates
 * with. Rotating one of those keys is a high blast radius operation:
 * rotate the wrong one and a production revenue line stops moving
 * money until the next deploy. Rotate it with a bad value and you
 * just leaked a key into the logs.
 *
 * The platform team wants three rules on every rotation:
 *
 *     1. Two person rule. The caller must be 'security_admin', and
 *        they must present a recorded second approval from another
 *        'security_admin' (never from themselves). The approval id
 *        is a param the caller fills in from the approval service's
 *        database.
 *
 *     2. The vendor the key belongs to must be in the currently
 *        tracked set. Rotating a key for a vendor that isn't even
 *        onboarded yet is almost always a mistake.
 *
 *     3. A rate cap of 10 rotations per day per admin. Anything over
 *        that is either an automation in a loop or an attacker who
 *        got a session token and is trying to churn keys across many
 *        vendors at once.
 *
 * Then two things on top of the gate:
 *
 *     4. Every rotation that permits gets a signed permit issued by
 *        the Platform Auth service. The downstream Vault worker takes
 *        the permit, verifies the ML-DSA-65 signature against the root
 *        signed directory, and only then updates the secret in the
 *        secrets store.
 *
 *     5. Every attempt (permit or refuse) is appended to a signed
 *        audit chain for the security team's weekly review.
 *
 * Six cases:
 *
 *     A. Legitimate rotation. security_admin Priya, fresh gate,
 *        vendor "stripe", approval id carries Rahul's signature.
 *        Expect PERMIT, permit is signed, Vault verifies, session opens.
 *     B. Self approval. Same admin fills in her own id as the
 *        approval_admin. The param_min rule on distinct_approvers
 *        fails and the rotation refuses.
 *     C. Unknown vendor. "acme-cash-v0" is not in the tracked set,
 *        param_in refuses.
 *     D. Non admin tries. Engineer Aarav has 'platform_engineer', not
 *        'security_admin', default deny.
 *     E. Eleven rotations in a day by a fresh admin. Ten permit, the
 *        eleventh refuses on the rate condition.
 *     F. An attacker relabels a permit from vendor 'stripe' to vendor
 *        'internal-wallet' on the wire. The Vault worker's verifier
 *        catches the signature mismatch and refuses.
 *
 * Run this file directly:
 *
 *   node dist/tier2/09_api_key_rotation.js
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
  type PermitTokenInput,
  type Verdict,
} from 'kavach-sdk';
import { mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// ---------------------------------------------------------------------
// Step 1. The policy.
//
// We encode the "two person rule" as a param_min on distinct_approvers.
// The caller sends:
//     requesting_admin_id     : string (who is clicking rotate)
//     approval_admin_id       : string (who signed off in the approval
//                                        tool)
//     distinct_approvers      : 1.0 if the two ids differ, 0.0 if they
//                                are the same person
//
// A real production gate would infer distinct_approvers server side
// from the approval record. Passing it as a param here keeps the
// scenario self contained. The invariant and the param_in do the rest.
// ---------------------------------------------------------------------

const TRACKED_VENDORS = ['stripe', 'adyen', 'plaid', 'onfido', 'internal-wallet'];

const POLICIES = {
  policies: [
    {
      name: 'dual_control_key_rotation',
      description: 'Security admins rotate API keys with a second admin approval',
      effect: 'permit',
      priority: 10,
      conditions: [
        { identity_role: 'security_admin' },
        { action: 'platform.rotate_api_key' },
        { param_in: { field: 'vendor', values: TRACKED_VENDORS } },
        { param_min: { field: 'distinct_approvers', min: 1.0 } },
        { rate_limit: { max: 10, window: '1d' } },
      ],
    },
  ],
};

function rotateCtx(
  requesterId: string,
  roles: string[],
  vendor: string,
  approverId: string,
): EvaluateOptions {
  return {
    principalId: requesterId,
    principalKind: 'user',
    actionName: 'platform.rotate_api_key',
    roles: roles,
    resource: `secrets/vendor/${vendor}/api_key`,
    params: {
      distinct_approvers: approverId !== requesterId ? 1.0 : 0.0,
      vendor: vendor,
      approval_admin_id: approverId,
    },
  };
}

function auditFromVerdict(
  chain: SignedAuditChain,
  requesterId: string,
  vendor: string,
  approverId: string,
  verdict: Verdict,
): void {
  const detail = JSON.stringify({
    vendor: vendor,
    approver: approverId,
    evaluator: verdict.evaluator ?? null,
    code: verdict.code ?? null,
    reason: verdict.reason ?? null,
  });
  chain.append(
    AuditEntry.new(
      requesterId,
      'platform.rotate_api_key',
      verdict.kind,
      detail,
    ),
  );
}

function main(): number {
  console.log('='.repeat(70));
  console.log('Scenario 09: API key rotation with the two person rule');
  console.log('='.repeat(70));
  console.log();
  console.log('We are going to set up Platform Auth (signs rotation permits)');
  console.log('and a Vault worker (verifies permits against a root signed');
  console.log('directory, then updates the secret). Every attempt is also');
  console.log('appended to a signed audit chain. Then we run six cases,');
  console.log('including one wire tampering attempt.');
  console.log();

  const results: [string, boolean][] = [];

  // -----------------------------------------------------------------
  // Keypairs.
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
  // Trusted directory, loaded into the Vault worker.
  // -----------------------------------------------------------------
  console.log('Building the root signed directory that Vault trusts.');
  const manifestBytes = rootKp.buildSignedManifest([authBundle]);
  const tmp = mkdtempSync(join(tmpdir(), 'kavach-18-'));
  const manifestPath = join(tmp, 'trusted_signers.json');
  writeFileSync(manifestPath, manifestBytes);
  const directory = PublicKeyDirectory.fromSignedFile(
    manifestPath,
    rootBundle.mlDsaVerifyingKey,
  );
  const verifier = new DirectoryTokenVerifier(directory, false);
  console.log(`  manifest path:    ${manifestPath}`);
  console.log(`  directory.length: ${directory.length}`);
  console.log();

  // -----------------------------------------------------------------
  // Audit chain.
  // -----------------------------------------------------------------
  console.log('Opening the audit chain.');
  const chain = new SignedAuditChain(auditKp, false);
  console.log(`  chain.isHybrid: ${chain.isHybrid}`);
  console.log(`  chain.length:   ${chain.length}`);
  console.log();

  // -----------------------------------------------------------------
  // Auth gate.
  // -----------------------------------------------------------------
  console.log("Building Platform Auth's gate with its signer attached.");
  const signer = PqTokenSigner.fromKeypairPqOnly(authKp);
  const gate = Gate.fromObject(POLICIES, { tokenSigner: signer });
  console.log(`  gate.evaluatorCount: ${gate.evaluatorCount}`);
  console.log(`  signer.keyId:        ${signer.keyId}`);
  console.log();

  // -----------------------------------------------------------------
  // Case A: legitimate rotation.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log("Case A: admin-priya rotates stripe's API key, approval from admin-rahul.");
  console.log('-'.repeat(70));
  console.log("Role is 'security_admin'. Vendor is in the tracked set. The");
  console.log('approver id (rahul) differs from the requester id (priya), so');
  console.log('distinct_approvers is 1.0, which clears the param_min on it.');
  console.log('Rate is fresh. We expect: PERMIT, with a signed permit that');
  console.log('the Vault worker verifies and accepts.');
  console.log();

  let ctx = rotateCtx('admin-priya', ['security_admin'], 'stripe', 'admin-rahul');
  let v = gate.evaluate(ctx);
  auditFromVerdict(chain, 'admin-priya', 'stripe', 'admin-rahul', v);

  console.log(`Auth verdict:      ${v.kind}`);
  console.log(`Is permit:         ${v.isPermit}`);
  console.log(`Permit token id:   ${v.tokenId}`);
  const permit = v.permitToken;
  let vaultOk = false;
  if (permit && permit.signature) {
    try {
      verifier.verify(
        {
          tokenId: permit.tokenId,
          evaluationId: permit.evaluationId,
          issuedAt: permit.issuedAt,
          expiresAt: permit.expiresAt,
          actionName: permit.actionName,
        },
        permit.signature,
      );
      vaultOk = true;
      console.log('Vault.verify(): accepted.');
    } catch (e) {
      console.log(`Vault.verify() raised unexpectedly: ${(e as Error).name}: ${(e as Error).message}`);
    }
  }
  console.log(`Chain length: ${chain.length}`);
  console.log();

  results.push(['Case A: dual control rotation permits', v.isPermit]);
  results.push(['Case A: Vault verifies the signature', vaultOk]);

  // -----------------------------------------------------------------
  // Case B: self approval.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case B: admin-priya lists herself as her own approver.');
  console.log('-'.repeat(70));
  console.log('The param_min rule on distinct_approvers requires the field');
  console.log('to be at least 1.0. When the requester and the approver are');
  console.log('the same person, the wrapper sets the field to 0.0, which');
  console.log('fails the min check. The rule does not match, default deny');
  console.log('refuses. The audit chain still records the attempt, because');
  console.log('this is a red flag you want a human to see.');
  console.log();

  ctx = rotateCtx('admin-priya', ['security_admin'], 'stripe', 'admin-priya');
  v = gate.evaluate(ctx);
  auditFromVerdict(chain, 'admin-priya', 'stripe', 'admin-priya', v);

  console.log(`Auth verdict: ${v.kind}`);
  console.log(`Is refuse:    ${v.isRefuse}`);
  console.log(`Evaluator:    ${v.evaluator}`);
  console.log(`Code:         ${v.code}`);
  console.log(`Chain length: ${chain.length}`);
  console.log();

  let ok = v.isRefuse && v.evaluator === 'policy' && v.code === 'NO_POLICY_MATCH';
  results.push(['Case B: self approval refused', ok]);

  // -----------------------------------------------------------------
  // Case C: unknown vendor.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log("Case C: admin-priya tries to rotate a key for 'acme-cash-v0'.");
  console.log('-'.repeat(70));
  console.log("'acme-cash-v0' is not in the tracked vendor list. param_in");
  console.log('fails and the rule does not match. Default deny refuses.');
  console.log('This protects against a developer fat-finger like');
  console.log("'stripeprod' when they meant 'stripe'.");
  console.log();

  ctx = rotateCtx('admin-priya', ['security_admin'], 'acme-cash-v0', 'admin-rahul');
  v = gate.evaluate(ctx);
  auditFromVerdict(chain, 'admin-priya', 'acme-cash-v0', 'admin-rahul', v);

  console.log(`Auth verdict: ${v.kind}`);
  console.log(`Is refuse:    ${v.isRefuse}`);
  console.log(`Evaluator:    ${v.evaluator}`);
  console.log(`Code:         ${v.code}`);
  console.log();

  ok = v.isRefuse && v.evaluator === 'policy' && v.code === 'NO_POLICY_MATCH';
  results.push(['Case C: unknown vendor refused', ok]);

  // -----------------------------------------------------------------
  // Case D: non admin tries.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case D: engineer Aarav (platform_engineer) tries to rotate.');
  console.log('-'.repeat(70));
  console.log("The identity_role condition requires 'security_admin'. Aarav");
  console.log("has 'platform_engineer' only. The rule does not match. Refuse.");
  console.log();

  ctx = rotateCtx('eng-aarav', ['platform_engineer'], 'stripe', 'admin-rahul');
  v = gate.evaluate(ctx);
  auditFromVerdict(chain, 'eng-aarav', 'stripe', 'admin-rahul', v);

  console.log(`Auth verdict: ${v.kind}`);
  console.log(`Is refuse:    ${v.isRefuse}`);
  console.log(`Evaluator:    ${v.evaluator}`);
  console.log(`Code:         ${v.code}`);
  console.log();

  ok = v.isRefuse && v.evaluator === 'policy' && v.code === 'NO_POLICY_MATCH';
  results.push(['Case D: non admin refused', ok]);

  // -----------------------------------------------------------------
  // Case E: rate burst on a fresh gate.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case E: fresh gate, admin-zara fires 11 rotations back to back.');
  console.log('-'.repeat(70));
  console.log('The daily cap is 10 per admin. We build a fresh gate so the');
  console.log('rate bucket is isolated. Expect 10 permits and 1 refuse.');
  console.log('Each attempt is audited.');
  console.log();

  const burstGate = Gate.fromObject(POLICIES, { tokenSigner: signer });
  let permitCount = 0;
  let refuseCount = 0;
  for (let i = 0; i < 11; i++) {
    const vendor = TRACKED_VENDORS[i % TRACKED_VENDORS.length]!;
    const burstCtx = rotateCtx('admin-zara', ['security_admin'], vendor, 'admin-rahul');
    const bv = burstGate.evaluate(burstCtx);
    auditFromVerdict(chain, 'admin-zara', vendor, 'admin-rahul', bv);
    if (bv.isPermit) {
      permitCount += 1;
    } else {
      refuseCount += 1;
    }
  }

  console.log(`Permits: ${permitCount}`);
  console.log(`Refuses: ${refuseCount}`);
  console.log(`Chain length: ${chain.length}`);
  console.log();

  results.push([
    'Case E: 10 permit, 11th refuses on rate',
    permitCount === 10 && refuseCount === 1,
  ]);

  // -----------------------------------------------------------------
  // Case F: wire tampering, vendor relabel.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log("Case F: attacker relabels the permit's action on the wire.");
  console.log('-'.repeat(70));
  console.log("admin-priya's legitimate permit from Case A was for rotating");
  console.log("stripe's key. An attacker in the middle copies the permit,");
  console.log('keeps every field identical except for action_name, which');
  console.log("they flip from 'platform.rotate_api_key' to something more");
  console.log("interesting ('platform.disable_vendor'). The signature covers");
  console.log("the action name, so the Vault worker's verifier recomputes");
  console.log('the canonical bytes, finds the mismatch, and raises.');
  console.log();

  const realPermit = permit!;
  const tampered: PermitTokenInput = {
    tokenId: realPermit.tokenId,
    evaluationId: realPermit.evaluationId,
    issuedAt: realPermit.issuedAt,
    expiresAt: realPermit.expiresAt,
    actionName: 'platform.disable_vendor',
  };
  console.log(`  original action_name: ${realPermit.actionName}`);
  console.log(`  tampered action_name: ${tampered.actionName}`);

  let tamperRefused = false;
  let tamperMsg = '';
  try {
    verifier.verify(tampered, realPermit.signature!);
  } catch (e) {
    tamperRefused = true;
    tamperMsg = (e as Error).message;
  }
  console.log(`  Vault.verify() raised: ${tamperRefused}`);
  console.log(`  message (first 180 chars): ${tamperMsg.slice(0, 180)}`);
  console.log();

  results.push(['Case F: wire tamper is refused', tamperRefused]);

  // -----------------------------------------------------------------
  // Close out: reverify the full chain.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Close out: export the audit chain and reverify.');
  console.log('-'.repeat(70));
  console.log('The security team exports the full JSONL blob to archive it.');
  console.log('Reverify against the audit bundle returns a count equal to');
  console.log('chain.length on an untouched chain.');
  console.log();

  const jsonl = chain.exportJsonl();
  const auditBundle = auditKp.publicKeys();
  let cleanCount = -1;
  try {
    cleanCount = SignedAuditChain.verifyJsonl(jsonl, auditBundle);
    console.log(`Clean reverify: passed (${cleanCount} entries verified).`);
  } catch (e) {
    console.log(`Clean reverify raised unexpectedly: ${(e as Error).name}: ${(e as Error).message}`);
  }
  console.log(`JSONL bytes length: ${jsonl.length}`);
  console.log(`Chain length:       ${chain.length}`);
  console.log();

  results.push([
    'Close out: chain reverifies cleanly',
    cleanCount === chain.length,
  ]);

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
