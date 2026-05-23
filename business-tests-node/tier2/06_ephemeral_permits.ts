/**
 * Scenario 06: ephemeral PQ permits replacing static API keys.
 *
 * The story
 * ---------
 * A fintech service calls five downstream vendors: Stripe for cards,
 * Adyen for EU cards, Plaid for bank verification, Onfido for KYC,
 * and an internal wallet. The classical way to authenticate is with
 * a long lived bearer API key per vendor. The keys sit in a secret
 * store, get injected at boot, and stay valid for weeks or months.
 * If one ever leaks (log line, cached HAR, compromised CI runner),
 * the attacker owns that vendor integration until somebody notices
 * and rotates.
 *
 * Kavach's answer: every outbound call carries a freshly signed
 * short TTL permit instead of a static key. The permit is signed by
 * an ML-DSA-65 keypair whose bundle is pinned by the vendor's
 * verifier against a root signed directory. When the bundle expires,
 * every permit ever signed by it stops verifying, not at the next
 * rotation window but at the second the bundle's expires_at is past.
 *
 * Short timescales in this demo
 * -----------------------------
 * The signing keypair in this scenario expires in 2 seconds to
 * keep the script fast. In production, tens of seconds to a few
 * minutes is typical, bounded by clock skew between services.
 *
 * Three things this buys you:
 *
 *     1. A captured permit cannot be reused after the keypair's TTL.
 *
 *     2. Rotation is not an emergency. Rotate the keypair, ship the
 *        new bundle into the directory, done. The old keypair
 *        naturally expires and every still-in-flight permit signed
 *        by it also expires. There is no race between 'I changed the
 *        secret' and 'the old secret still works'.
 *
 *     3. Post-quantum signatures. The signature is ML-DSA-65, the
 *        NIST standardised post-quantum scheme. Classical signatures
 *        (RSA, Ed25519) remain secure today, but audit archives that
 *        outlive the quantum transition are on firmer ground with a
 *        PQ scheme from day one. Kavach's hybrid mode combines both
 *        when you want belt and suspenders.
 *
 * Four cases:
 *
 *     A. Fresh keypair, permit issued, verified inside the TTL. Pass.
 *     B. Wait past the keypair's expiry, reverify the SAME permit.
 *        Rejected because the signing bundle is expired.
 *     C. Forensic verify with enforceExpiry=false still accepts,
 *        for audit trails that need to re-check archived signatures
 *        against bundles that have since expired.
 *     D. Rotation: a second keypair is generated, its bundle is added
 *        to the directory, a new permit signed under it verifies
 *        cleanly. The old keypair's bundle remains so historical
 *        forensic verification still works.
 *
 * Run this file directly:
 *
 *   node dist/tier2/06_ephemeral_permits.js
 */

import {
  DirectoryTokenVerifier,
  Gate,
  KavachKeyPair,
  PqTokenSigner,
  PublicKeyDirectory,
  type EvaluateOptions,
  type PermitTokenInput,
} from 'kavach-sdk';

// Keep the TTL small so the scenario runs in a few seconds.
const KEY_TTL_SECONDS = 2;
const SLEEP_SECONDS = 3;

const POLICIES = {
  policies: [
    {
      name: 'vendor_call',
      description: 'Fintech may call vendor APIs',
      effect: 'permit',
      priority: 10,
      conditions: [
        { identity_role: 'fintech_service' },
        { action: 'vendor.call' },
      ],
    },
  ],
};

function sleep(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms));
}

async function main(): Promise<number> {
  console.log('='.repeat(70));
  console.log('Scenario 06: ephemeral PQ permits replacing static API keys');
  console.log('='.repeat(70));
  console.log();
  console.log('(The keypair TTL is 2 seconds so this script runs fast; in');
  console.log(' production, tens of seconds to a few minutes is typical.)');
  console.log();
  console.log('We are going to generate a signing keypair with a 2 second');
  console.log('TTL, sign one permit, verify it cleanly, wait 3 seconds, then');
  console.log('try to verify the SAME permit. The verifier will refuse');
  console.log("because the signing bundle's expiry has passed. After that we");
  console.log('check the forensic path and rotation flow.');
  console.log();

  const results: [string, boolean][] = [];

  // -----------------------------------------------------------------
  // Set up a short lived signing keypair and the directory used by
  // the vendor's verifier.
  // -----------------------------------------------------------------
  console.log(`Generating a signing keypair with TTL = ${KEY_TTL_SECONDS} seconds.`);
  const signingKp = KavachKeyPair.generateWithExpiry(KEY_TTL_SECONDS);
  const bundle = signingKp.publicKeys();
  console.log(`  signing.key_id:     ${signingKp.id}`);
  console.log(`  signing.expires_at: ${signingKp.expiresAt}`);
  console.log(`  is_expired now:     ${signingKp.isExpired}`);
  console.log();

  const directory = PublicKeyDirectory.inMemory([bundle]);
  const verifier = new DirectoryTokenVerifier(directory, false);
  console.log(`  directory.length:   ${directory.length}`);
  console.log();

  const signer = PqTokenSigner.fromKeypairPqOnly(signingKp);
  const gate = Gate.fromObject(POLICIES, { tokenSigner: signer });
  console.log(`  gate.evaluator_count: ${gate.evaluatorCount}`);
  console.log();

  // -----------------------------------------------------------------
  // Case A: within the TTL window, happy path.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case A: fintech service calls Stripe, verifier accepts the permit.');
  console.log('-'.repeat(70));
  console.log("Fresh keypair, fresh permit, verifier's enforceExpiry=true");
  console.log("default kicks in, bundle.expires_at is in the future, signature");
  console.log('checks out. This is the everyday case: a permit signed thirty');
  console.log('milliseconds ago, verified against a bundle that is good for');
  console.log('another two seconds.');
  console.log();

  const ctx: EvaluateOptions = {
    principalId: 'fintech-service',
    principalKind: 'service',
    actionName: 'vendor.call',
    roles: ['fintech_service'],
  };
  const verdict = gate.evaluate(ctx);
  const permit = verdict.permitToken;

  console.log(`gate.evaluate().kind:   ${verdict.kind}`);
  if (permit == null || permit.signature == null) {
    console.log('  expected a permit token with signature, aborting.');
    return 1;
  }
  console.log(`permit.token_id:        ${permit.tokenId}`);
  console.log(`permit.issued_at:       ${permit.issuedAt}`);
  console.log(`permit.expires_at:      ${permit.expiresAt}`);
  console.log();

  const permitInput: PermitTokenInput = {
    tokenId: permit.tokenId,
    evaluationId: permit.evaluationId,
    issuedAt: permit.issuedAt,
    expiresAt: permit.expiresAt,
    actionName: permit.actionName,
  };
  const permitSignature = Buffer.from(permit.signature);

  let verifyOk = false;
  try {
    verifier.verify(permitInput, permitSignature);
    verifyOk = true;
    console.log('verifier.verify(): accepted.');
  } catch (e) {
    const err = e as Error;
    console.log(`verifier raised unexpectedly: ${err.name}: ${err.message}`);
  }
  console.log();

  results.push(['Case A: in TTL window, verify passes', verifyOk]);

  // -----------------------------------------------------------------
  // Case B: past the TTL, verify refuses by default.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log(`Case B: sleep ${SLEEP_SECONDS} seconds, past the keypair's TTL.`);
  console.log('-'.repeat(70));
  console.log('Same permit bytes as in Case A. We did not touch it. The only');
  console.log("thing that changed is the wall clock: the signing bundle's");
  console.log('expires_at is now in the past. The verifier\'s default');
  console.log('(enforceExpiry=true) refuses. This is what makes a leaked');
  console.log('permit from a logs dump useless after the window. A static');
  console.log('API key in the same situation would still authenticate.');
  console.log();

  await sleep(SLEEP_SECONDS * 1000);
  console.log(`  signing_kp.is_expired (after sleep): ${signingKp.isExpired}`);

  let refused = false;
  let msg = '';
  try {
    verifier.verify(permitInput, permitSignature);
  } catch (e) {
    refused = true;
    msg = (e as Error).message;
  }
  console.log(`  verifier raised: ${refused}`);
  console.log(`  message (first 200 chars): ${msg.slice(0, 200)}`);
  console.log();

  const lowered = msg.toLowerCase();
  const okB = refused && (lowered.includes('expired') || lowered.includes('expire'));
  results.push(['Case B: past TTL, default verify refuses', okB]);

  // -----------------------------------------------------------------
  // Case C: forensic verify with enforceExpiry=false still accepts.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case C: forensic path, enforceExpiry=false.');
  console.log('-'.repeat(70));
  console.log('A compliance tool re-checks an archived permit against the');
  console.log("directory months after the fact, asking only 'was this");
  console.log("signature valid at the time?'. Passing enforceExpiry=false");
  console.log('skips the TTL check and runs the crypto anyway. This is the');
  console.log('one, carefully labelled, opt out. No production authorisation');
  console.log('path should ever set this flag.');
  console.log();

  let forensicOk = false;
  try {
    verifier.verify(permitInput, permitSignature, false);
    forensicOk = true;
    console.log('verifier.verify(enforceExpiry=false): accepted.');
  } catch (e) {
    const err = e as Error;
    console.log(`forensic verify raised unexpectedly: ${err.name}: ${err.message}`);
  }
  console.log();

  results.push(['Case C: forensic verify still accepts', forensicOk]);

  // -----------------------------------------------------------------
  // Case D: rotation, new keypair, new bundle in the directory.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case D: rotate to a fresh keypair, sign again, verify.');
  console.log('-'.repeat(70));
  console.log('The fintech service rotates. A new keypair is generated with');
  console.log('a fresh TTL. The new bundle is added to the directory. The');
  console.log("old bundle stays, so Case C's forensic path keeps working.");
  console.log('A new permit is signed under the new keypair and verifies');
  console.log('cleanly. This is what a zero downtime rotation looks like:');
  console.log("no window where 'the old key still works and the new key");
  console.log("does not', because every permit names its signing key id");
  console.log('inside the envelope and the verifier looks up the right');
  console.log('bundle by id.');
  console.log();

  const newKp = KavachKeyPair.generateWithExpiry(60);
  const newBundle = newKp.publicKeys();
  const newSigner = PqTokenSigner.fromKeypairPqOnly(newKp);

  // Rebuild directory with BOTH old (for forensic) and new (for auth).
  const rotatedDirectory = PublicKeyDirectory.inMemory([bundle, newBundle]);
  const rotatedVerifier = new DirectoryTokenVerifier(rotatedDirectory, false);
  console.log(`  rotated directory length: ${rotatedDirectory.length}`);

  // Build a fresh gate under the new signer.
  const newGate = Gate.fromObject(POLICIES, { tokenSigner: newSigner });
  const ctxNew: EvaluateOptions = {
    principalId: 'fintech-service',
    principalKind: 'service',
    actionName: 'vendor.call',
    roles: ['fintech_service'],
  };
  const vNew = newGate.evaluate(ctxNew);
  const newPermit = vNew.permitToken;
  if (newPermit == null || newPermit.signature == null) {
    console.log('  expected a new permit, aborting.');
    return 1;
  }
  console.log(`  new permit token_id: ${newPermit.tokenId}`);

  const newPermitInput: PermitTokenInput = {
    tokenId: newPermit.tokenId,
    evaluationId: newPermit.evaluationId,
    issuedAt: newPermit.issuedAt,
    expiresAt: newPermit.expiresAt,
    actionName: newPermit.actionName,
  };
  const newPermitSignature = Buffer.from(newPermit.signature);

  let newVerifyOk = false;
  try {
    rotatedVerifier.verify(newPermitInput, newPermitSignature);
    newVerifyOk = true;
    console.log('rotated_verifier.verify() on new permit: accepted.');
  } catch (e) {
    const err = e as Error;
    console.log(`new permit verify raised unexpectedly: ${err.name}: ${err.message}`);
  }

  // The old permit should still refuse under the rotated verifier's
  // default, because the old bundle is still expired.
  let oldRefused = false;
  try {
    rotatedVerifier.verify(permitInput, permitSignature);
  } catch {
    oldRefused = true;
  }
  console.log(`  old permit still refused by rotated verifier: ${oldRefused}`);
  console.log();

  results.push(['Case D: new keypair signs, new permit verifies', newVerifyOk]);
  results.push(['Case D: old expired permit still refused', oldRefused]);

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

main().then(code => process.exit(code));
