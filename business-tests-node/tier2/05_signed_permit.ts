/**
 * Scenario 05: signed permit token crossing a service boundary.
 *
 * The story
 * ---------
 * A financial platform splits "who is authorised" from "who actually
 * moves the money" across two services:
 *
 *     Auth service      : holds the signing keys. Runs Kavach's policy
 *                         chain for every charge request. If the rules
 *                         permit, returns a permit token signed with
 *                         ML-DSA-65 (a post quantum signature scheme)
 *                         over a canonical payload.
 *
 *     Payments service  : does not hold any policy. It takes the permit
 *                         token off the wire and verifies it against a
 *                         public key directory. If the signature checks
 *                         out, the token is trusted. If not, the request
 *                         is refused before the payment rail ever sees
 *                         it.
 *
 * This split is how Kavach's multi service story works in practice.
 * The permit token is the single source of truth for "this action was
 * authorised at this time for this principal". Payments never has to
 * re-run the policy chain, it only has to verify the signature.
 *
 * We will show four things:
 *
 *     1. Happy path. Auth permits a $250 charge. Payments verifies
 *        the signature against its trusted directory. Accept.
 *
 *     2. Action swap attack. An attacker captures the permit for
 *        'payments.charge' and relabels it 'payments.refund' before
 *        forwarding. The signature covers the action name, so the
 *        verify must fail.
 *
 *     3. Evaluation id swap attack. Attacker captures two real permits
 *        (say, two real charges), lifts the evaluation id from one
 *        and grafts it onto the envelope of the other. The signature
 *        covers the evaluation id, so the verify must fail.
 *
 *     4. Forged permit. Attacker spins up their own ML-DSA keypair,
 *        signs a fabricated permit, and sends it to Payments. The
 *        rogue key is not in the trusted directory, so verify fails
 *        with 'public key not found' before any crypto even runs.
 *
 * Run this file directly:
 *
 *   node dist/tier2/05_signed_permit.js
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
  type PermitTokenInput,
} from 'kavach-sdk';

// ---------------------------------------------------------------------
// Step 1. Write the Auth service's permit rule.
// ---------------------------------------------------------------------
// A customer may charge a card up to $500 per call. Nothing fancy,
// this scenario is about the signed token and the verification on the
// other side.

const POLICIES = {
  policies: [
    {
      name: 'customer_may_charge_under_cap',
      description: 'Any customer may charge a card up to $500 per call',
      effect: 'permit',
      priority: 10,
      conditions: [
        { identity_role: 'customer' },
        { action: 'payments.charge' },
        { param_max: { field: 'amount_usd', max: 500.0 } },
      ],
    },
  ],
};

function main(): number {
  console.log('='.repeat(70));
  console.log('Scenario 05: signed permit token crossing a service boundary');
  console.log('='.repeat(70));
  console.log();
  console.log('We are going to set up two services. Auth holds the signing');
  console.log('keys and runs the Kavach policy chain. Payments holds no');
  console.log('policy, only a trusted public key directory. We show the');
  console.log('happy path first, then three attacks that the directory');
  console.log('verifier must refuse.');
  console.log();

  const results: [string, boolean][] = [];

  // -----------------------------------------------------------------
  // Step 2. Generate two keypairs: one for Auth, one for the directory root.
  // -----------------------------------------------------------------
  // The root keypair signs the directory manifest at deploy time.
  // Payments holds only the root's verifying key, which is how we
  // bootstrap trust: any bundle listed in a manifest the root
  // signed is treated as a trusted identity.
  console.log('Generating two keypairs.');
  const authKp = KavachKeyPair.generate();
  const rootKp = KavachKeyPair.generate();
  const authBundle = authKp.publicKeys();
  const rootBundle = rootKp.publicKeys();
  console.log(`  auth.key_id: ${authKp.id}`);
  console.log(`  root.key_id: ${rootKp.id}`);
  console.log();

  // -----------------------------------------------------------------
  // Step 3. Build a root signed directory manifest.
  // -----------------------------------------------------------------
  // Operator writes a JSON manifest that lists every trusted auth
  // bundle, signed by the root keypair. Payments verifies this
  // signature once at startup using the pinned root verifying key;
  // any bundle in that manifest is then a first class identity.
  console.log('Building a root signed directory manifest that lists the auth bundle.');
  const manifestBytes = rootKp.buildSignedManifest([authBundle]);
  const tmp = mkdtempSync(join(tmpdir(), 'kavach-07-'));
  const manifestPath = join(tmp, 'trusted_signers.json');
  writeFileSync(manifestPath, manifestBytes);
  console.log(`  manifest written to: ${manifestPath}`);
  console.log(`  manifest size:       ${manifestBytes.length} bytes`);
  console.log();

  console.log('Loading the directory into Payments and building the verifier.');
  const directory = PublicKeyDirectory.fromSignedFile(
    manifestPath,
    Buffer.from(rootBundle.mlDsaVerifyingKey),
  );
  console.log(`  directory.length:   ${directory.length}`);
  console.log(`  directory.is_empty: ${directory.isEmpty}`);
  const verifier = new DirectoryTokenVerifier(directory, false);
  console.log();

  // -----------------------------------------------------------------
  // Step 4. Build the Auth gate, with the token signer attached.
  // -----------------------------------------------------------------
  console.log("Building Auth's gate with its signer attached.");
  const signer = PqTokenSigner.fromKeypairPqOnly(authKp);
  console.log(`  signer.is_hybrid: ${signer.isHybrid}`);
  console.log(`  signer.key_id:    ${signer.keyId}`);
  const gate = Gate.fromObject(POLICIES, { tokenSigner: signer });
  console.log(`  gate.evaluator_count: ${gate.evaluatorCount}`);
  console.log();

  // -----------------------------------------------------------------
  // Case 1: happy path.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case 1: customer charges $250. Auth permits, Payments verifies.');
  console.log('-'.repeat(70));
  console.log('Auth runs the policy chain, which permits ($250 is under the');
  console.log('$500 cap). Auth returns a signed permit token. Payments calls');
  console.log('verifier.verify(token, token.signature) and accepts. This is');
  console.log('the baseline that says the signing and verification loop');
  console.log('works end to end.');
  console.log();

  const realVerdict = gate.evaluate({
    principalId: 'cust-7f11',
    principalKind: 'user',
    actionName: 'payments.charge',
    roles: ['customer'],
    params: { amount_usd: 250.0 },
  });

  console.log(`Auth verdict kind:   ${realVerdict.kind}`);
  console.log(`Auth is permit:      ${realVerdict.isPermit}`);
  console.log(`Permit token id:     ${realVerdict.tokenId}`);
  const realToken = realVerdict.permitToken;
  console.log(`Permit action_name:  ${realToken ? realToken.actionName : null}`);
  console.log();

  results.push(['Case 1: Auth permits a $250 charge', realVerdict.isPermit]);
  results.push(['Case 1: verdict carries a permit token', realToken != null]);

  // We require a real token for the rest of the scenario.
  if (realToken == null || realToken.signature == null) {
    console.log('  no permit token issued, aborting.');
    return 1;
  }
  const realSignature = Buffer.from(realToken.signature);

  console.log('Payments verifies the permit:');
  try {
    verifier.verify(
      {
        tokenId: realToken.tokenId,
        evaluationId: realToken.evaluationId,
        issuedAt: realToken.issuedAt,
        expiresAt: realToken.expiresAt,
        actionName: realToken.actionName,
      },
      realSignature,
    );
    console.log('  directory.verify() accepted the permit.');
    results.push(['Case 1: Payments accepts the real permit', true]);
  } catch (e) {
    const err = e as Error;
    console.log(`  directory.verify() raised unexpectedly: ${err.name}: ${err.message}`);
    results.push(['Case 1: Payments accepts the real permit', false]);
  }
  console.log();

  // -----------------------------------------------------------------
  // Case 2: action swap attack.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log("Case 2: attacker relabels the permit from 'charge' to 'refund'.");
  console.log('-'.repeat(70));
  console.log('The attacker keeps the original signature bytes and every');
  console.log('other field identical, but overwrites action_name. The');
  console.log('signature covers the canonical serialisation of the token,');
  console.log('which includes the action name. So when the verifier');
  console.log('recomputes the canonical payload, the bytes do not match');
  console.log('what was signed, and the ML-DSA check fails.');
  console.log();

  const tamperedAction: PermitTokenInput = {
    tokenId: realToken.tokenId,
    evaluationId: realToken.evaluationId,
    issuedAt: realToken.issuedAt,
    expiresAt: realToken.expiresAt,
    actionName: 'payments.refund',
  };
  console.log(`  original action_name:  ${realToken.actionName}`);
  console.log(`  tampered action_name:  ${tamperedAction.actionName}`);
  console.log(`  signature bytes reused: ${realSignature.length} bytes`);
  console.log();
  try {
    verifier.verify(tamperedAction, realSignature);
    console.log('  directory.verify() accepted the permit when it should have refused.');
    results.push(['Case 2: action swap is refused', false]);
  } catch (e) {
    const msg = (e as Error).message;
    const ok = msg.includes('signature verification failed');
    console.log('  directory.verify() raised as expected.');
    console.log(`  message (first 180 chars): ${msg.slice(0, 180)}`);
    results.push(['Case 2: action swap is refused', ok]);
  }
  console.log();

  // -----------------------------------------------------------------
  // Case 3: evaluation id swap attack.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log("Case 3: attacker grafts another permit's evaluation id.");
  console.log('-'.repeat(70));
  console.log('More realistic attack. Auth has issued many valid permits');
  console.log('over time. Attacker captures two of them, lifts the');
  console.log('evaluation id from permit B and pastes it onto permit A\'s');
  console.log("envelope, hoping that downstream logs show 'fresh activity'");
  console.log("tied to B's id. The signature on permit A covered permit");
  console.log("A's evaluation id, so swapping it (even to another valid");
  console.log('id from elsewhere) breaks the signature check.');
  console.log();

  const secondVerdict = gate.evaluate({
    principalId: 'cust-9e42',
    principalKind: 'user',
    actionName: 'payments.charge',
    roles: ['customer'],
    params: { amount_usd: 100.0 },
  });
  const secondToken = secondVerdict.permitToken;
  if (secondToken == null) {
    console.log('  expected a second permit, aborting.');
    return 1;
  }
  console.log(`  permit A evaluation_id: ${realToken.evaluationId}`);
  console.log(`  permit B evaluation_id: ${secondToken.evaluationId}`);

  const tamperedEid: PermitTokenInput = {
    tokenId: realToken.tokenId,
    evaluationId: secondToken.evaluationId,
    issuedAt: realToken.issuedAt,
    expiresAt: realToken.expiresAt,
    actionName: realToken.actionName,
  };
  console.log(`  spliced onto A's envelope: ${tamperedEid.evaluationId}`);
  console.log();

  try {
    verifier.verify(tamperedEid, realSignature);
    console.log('  directory.verify() accepted the permit when it should have refused.');
    results.push(['Case 3: evaluation id swap is refused', false]);
  } catch (e) {
    const msg = (e as Error).message;
    const ok = msg.includes('signature verification failed');
    console.log('  directory.verify() raised as expected.');
    console.log(`  message (first 180 chars): ${msg.slice(0, 180)}`);
    results.push(['Case 3: evaluation id swap is refused', ok]);
  }
  console.log();

  // -----------------------------------------------------------------
  // Case 4: forged permit from a rogue keypair.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case 4: attacker signs a fabricated permit with their own key.');
  console.log('-'.repeat(70));
  console.log('Attacker generates their own ML-DSA keypair, signs a crafted');
  console.log('permit, and forwards it to Payments. The signature is');
  console.log("perfectly valid against the attacker's own public key, but");
  console.log('their public key is not in the trusted directory. The');
  console.log("verifier resolves the envelope's key id, finds nothing, and");
  console.log("raises with 'public key not found'. No crypto");
  console.log('even runs in this path, the lookup fails first.');
  console.log();

  const rogueKp = KavachKeyPair.generate();
  const rogueBundle = rogueKp.publicKeys();
  const rogueSigner = PqTokenSigner.fromKeypairPqOnly(rogueKp);
  console.log(`  rogue key_id:          ${rogueKp.id}`);
  console.log(`  trusted auth key_id:   ${authKp.id}`);
  console.log('  is the rogue key in the trusted directory? no');
  console.log();

  const forgedBase: PermitTokenInput = {
    tokenId: randomUUID(),
    evaluationId: randomUUID(),
    issuedAt: realToken.issuedAt,
    expiresAt: realToken.expiresAt,
    actionName: 'payments.charge',
  };
  const forgedSignature = rogueSigner.sign(forgedBase);
  try {
    verifier.verify(forgedBase, forgedSignature);
    console.log('  directory.verify() accepted the permit when it should have refused.');
    results.push(['Case 4: rogue key forgery is refused', false]);
  } catch (e) {
    const msg = (e as Error).message;
    const ok = msg.includes('public key not found');
    console.log('  directory.verify() raised as expected.');
    console.log(`  message (first 180 chars): ${msg.slice(0, 180)}`);
    results.push(['Case 4: rogue key forgery is refused', ok]);
  }
  console.log();

  // Sanity check: the rogue signature IS valid against a directory
  // that only contains the rogue bundle. The trust boundary is the
  // root signed directory, not the signature itself.
  console.log('  Sanity check: the forgery does verify against a directory');
  console.log('  that contains the rogue bundle. This is not a bug, it is');
  console.log('  the whole point of the trusted directory. The directory');
  console.log('  is the trust boundary, not the signature on its own.');
  const rogueOnly = PublicKeyDirectory.inMemory([rogueBundle]);
  const rogueVerifier = new DirectoryTokenVerifier(rogueOnly, false);
  let rogueSelfVerifyOk = false;
  try {
    rogueVerifier.verify(forgedBase, forgedSignature);
    rogueSelfVerifyOk = true;
  } catch (e) {
    console.log(`  unexpected: rogue-only directory refused the forgery: ${(e as Error).message}`);
  }
  console.log(`  forgery verifies against a rogue-only directory: ${rogueSelfVerifyOk}`);
  console.log();

  results.push([
    'Case 4: rogue forgery verifies against a rogue only directory',
    rogueSelfVerifyOk,
  ]);

  // -----------------------------------------------------------------
  // Case 5: empty directory refuses even the real permit.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case 5: swap to an empty directory and reverify the real permit.');
  console.log('-'.repeat(70));
  console.log('This proves the directory is the load bearing part. If the');
  console.log('directory is empty, the real permit has no trusted bundle to');
  console.log("verify against, and the lookup fails with 'public key not");
  console.log("found'. The permit itself is fine; what is missing is the");
  console.log('trust binding.');
  console.log();

  const emptyDirectory = PublicKeyDirectory.inMemory([]);
  const emptyVerifier = new DirectoryTokenVerifier(emptyDirectory, false);
  console.log(`  empty_directory.length:   ${emptyDirectory.length}`);
  console.log(`  empty_directory.is_empty: ${emptyDirectory.isEmpty}`);
  console.log();
  try {
    emptyVerifier.verify(
      {
        tokenId: realToken.tokenId,
        evaluationId: realToken.evaluationId,
        issuedAt: realToken.issuedAt,
        expiresAt: realToken.expiresAt,
        actionName: realToken.actionName,
      },
      realSignature,
    );
    console.log('  directory.verify() accepted the permit when it should have refused.');
    results.push(['Case 5: real permit is refused against an empty directory', false]);
  } catch (e) {
    const msg = (e as Error).message;
    const ok = msg.includes('public key not found');
    console.log('  directory.verify() raised as expected.');
    console.log(`  message (first 180 chars): ${msg.slice(0, 180)}`);
    results.push(['Case 5: real permit is refused against an empty directory', ok]);
  }
  console.log();

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

process.exit(main());
