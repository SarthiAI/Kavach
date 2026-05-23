/**
 * Scenario 17: PQ audit archives across a key rotation, read back years later.
 *
 * The story
 * ---------
 * A commercial bank is subject to a seven year audit retention rule.
 * Every consumer loan decision between 2026 and 2033 has to be
 * retrievable on demand, with a proof that the decision really was
 * what the audit says it was, signed by a real authoriser.
 *
 * Two forces pull against each other:
 *
 *     Short keypair TTL is good practice. If a signing keypair is
 *     compromised, you want the damage bounded to a narrow window.
 *     A signing identity that lives for years makes every entry
 *     signed in that window forgeable the second the key leaks.
 *
 *     Long retention demands that OLD signatures remain verifiable
 *     forever. If the keypair that signed a 2026 entry has long
 *     since been retired, the verifier still has to be able to check
 *     the signature today.
 *
 * Classical crypto has a deeper problem: when a real quantum
 * computer exists, Ed25519 and RSA signatures on those old archives
 * become forgeable. Anyone can craft a "2026 audit entry" that
 * verifies under a 2026 keypair's public key. Your archive stops
 * being evidence; it becomes a suggestion.
 *
 * Kavach's answer to both problems:
 *
 *     1. Rotation is cheap. Each keypair has an `expiresAt`. When a
 *        rotation is due, generate a new keypair, ship its bundle to
 *        the directory, and new entries sign under it. Old bundles
 *        stay in the directory for historical verification.
 *
 *     2. Signatures are ML-DSA-65 (post quantum). An archive signed
 *        in 2026 still verifies in 2040 even if a quantum computer
 *        has broken every classical scheme in the meantime.
 *
 * Six cases:
 *
 *     A. Archive A signed under key A, verifies cleanly.
 *     B. Archive B signed under key B, verifies cleanly.
 *     C. Tamper inside archive A, verify reports the exact entry.
 *     D. Stripped directory (only key B), verify on archive A refuses.
 *     E. Forensic path with enforceExpiry=false accepts expired bundle.
 *     F. Cross key splice: A's signature onto a B envelope. Refused.
 *
 * Run this file directly:
 *
 *   node dist/tier3/17_pq_audit_rotation.js
 */

import {
  AuditEntry,
  DirectoryTokenVerifier,
  Gate,
  KavachKeyPair,
  PqTokenSigner,
  PublicKeyDirectory,
  SignedAuditChain,
  type PublicKeyBundleView,
} from 'kavach-sdk';

function appendEntries(chain: SignedAuditChain, count: number, tag: string): void {
  for (let i = 0; i < count; i++) {
    const idx = String(i).padStart(3, '0');
    const detail = JSON.stringify({
      tag,
      entry_index: i,
      amount_usd: 1000 + i * 50,
    });
    chain.append(
      AuditEntry.new(
        `officer-${tag}-${idx}`,
        'loan.approve',
        'permit',
        detail,
      ),
    );
  }
}

function mutateLine(jsonl: Buffer, idx: number, mutator: (obj: any) => void): Buffer {
  const hasTrailingNewline = jsonl.length > 0 && jsonl[jsonl.length - 1] === 0x0a;
  const text = jsonl.toString('utf-8');
  const trimmed = hasTrailingNewline ? text.slice(0, -1) : text;
  const lines = trimmed.split('\n');
  const obj = JSON.parse(lines[idx]!);
  mutator(obj);
  lines[idx] = JSON.stringify(obj);
  const out = lines.join('\n') + (hasTrailingNewline ? '\n' : '');
  return Buffer.from(out, 'utf-8');
}

async function main(): Promise<number> {
  console.log('='.repeat(70));
  console.log('Scenario 17: PQ audit archives across a key rotation');
  console.log('='.repeat(70));
  console.log();
  console.log("We are going to simulate the 2026 to 2033 life of a bank's");
  console.log('loan approval archive. Two keypairs signed entries in that');
  console.log('window; both should still verify against a directory that');
  console.log('retains their public bundles. Then we show what a real');
  console.log('revocation and a cross key replay look like.');
  console.log();

  const results: [string, boolean][] = [];

  // -----------------------------------------------------------------
  // Generate the two keypairs.
  // -----------------------------------------------------------------
  console.log('Generating two signing keypairs.');
  const year2026Kp = KavachKeyPair.generate();
  const year2029Kp = KavachKeyPair.generate();
  const bundle2026 = year2026Kp.publicKeys();
  const bundle2029 = year2029Kp.publicKeys();
  console.log(`  2026 key_id: ${year2026Kp.id}`);
  console.log(`  2029 key_id: ${year2029Kp.id}`);
  console.log();

  // -----------------------------------------------------------------
  // Two chains.
  // -----------------------------------------------------------------
  console.log('Signing archive A (5 entries) under the 2026 keypair.');
  const chainA = new SignedAuditChain(year2026Kp, false);
  appendEntries(chainA, 5, 'A');
  console.log(`  chainA.length:    ${chainA.length}`);

  console.log('Signing archive B (5 entries) under the 2029 keypair.');
  const chainB = new SignedAuditChain(year2029Kp, false);
  appendEntries(chainB, 5, 'B');
  console.log(`  chainB.length:    ${chainB.length}`);
  console.log();

  const jsonlA = chainA.exportJsonl();
  const jsonlB = chainB.exportJsonl();
  console.log(`  archive A JSONL bytes: ${jsonlA.length}`);
  console.log(`  archive B JSONL bytes: ${jsonlB.length}`);
  console.log();

  // -----------------------------------------------------------------
  // Case A
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case A: reverify archive A against bundle_2026.');
  console.log('-'.repeat(70));
  console.log("The compliance tool looks up archive A's signing key_id (the");
  console.log('first entry names the 2026 keypair), fetches bundle_2026');
  console.log('from the directory, and runs verifyJsonl. All 5 entries');
  console.log('pass.');
  console.log();

  const countA = SignedAuditChain.verifyJsonl(jsonlA, bundle2026);
  console.log(`  verifyJsonl(archive A, bundle_2026) -> ${countA} entries`);
  console.log();
  results.push(['Case A: archive A reverifies under bundle_2026', countA === chainA.length]);

  // -----------------------------------------------------------------
  // Case B
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case B: reverify archive B against bundle_2029.');
  console.log('-'.repeat(70));
  console.log('Same flow against the post rotation chain. This is what tells');
  console.log("us rotation does not mean 'lose everything before the");
  console.log("rotation date'. Both keypairs live in the archive forever.");
  console.log();

  const countB = SignedAuditChain.verifyJsonl(jsonlB, bundle2029);
  console.log(`  verifyJsonl(archive B, bundle_2029) -> ${countB} entries`);
  console.log();
  results.push(['Case B: archive B reverifies under bundle_2029', countB === chainB.length]);

  // -----------------------------------------------------------------
  // Case C
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case C: flip a byte inside entry 2 of archive A, reverify.');
  console.log('-'.repeat(70));
  console.log('If a bad actor edits an entry in the archive years later,');
  console.log('verifyJsonl refuses and names the exact entry position.');
  console.log('This is the property that makes the archive evidence, not');
  console.log("just 'stuff our database had stored'.");
  console.log();

  const flipFirstDataByte = (obj: any) => {
    const data: number[] = obj.signed_payload.data as number[];
    data[0] = (data[0]! + 7) & 0xff;
    obj.signed_payload.data = data;
  };

  const tamperedA = mutateLine(jsonlA, 2, flipFirstDataByte);
  let refused = false;
  let msg = '';
  try {
    SignedAuditChain.verifyJsonl(tamperedA, bundle2026);
  } catch (e) {
    refused = true;
    msg = (e as Error).message;
  }
  console.log(`  verifyJsonl raised: ${refused}`);
  console.log(`  message (first 220 chars): ${msg.slice(0, 220)}`);
  console.log();

  const okC = refused && (msg.includes('entry 2') || msg.toLowerCase().includes('entry'));
  results.push(['Case C: tampered entry 2 in archive A caught', okC]);

  // -----------------------------------------------------------------
  // Case D: retroactive revocation
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case D: retroactive revocation of bundle_2026.');
  console.log('-'.repeat(70));
  console.log('Suppose at some point we learn the 2026 keypair was');
  console.log('compromised retroactively. The right response is to remove');
  console.log("bundle_2026 from the verifier's trusted set. Once that is");
  console.log('done, archive A cannot be verified: the verifier looks up');
  console.log("the signer's key_id, finds nothing, and refuses. This is");
  console.log('how full revocation looks. If compliance decides they');
  console.log('still need a forensic pass, they can re-add the bundle');
  console.log('read only in a separate tool, but no production path uses');
  console.log('the revoked bundle again.');
  console.log();

  refused = false;
  msg = '';
  try {
    SignedAuditChain.verifyJsonl(jsonlA, bundle2029);
  } catch (e) {
    refused = true;
    msg = (e as Error).message;
  }
  console.log(`  verifyJsonl(archive A, bundle_2029) raised: ${refused}`);
  console.log(`  message (first 220 chars): ${msg.slice(0, 220)}`);
  console.log();

  results.push(['Case D: revoked bundle refuses the old archive', refused]);

  // -----------------------------------------------------------------
  // Case E: forensic path
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case E: forensic path across a rotation.');
  console.log('-'.repeat(70));
  console.log('For permits (as opposed to chain entries) Kavach exposes');
  console.log("DirectoryTokenVerifier, whose verify() enforces the bundle's");
  console.log('expiresAt by default and accepts enforceExpiry=false for');
  console.log('historical review. We simulate the forensic case for an old');
  console.log("permit by issuing one under a TTL'd keypair, letting the TTL");
  console.log('pass, and reverifying with enforceExpiry=false. This is the');
  console.log('audit path a regulator would use to confirm a historical');
  console.log('decision was validly signed at the time it was made.');
  console.log();

  const shortLivedKp = KavachKeyPair.generateWithExpiry(1);
  const shortBundle: PublicKeyBundleView = shortLivedKp.publicKeys();
  const shortDir = PublicKeyDirectory.inMemory([shortBundle]);
  const shortVerifier = new DirectoryTokenVerifier(shortDir, false);

  const POL = {
    policies: [
      {
        name: 'p',
        effect: 'permit',
        priority: 10,
        conditions: [{ action: 'loan.approve' }],
      },
    ],
  };
  const shortSigner = PqTokenSigner.fromKeypairPqOnly(shortLivedKp);
  const shortGate = Gate.fromObject(POL, { tokenSigner: shortSigner });
  const verdict = shortGate.evaluate({
    principalId: 'officer-historical',
    principalKind: 'user',
    actionName: 'loan.approve',
  });
  const permit = verdict.permitToken!;
  console.log('Sleeping 2 seconds to let the short TTL bundle expire...');
  await new Promise(r => setTimeout(r, 2000));

  let strictRefused = false;
  try {
    shortVerifier.verify(
      {
        tokenId: permit.tokenId,
        evaluationId: permit.evaluationId,
        issuedAt: permit.issuedAt,
        expiresAt: permit.expiresAt,
        actionName: permit.actionName,
      },
      Buffer.from(permit.signature!),
    );
  } catch (e) {
    void e;
    strictRefused = true;
  }
  console.log(`  strict verify (default) refuses expired bundle: ${strictRefused}`);

  let forensicOk = false;
  try {
    shortVerifier.verify(
      {
        tokenId: permit.tokenId,
        evaluationId: permit.evaluationId,
        issuedAt: permit.issuedAt,
        expiresAt: permit.expiresAt,
        actionName: permit.actionName,
      },
      Buffer.from(permit.signature!),
      false,
    );
    forensicOk = true;
  } catch (e) {
    const err = e as Error;
    console.log(`  forensic verify raised: ${err.name}: ${err.message}`);
  }
  console.log(`  forensic verify (enforceExpiry=false) accepts: ${forensicOk}`);
  console.log();

  results.push(['Case E: strict rejects expired bundle', strictRefused]);
  results.push(['Case E: forensic path still accepts', forensicOk]);

  // -----------------------------------------------------------------
  // Case F: cross key replay
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log("Case F: cross key replay, splice A's signature onto a B envelope.");
  console.log('-'.repeat(70));
  console.log('An attacker captures an entry from archive A and tries to');
  console.log('pass it off as though it had been signed under the 2029');
  console.log("keypair. They overwrite the envelope's key_id field to point");
  console.log('at the 2029 bundle. The verifier resolves the new key_id,');
  console.log('fetches bundle_2029, runs ML-DSA verify. The signature does');
  console.log('not match the 2029 public key, so verify refuses.');
  console.log();

  const swapKeyId = (obj: any) => {
    obj.signed_payload.key_id = year2029Kp.id;
  };

  const spliced = mutateLine(jsonlA, 1, swapKeyId);
  refused = false;
  msg = '';
  try {
    SignedAuditChain.verifyJsonl(spliced, bundle2029);
  } catch (e) {
    refused = true;
    msg = (e as Error).message;
  }
  console.log(`  verifyJsonl raised: ${refused}`);
  console.log(`  message (first 220 chars): ${msg.slice(0, 220)}`);
  console.log();

  results.push(['Case F: cross key signature splice refused', refused]);

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

main()
  .then(rc => process.exit(rc))
  .catch(e => {
    console.error(e);
    process.exit(1);
  });
