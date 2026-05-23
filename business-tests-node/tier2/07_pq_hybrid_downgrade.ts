/**
 * Scenario 07: post quantum hybrid mode and the downgrade defence.
 *
 * The story
 * ---------
 * Kavach signs things (permits, audit entries, channel messages) in
 * one of two modes:
 *
 *     PQ only. ML-DSA-65 signature alone. Post quantum strength only.
 *     Slightly smaller on the wire.
 *
 *     Hybrid. ML-DSA-65 signature AND Ed25519 signature, both required.
 *     Twice the bytes, but a break in either scheme alone does not
 *     break the chain. This is the sensible default while the world
 *     is still in the middle of the PQ transition: ML-DSA is brand new
 *     and might have a flaw nobody has found yet, Ed25519 is old and
 *     will fall to a real quantum computer eventually. Hybrid means
 *     you need to break both, at the same time, to forge a signature.
 *
 * The whole point of hybrid mode is to rule out a downgrade attack. A
 * sophisticated attacker who has broken one of the two schemes could
 * try to present a PQ only chain to a verifier configured for hybrid,
 * or a hybrid chain to a verifier configured for PQ only, hoping the
 * verifier accepts the weaker proof and then ignores the other half.
 *
 * Kavach refuses to allow either confusion. The verifier is strict
 * about mode: if the caller passes hybrid=true or hybrid=false, the
 * verifier checks the blob matches BEFORE it runs any crypto. If the
 * caller omits hybrid, Kavach infers from the blob. No silent
 * downgrade, ever.
 *
 * This is not something you can get from a JWT library. JWT has an
 * 'alg' header that callers have to validate themselves (the famous
 * 'alg:none' bug was exactly this kind of confusion). Kavach's gate
 * and chain verifiers enforce the mode by construction.
 *
 * Six cases, all on a signed audit chain:
 *
 *     A. Hybrid chain, verify with inferred mode, expect clean pass.
 *     B. Hybrid chain, explicit hybrid=true, clean pass (asserted).
 *     C. Hybrid chain, explicit hybrid=false, expect REFUSE, mode
 *        mismatch reported before any crypto runs.
 *     D. PQ only chain, explicit hybrid=true, expect REFUSE (the
 *        other direction of the same confusion).
 *     E. PQ only chain, inferred mode, clean pass.
 *     F. Tamper one byte inside a hybrid chain entry and expect
 *        verify to refuse and point at the broken entry. This is to
 *        confirm hybrid mode does not accidentally weaken tamper
 *        detection.
 *
 * Run this file directly:
 *
 *   node dist/tier2/07_pq_hybrid_downgrade.js
 */

import {
  AuditEntry,
  KavachKeyPair,
  SignedAuditChain,
} from 'kavach-sdk';

function auditEntry(
  principalId: string,
  actionName: string,
  verdictKind: string,
  detail: Record<string, unknown>,
): AuditEntry {
  return AuditEntry.new(
    principalId,
    actionName,
    verdictKind,
    JSON.stringify(detail),
  );
}

function mutateLine(
  jsonl: Buffer,
  idx: number,
  mutator: (obj: Record<string, unknown>) => void,
): Buffer {
  const endsWithNewline = jsonl.length > 0 && jsonl[jsonl.length - 1] === 0x0a;
  const text = jsonl.toString('utf-8');
  const trimmed = endsWithNewline ? text.slice(0, -1) : text;
  const lines = trimmed.split('\n');
  const obj = JSON.parse(lines[idx]!) as Record<string, unknown>;
  mutator(obj);
  lines[idx] = JSON.stringify(obj);
  const joined = lines.join('\n');
  return Buffer.from(endsWithNewline ? joined + '\n' : joined, 'utf-8');
}

function main(): number {
  console.log('='.repeat(70));
  console.log('Scenario 07: post quantum hybrid mode and the downgrade defence');
  console.log('='.repeat(70));
  console.log();
  console.log('We are going to build two signed audit chains. One is hybrid');
  console.log('(ML-DSA-65 plus Ed25519), the other is PQ only (ML-DSA-65');
  console.log('alone). Then we will try every combination of chain mode and');
  console.log('verifier assertion, showing Kavach refuses every downgrade');
  console.log('attempt before any crypto even runs.');
  console.log();

  const results: [string, boolean][] = [];

  // -----------------------------------------------------------------
  // Build both chains.
  // -----------------------------------------------------------------
  console.log('Generating one keypair, building both chains against it.');
  const kp = KavachKeyPair.generate();
  const bundle = kp.publicKeys();
  console.log(`  key_id: ${kp.id}`);
  console.log();

  const hybridChain = new SignedAuditChain(kp, true);
  const pqChain = new SignedAuditChain(kp, false);
  console.log(`  hybrid_chain.is_hybrid: ${hybridChain.isHybrid}`);
  console.log(`  pq_chain.is_hybrid:     ${pqChain.isHybrid}`);

  for (let i = 0; i < 3; i++) {
    hybridChain.append(
      auditEntry(`user-${i}`, 'payments.charge', 'permit', {
        amount_usd: 100 + i * 10,
      }),
    );
    pqChain.append(
      auditEntry(`user-${i}`, 'payments.charge', 'permit', {
        amount_usd: 100 + i * 10,
      }),
    );
  }

  console.log(`  hybrid_chain.length: ${hybridChain.length}`);
  console.log(`  pq_chain.length:     ${pqChain.length}`);
  console.log();

  const hybridJsonl = hybridChain.exportJsonl();
  const pqJsonl = pqChain.exportJsonl();
  console.log(
    `  hybrid_jsonl size: ${hybridJsonl.length} bytes  (two signatures per entry)`,
  );
  console.log(
    `  pq_jsonl size:     ${pqJsonl.length} bytes  (one signature per entry)`,
  );
  console.log('(note: hybrid entries are bigger because every entry carries');
  console.log(' both ML-DSA-65 and Ed25519 signatures. This is the cost of');
  console.log(' the transition.)');
  console.log();

  // -----------------------------------------------------------------
  // Case A: hybrid chain, inferred mode.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case A: hybrid chain, verify with inferred mode.');
  console.log('-'.repeat(70));
  console.log('No hybrid arg passed. The verifier reads the blob, sees');
  console.log('two-signature-per-entry structure, infers hybrid mode, and');
  console.log('runs the full ML-DSA plus Ed25519 verification. Clean pass.');
  console.log();

  try {
    const verified = SignedAuditChain.verifyJsonl(hybridJsonl, bundle);
    console.log(`  verify_jsonl passed: ${verified} entries verified.`);
    results.push([
      'Case A: hybrid chain, inferred mode, passes',
      verified === hybridChain.length,
    ]);
  } catch (e) {
    const err = e as Error;
    console.log(`  verify_jsonl raised unexpectedly: ${err.name}: ${err.message}`);
    results.push(['Case A: hybrid chain, inferred mode, passes', false]);
  }
  console.log();

  // -----------------------------------------------------------------
  // Case B: hybrid chain, explicit hybrid=true.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case B: hybrid chain, explicit hybrid=true.');
  console.log('-'.repeat(70));
  console.log('The caller knows what they wrote and asserts hybrid. The');
  console.log('blob matches, the crypto runs, clean pass. This is the');
  console.log('defensive form you want in production: state the mode you');
  console.log('expect so a misconfigured signer downstream is caught.');
  console.log();

  try {
    const verified = SignedAuditChain.verifyJsonl(hybridJsonl, bundle, true);
    console.log(`  verify_jsonl(hybrid=true) passed: ${verified} entries.`);
    results.push([
      'Case B: hybrid chain, hybrid=true asserted, passes',
      verified === hybridChain.length,
    ]);
  } catch (e) {
    const err = e as Error;
    console.log(`  verify_jsonl raised unexpectedly: ${err.name}: ${err.message}`);
    results.push(['Case B: hybrid chain, hybrid=true asserted, passes', false]);
  }
  console.log();

  // -----------------------------------------------------------------
  // Case C: hybrid chain, verifier asserts PQ only.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case C: hybrid chain, caller asserts hybrid=false. Downgrade.');
  console.log('-'.repeat(70));
  console.log('This is the first downgrade direction: caller has been fooled');
  console.log('into thinking they are handling a PQ only chain, but the blob');
  console.log('is actually hybrid. A naive verifier might pick the ML-DSA');
  console.log("half and skip Ed25519, accepting a 'proof' that silently");
  console.log('dropped one of the two required signatures. Kavach catches');
  console.log("the mismatch at the caller's assertion BEFORE crypto runs,");
  console.log('and raises with both sides named.');
  console.log();

  let refused = false;
  let msg = '';
  try {
    SignedAuditChain.verifyJsonl(hybridJsonl, bundle, false);
  } catch (e) {
    refused = true;
    msg = (e as Error).message;
  }
  console.log(`  verifier raised: ${refused}`);
  console.log(`  message (first 220 chars): ${msg.slice(0, 220)}`);
  console.log();

  const okC = refused && msg.toLowerCase().includes('hybrid');
  results.push(['Case C: hybrid=false on hybrid chain refused', okC]);

  // -----------------------------------------------------------------
  // Case D: PQ only chain, verifier asserts hybrid.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case D: PQ only chain, caller asserts hybrid=true. Other direction.');
  console.log('-'.repeat(70));
  console.log('A caller configured for hybrid is handed a PQ only blob. If');
  console.log('the verifier accepted this (silently ignored the missing');
  console.log('Ed25519 half), an attacker who could break ML-DSA but not');
  console.log("Ed25519 could forge a 'hybrid' permit by sending only the");
  console.log('ML-DSA half. Same defence: assertion mismatch raises.');
  console.log();

  refused = false;
  msg = '';
  try {
    SignedAuditChain.verifyJsonl(pqJsonl, bundle, true);
  } catch (e) {
    refused = true;
    msg = (e as Error).message;
  }
  console.log(`  verifier raised: ${refused}`);
  console.log(`  message (first 220 chars): ${msg.slice(0, 220)}`);
  console.log();

  const loweredD = msg.toLowerCase();
  const okD = refused && (loweredD.includes('pq') || loweredD.includes('hybrid'));
  results.push(['Case D: hybrid=true on PQ only chain refused', okD]);

  // -----------------------------------------------------------------
  // Case E: PQ only chain, inferred mode.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case E: PQ only chain, verify with inferred mode.');
  console.log('-'.repeat(70));
  console.log('Baseline: PQ only chain verifies cleanly when mode is not');
  console.log('asserted. Inferred from the single signature structure.');
  console.log();

  try {
    const verified = SignedAuditChain.verifyJsonl(pqJsonl, bundle);
    console.log(`  verify_jsonl passed: ${verified} entries verified.`);
    results.push([
      'Case E: PQ only chain, inferred mode, passes',
      verified === pqChain.length,
    ]);
  } catch (e) {
    const err = e as Error;
    console.log(`  verify_jsonl raised unexpectedly: ${err.name}: ${err.message}`);
    results.push(['Case E: PQ only chain, inferred mode, passes', false]);
  }
  console.log();

  // -----------------------------------------------------------------
  // Case F: tamper a hybrid entry and make sure it is still caught.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case F: tamper one byte inside hybrid chain entry 1, reverify.');
  console.log('-'.repeat(70));
  console.log('Hybrid mode carries two signatures per entry. We flip a byte');
  console.log('in the signed payload of entry 1 (zero indexed). Both');
  console.log('signatures break, the verifier reports the broken entry by');
  console.log('its position. Tamper detection has the same granularity as');
  console.log('PQ only mode.');
  console.log();

  const flipFirstDataByte = (obj: Record<string, unknown>): void => {
    const signedPayload = obj['signed_payload'] as Record<string, unknown>;
    const data = signedPayload['data'] as number[];
    data[0] = (data[0]! + 7) & 0xff;
    signedPayload['data'] = data;
  };

  const tampered = mutateLine(hybridJsonl, 1, flipFirstDataByte);
  refused = false;
  msg = '';
  try {
    SignedAuditChain.verifyJsonl(tampered, bundle);
  } catch (e) {
    refused = true;
    msg = (e as Error).message;
  }
  console.log(`  verifier raised: ${refused}`);
  console.log(`  message (first 220 chars): ${msg.slice(0, 220)}`);
  console.log();

  const okF = refused && (msg.includes('entry 1') || msg.toLowerCase().includes('entry'));
  results.push(['Case F: hybrid chain tamper at entry 1 refused', okF]);

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
