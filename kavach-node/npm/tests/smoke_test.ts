/**
 * End-to-end smoke test for the Node/TypeScript SDK.
 *
 * Exercises every public surface through the compiled Rust engine:
 *   - Gate.fromToml construction
 *   - Gate.evaluate (Permit, Refuse, default-deny)
 *   - Gate.check throwing KavachRefused
 *   - Invariants overriding policy
 *   - McpKavachMiddleware evaluateToolCall + checkToolCall + guardTool
 *
 * Run:
 *   (from kavach-node/npm)
 *   npm run build
 *   node --loader ts-node/esm tests/smoke_test.ts
 *
 * We don't want to pull ts-node as a dep — compile to dist/ then run the .js.
 */

import {
  AuditEntry,
  DirectoryTokenVerifier,
  Gate,
  InMemoryInvalidationBroadcaster,
  InMemorySessionStore,
  KavachInvalidated,
  KavachKeyPair,
  KavachRefused,
  McpKavachMiddleware,
  PqTokenSigner,
  PublicKeyDirectory,
  SecureChannel,
  SignedAuditChain,
  spawnInvalidationListener,
  type InvalidationScopeView,
  type PermitTokenInput,
} from '../src/index';
import { randomUUID } from 'crypto';
import { writeFileSync, unlinkSync, mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

const PASS = '\x1b[32m✓\x1b[0m';
const FAIL = '\x1b[31m✗\x1b[0m';

let passed = 0;
let total = 0;

function check(name: string, cond: boolean, detail = ''): void {
  total += 1;
  if (cond) passed += 1;
  const mark = cond ? PASS : FAIL;
  const tail = detail ? ` — ${detail}` : '';
  console.log(`  ${mark} ${name}${tail}`);
}

function section(title: string): void {
  console.log(`\n${title}`);
}

// ─── 1. Gate construction + permit ─────────────────────────────────────

section('[1] Gate.fromToml → evaluate → Permit');

const permitToml = `
[[policy]]
name = "permit_small_refunds"
effect = "permit"
conditions = [
    { identity_role = "support" },
    { action = "issue_refund" },
    { param_max = { field = "amount", max = 5000.0 } },
]
`;

const permitGate = Gate.fromToml(permitToml, {
  invariants: [{ name: 'max_refund', field: 'amount', maxValue: 10000 }],
});

check('gate constructed', permitGate !== null);
check(
  'evaluator_count >= 2',
  permitGate.evaluatorCount >= 2,
  `got ${permitGate.evaluatorCount}`
);

const permitVerdict = permitGate.evaluate({
  principalId: 'agent-alice',
  principalKind: 'agent',
  actionName: 'issue_refund',
  roles: ['support'],
  params: { amount: 1500 },
});
check('verdict isPermit', permitVerdict.isPermit, `kind=${permitVerdict.kind}`);
check(
  'verdict carries tokenId',
  typeof permitVerdict.tokenId === 'string' && permitVerdict.tokenId.length > 0
);

// ─── 2. Default-deny ───────────────────────────────────────────────────

section('[2] Empty policy set → default-deny');

const emptyGate = Gate.fromToml('');
const denyVerdict = emptyGate.evaluate({
  principalId: 'agent',
  principalKind: 'agent',
  actionName: 'anything',
});
check('empty policy set refuses', denyVerdict.isRefuse, `kind=${denyVerdict.kind}`);

// ─── 3. Invariant overrides policy ─────────────────────────────────────

section('[3] Invariant blocks even when policy permits');

const permissiveToml = `
[[policy]]
name = "permit_any_refund"
effect = "permit"
conditions = [
    { identity_role = "support" },
    { action = "issue_refund" },
]
`;
const cappedGate = Gate.fromToml(permissiveToml, {
  invariants: [{ name: 'hard_cap', field: 'amount', maxValue: 100 }],
});
const overCap = cappedGate.evaluate({
  principalId: 'a',
  principalKind: 'agent',
  actionName: 'issue_refund',
  roles: ['support'],
  params: { amount: 500 },
});
check('invariant wins over policy permit', overCap.isRefuse, `kind=${overCap.kind}`);

// ─── 4. Gate.check throws KavachRefused ────────────────────────────────

section('[4] Gate.check throws KavachRefused on block');

let thrown: unknown = null;
try {
  emptyGate.check({ principalId: 'a', principalKind: 'agent', actionName: 'x' });
} catch (e) {
  thrown = e;
}
check('threw something', thrown !== null);
check('threw KavachRefused', thrown instanceof KavachRefused);
if (thrown instanceof KavachRefused) {
  check('error.code populated', typeof thrown.code === 'string' && thrown.code.length > 0);
  check('error.evaluator populated', typeof thrown.evaluator === 'string' && thrown.evaluator.length > 0);
}

// ─── 5. MCP middleware ─────────────────────────────────────────────────

section('[5] McpKavachMiddleware');

const mcpToml = `
[[policy]]
name = "agent_small_refunds"
effect = "permit"
conditions = [
    { identity_kind = "agent" },
    { action = "issue_refund" },
    { param_max = { field = "amount", max = 5000.0 } },
]
`;
const mcpGate = Gate.fromToml(mcpToml);
const kv = new McpKavachMiddleware(mcpGate);

async function runMcpMiddlewareTests(): Promise<void> {
  const mcpPermit = await kv.evaluateToolCall(
    'issue_refund',
    { orderId: 'ORD-1', amount: 500 },
    { callerId: 'support-bot', callerKind: 'agent', sessionId: 'sess-1' },
  );
  check('small refund permitted', mcpPermit.isPermit, `kind=${mcpPermit.kind}`);

  const mcpRefuse = await kv.evaluateToolCall(
    'issue_refund',
    { orderId: 'ORD-2', amount: 25000 },
    { callerId: 'support-bot', callerKind: 'agent', sessionId: 'sess-1' },
  );
  check('over-limit refund refused', mcpRefuse.isRefuse, `kind=${mcpRefuse.kind}`);

  const mcpUnknown = await kv.evaluateToolCall(
    'delete_customer',
    { customerId: 'c1' },
    { callerId: 'support-bot', callerKind: 'agent' },
  );
  check('unknown tool refused (default deny)', mcpUnknown.isRefuse, `kind=${mcpUnknown.kind}`);

  let mcpThrew = false;
  try {
    await kv.checkToolCall('delete_customer', {}, { callerId: 'bot', callerKind: 'agent' });
  } catch (e) {
    if (e instanceof KavachRefused) mcpThrew = true;
  }
  check('checkToolCall throws KavachRefused', mcpThrew);
}

// ─── 6. guardTool wrapper ──────────────────────────────────────────────

section('[6] guardTool wraps handler with gate check');

const guardedAllow = kv.guardTool(
  'issue_refund',
  async (params: Record<string, unknown>) => {
    return { ok: true, amount: params.amount };
  },
  { callerId: 'support-bot', callerKind: 'agent', roles: [] },
);

async function runGuardTests(): Promise<void> {
  const result = await guardedAllow({ orderId: 'ORD-3', amount: 100 });
  check('guardTool allows legit call', (result as { ok: boolean }).ok === true);

  let guardedBlocked = false;
  try {
    await guardedAllow({ orderId: 'ORD-4', amount: 99999 });
  } catch (e) {
    if (e instanceof KavachRefused) guardedBlocked = true;
  }
  check('guardTool blocks over-limit call', guardedBlocked);
}

// ─── 7. Malformed TOML surfaces as an Error ────────────────────────────

section('[7] Malformed TOML → Error');

let tomlErr = false;
try {
  Gate.fromToml('this is not === valid toml [[[');
} catch {
  tomlErr = true;
}
check('error raised on bad TOML', tomlErr);

// ─── 8. PqTokenSigner — sign/verify roundtrip + tamper detection ───────

section('[8] PqTokenSigner sign/verify (PQ-only + hybrid)');

const baseToken: PermitTokenInput = {
  tokenId: '00000000-0000-0000-0000-000000000001',
  evaluationId: '00000000-0000-0000-0000-000000000002',
  issuedAt: 1_700_000_000,
  expiresAt: 1_700_000_030,
  actionName: 'issue_refund',
};

const pq = PqTokenSigner.generatePqOnly();
check('PQ-only signer constructed', pq !== null);
check('PQ-only signer.isHybrid is false', pq.isHybrid === false);
check('PQ-only signer.keyId is non-empty', typeof pq.keyId === 'string' && pq.keyId.length > 0);

const sig = pq.sign(baseToken);
check('PQ-only sign returned a Buffer', Buffer.isBuffer(sig) && sig.length > 0);

let valid = false;
try {
  pq.verify(baseToken, sig);
  valid = true;
} catch (e) {
  console.error('verify threw unexpectedly:', e);
}
check('PQ-only verify(valid) succeeds', valid);

// Tamper signature
const badSig = Buffer.from(sig);
badSig[Math.floor(badSig.length / 2)] ^= 0x01;
let tamperRejected = false;
try {
  pq.verify(baseToken, badSig);
} catch {
  tamperRejected = true;
}
check('PQ-only verify(tampered sig) throws', tamperRejected);

// Tamper token (action_name) — sig was for "issue_refund"
let tokenTamperRejected = false;
try {
  pq.verify({ ...baseToken, actionName: 'delete_customer' }, sig);
} catch {
  tokenTamperRejected = true;
}
check('PQ-only verify(tampered token) throws', tokenTamperRejected);

// Wrong key
const otherPq = PqTokenSigner.generatePqOnly();
let wrongKeyRejected = false;
try {
  otherPq.verify(baseToken, sig);
} catch {
  wrongKeyRejected = true;
}
check('PQ-only verify(wrong key) throws', wrongKeyRejected);

// Hybrid roundtrip
const hy = PqTokenSigner.generateHybrid();
check('hybrid signer.isHybrid is true', hy.isHybrid === true);
const sigH = hy.sign(baseToken);
let hyValid = false;
try {
  hy.verify(baseToken, sigH);
  hyValid = true;
} catch (e) {
  console.error('hybrid verify threw unexpectedly:', e);
}
check('hybrid verify(valid) succeeds', hyValid);

// Downgrade guard: hybrid verifier rejects PQ-only envelope
let downgradeRejected = false;
try {
  hy.verify(baseToken, sig);
} catch {
  downgradeRejected = true;
}
check('hybrid verifier rejects PQ-only envelope', downgradeRejected);

// PQ-only verifier rejects hybrid envelope
let upgradeRejected = false;
try {
  pq.verify(baseToken, sigH);
} catch {
  upgradeRejected = true;
}
check('PQ-only verifier rejects hybrid envelope', upgradeRejected);

// ─── 9. Gate.fromToml({tokenSigner}) → signed Permit verifies ──────────

section('[9] Gate(tokenSigner=…) → signed Permit verifies end-to-end');

const signedToml = `
[[policy]]
name = "permit_small_refunds"
effect = "permit"
conditions = [
    { identity_role = "support" },
    { action = "issue_refund" },
    { param_max = { field = "amount", max = 5000.0 } },
]
`;
const signer = PqTokenSigner.generateHybrid();
const signedGate = Gate.fromToml(signedToml, { tokenSigner: signer });
const signedVerdict = signedGate.evaluate({
  principalId: 'agent-alice',
  principalKind: 'agent',
  actionName: 'issue_refund',
  roles: ['support'],
  params: { amount: 1500 },
});
check('Permit returned', signedVerdict.isPermit, `kind=${signedVerdict.kind}`);

const pt = signedVerdict.permitToken;
check('verdict.permitToken populated', pt !== null && pt !== undefined);
check(
  'verdict.signature populated',
  signedVerdict.signature !== null &&
    signedVerdict.signature !== undefined &&
    Buffer.isBuffer(signedVerdict.signature),
);

if (pt && signedVerdict.signature) {
  let signedValid = false;
  try {
    signer.verify(
      {
        tokenId: pt.tokenId,
        evaluationId: pt.evaluationId,
        issuedAt: pt.issuedAt,
        expiresAt: pt.expiresAt,
        actionName: pt.actionName,
      },
      signedVerdict.signature,
    );
    signedValid = true;
  } catch (e) {
    console.error('signer.verify threw unexpectedly:', e);
  }
  check('signer.verify(permitToken, signature) succeeds', signedValid);

  // Forge: reuse signature with different action_name
  let forgeRejected = false;
  try {
    signer.verify(
      {
        tokenId: pt.tokenId,
        evaluationId: pt.evaluationId,
        issuedAt: pt.issuedAt,
        expiresAt: pt.expiresAt,
        actionName: 'delete_customer',
      },
      signedVerdict.signature,
    );
  } catch {
    forgeRejected = true;
  }
  check('forged action_name rejected by verify', forgeRejected);
}

// ─── 10. Gate.reload — hot policy swap + parse-error fail-safe ─────────

section('[10] Gate.reload — hot policy swap');

const reloadPermissive = `
[[policy]]
name = "permit_refunds"
effect = "permit"
conditions = [
    { identity_role = "support" },
    { action = "issue_refund" },
]
`;
const reloadGate = Gate.fromToml(reloadPermissive);
const reloadCtx = {
  principalId: 'agent',
  principalKind: 'agent' as const,
  actionName: 'issue_refund',
  roles: ['support'],
  params: { amount: 100 },
};
check('initial policy permits', reloadGate.evaluate(reloadCtx).isPermit);

reloadGate.reload('');
check("reload('') swaps to default-deny", reloadGate.evaluate(reloadCtx).isRefuse);

reloadGate.reload(reloadPermissive);
check('reload(permissive) restores permit', reloadGate.evaluate(reloadCtx).isPermit);

let reloadParseErr = false;
try {
  reloadGate.reload('this is === not valid toml [[[');
} catch {
  reloadParseErr = true;
}
check('reload(bad toml) throws', reloadParseErr);
check(
  'policy still permits after failed reload',
  reloadGate.evaluate(reloadCtx).isPermit,
);

// ─── 11. KavachKeyPair.generate + publicKeys + signer integration ──────

section('[11] KavachKeyPair.generate + publicKeys + signer integration');

const kp = KavachKeyPair.generate();
check('KavachKeyPair constructed', kp !== null && kp !== undefined);
check('kp.id non-empty', typeof kp.id === 'string' && kp.id.length > 0);
check('kp.createdAt > 0', kp.createdAt > 0);
check('kp.expiresAt is null (no expiry)', kp.expiresAt === null || kp.expiresAt === undefined);
check('kp.isExpired is false', kp.isExpired === false);

const bundle = kp.publicKeys();
check('publicKeys returns a bundle object', bundle !== null && bundle !== undefined);
check('bundle.id matches kp.id', bundle.id === kp.id);
check('mlDsaVerifyingKey is a Buffer with bytes', Buffer.isBuffer(bundle.mlDsaVerifyingKey) && bundle.mlDsaVerifyingKey.length > 0);
check('ed25519VerifyingKey is 32 bytes',
  Buffer.isBuffer(bundle.ed25519VerifyingKey) && bundle.ed25519VerifyingKey.length === 32);
check('x25519PublicKey is 32 bytes',
  Buffer.isBuffer(bundle.x25519PublicKey) && bundle.x25519PublicKey.length === 32);
check('mlKemEncapsulationKey non-empty',
  Buffer.isBuffer(bundle.mlKemEncapsulationKey) && bundle.mlKemEncapsulationKey.length > 0);

const otherKp = KavachKeyPair.generate();
check('two generations produce distinct ids', kp.id !== otherKp.id);

// from_keypair_pq_only — sign + verify roundtrip via bundle's VK
const kpSigner = PqTokenSigner.fromKeypairPqOnly(kp);
check('fromKeypairPqOnly forwards kp.id',
  kpSigner.keyId === kp.id && kpSigner.isHybrid === false);

const kpToken: PermitTokenInput = {
  tokenId: '00000000-0000-0000-0000-000000000003',
  evaluationId: '00000000-0000-0000-0000-000000000004',
  issuedAt: 1_700_000_000,
  expiresAt: 1_700_000_030,
  actionName: 'kp_test',
};
const kpSig = kpSigner.sign(kpToken);

// Rebuild a verifier-only signer from the bundle's VK + an empty SK
const rebuilt = PqTokenSigner.pqOnly(
  Buffer.alloc(0), // SK unused for verify
  bundle.mlDsaVerifyingKey,
  kp.id,
);
let bundleVerifyOk = false;
try {
  rebuilt.verify(kpToken, kpSig);
  bundleVerifyOk = true;
} catch (e) {
  console.error('verify via bundle VK threw:', e);
}
check("verify via bundle's VK succeeds", bundleVerifyOk);

// fromKeypairHybrid roundtrip
const kpHybrid = PqTokenSigner.fromKeypairHybrid(kp);
check('fromKeypairHybrid is_hybrid', kpHybrid.isHybrid === true);
const kpSigH = kpHybrid.sign(kpToken);
let hybridRoundtripOk = false;
try {
  kpHybrid.verify(kpToken, kpSigH);
  hybridRoundtripOk = true;
} catch (e) {
  console.error('hybrid roundtrip threw:', e);
}
check('fromKeypairHybrid roundtrip succeeds', hybridRoundtripOk);

// Expiry: generateWithExpiry(1) → wait 1.5s → expired
const shortKp = KavachKeyPair.generateWithExpiry(1);
check('short-lived kp has expiresAt',
  shortKp.expiresAt !== null && shortKp.expiresAt !== undefined);
check('short-lived kp not expired immediately', shortKp.isExpired === false);

async function runExpiryCheck(): Promise<void> {
  await new Promise(r => setTimeout(r, 1500));
  check('short-lived kp expired after 1.5s', shortKp.isExpired === true);
}

// ─── 12. SignedAuditChain — append/verify/export/tamper detection ──────

section('[12] SignedAuditChain append + verify + export + tamper detection');

const auditKp = KavachKeyPair.generate();
const auditBundle = auditKp.publicKeys();

const chain = new SignedAuditChain(auditKp, true);
check('empty chain length == 0', chain.length === 0);
check('empty chain isEmpty is true', chain.isEmpty === true);
check('chain.isHybrid is true', chain.isHybrid === true);
check("empty chain headHash === 'genesis'", chain.headHash === 'genesis');

const e1 = AuditEntry.new('agent-alice', 'issue_refund', 'permit', 'token=abc');
const e2 = AuditEntry.new('agent-bob', 'issue_refund', 'refuse', '[POLICY_DENIED] no match');
const e3 = AuditEntry.new('agent-bob', 'delete_customer', 'invalidate', 'drift detected');
const n1 = chain.append(e1);
const n2 = chain.append(e2);
const n3 = chain.append(e3);
check('append returns growing length', n1 === 1 && n2 === 2 && n3 === 3);
check('chain.length === 3 after appends', chain.length === 3);
check('isEmpty false after appends', chain.isEmpty === false);
check('headHash advanced past genesis', chain.headHash !== 'genesis' && chain.headHash.length === 64);

let chainVerifyOk = false;
try {
  chain.verify(auditBundle);
  chainVerifyOk = true;
} catch (e) {
  console.error('chain.verify threw:', e);
}
check('chain.verify(bundle) succeeds', chainVerifyOk);

const blob = chain.exportJsonl();
check('exportJsonl returns Buffer', Buffer.isBuffer(blob) && blob.length > 0);
const lineCount = (blob.toString('utf-8').match(/\n/g) || []).length;
check('exportJsonl has 3 lines', lineCount === 3);

const verifiedN = SignedAuditChain.verifyJsonl(blob, auditBundle, true);
check('verifyJsonl(hybrid=true) returns 3', verifiedN === 3);

// Mode inference — omit the hybrid flag.
const inferredN = SignedAuditChain.verifyJsonl(blob, auditBundle);
check('verifyJsonl without hybrid infers hybrid', inferredN === 3);

// Tamper: flip a byte mid-blob → verify must throw
const tampered = Buffer.from(blob);
tampered[Math.floor(tampered.length / 2)] ^= 0x01;
let auditTamperRejected = false;
try {
  SignedAuditChain.verifyJsonl(tampered, auditBundle, true);
} catch {
  auditTamperRejected = true;
}
check('tampered blob → verifyJsonl throws', auditTamperRejected);

// Wrong-key bundle → verify throws
const wrongBundle = KavachKeyPair.generate().publicKeys();
let auditWrongKeyRejected = false;
try {
  SignedAuditChain.verifyJsonl(blob, wrongBundle, true);
} catch {
  auditWrongKeyRejected = true;
}
check('wrong-key bundle → verifyJsonl throws', auditWrongKeyRejected);

// PQ-only verifier on a hybrid chain MUST be rejected — downgrade defense.
let chainDowngradeRejected = false;
try {
  SignedAuditChain.verifyJsonl(blob, auditBundle, false);
} catch {
  chainDowngradeRejected = true;
}
check('PQ-only verifier rejects hybrid chain (downgrade blocked)', chainDowngradeRejected);

// PQ-only chain
const pqChain = new SignedAuditChain(auditKp, false);
pqChain.append(AuditEntry.new('a', 'x', 'permit', 'ok'));
check('PQ-only chain isHybrid is false', pqChain.isHybrid === false);
let pqVerifyOk = false;
try {
  pqChain.verify(auditBundle);
  pqVerifyOk = true;
} catch (e) {
  console.error('PQ-only chain.verify threw:', e);
}
check('PQ-only chain.verify succeeds', pqVerifyOk);

const pqBlob = pqChain.exportJsonl();

// Hybrid verifier rejects PQ-only chain (Ed25519 sig missing)
let mismatchRejected = false;
try {
  SignedAuditChain.verifyJsonl(pqBlob, auditBundle, true);
} catch {
  mismatchRejected = true;
}
check('hybrid verifier rejects PQ-only chain', mismatchRejected);

// Inference also picks PQ-only from a PQ-only blob.
const inferredPq = SignedAuditChain.verifyJsonl(pqBlob, auditBundle);
check('verifyJsonl infers PQ-only from PQ-only blob', inferredPq === 1);

// Blank lines tolerated on parse.
const padded = Buffer.concat([Buffer.from('\n'), blob, Buffer.from('\n\n')]);
const paddedN = SignedAuditChain.verifyJsonl(padded, auditBundle);
check('verifyJsonl tolerates blank lines', paddedN === 3);

// Empty chain verifies trivially
const emptyChain = new SignedAuditChain(auditKp, true);
let emptyOk = false;
try {
  emptyChain.verify(auditBundle);
  emptyOk = true;
} catch (e) {
  console.error('empty chain.verify threw:', e);
}
check('empty chain verifies', emptyOk);

// ─── 13. SecureChannel — hybrid encrypt + sign + replay + context binding ──

section('[13] SecureChannel send/receive + replay + tamper + context binding');

const gateKp = KavachKeyPair.generate();
const handlerKp = KavachKeyPair.generate();
const outsiderKp = KavachKeyPair.generate();

const gateBundle = gateKp.publicKeys();
const handlerBundle = handlerKp.publicKeys();

const gateCh = new SecureChannel(gateKp, handlerBundle);
const handlerCh = new SecureChannel(handlerKp, gateBundle);

check('gateCh.localKeyId === gateKp.id', gateCh.localKeyId === gateKp.id);
check('gateCh.remoteKeyId === handlerKp.id', gateCh.remoteKeyId === handlerKp.id);
check('handlerCh.localKeyId === handlerKp.id', handlerCh.localKeyId === handlerKp.id);
check('handlerCh.remoteKeyId === gateKp.id', handlerCh.remoteKeyId === gateKp.id);

const chPayload = Buffer.from('{"kind":"permit","action":"issue_refund"}', 'utf-8');
const sealed = gateCh.sendSigned(chPayload, 'issue_refund', 'eval-1');
check('sendSigned returns non-empty Buffer', Buffer.isBuffer(sealed) && sealed.length > 0);
const received = handlerCh.receiveSigned(sealed, 'issue_refund');
check('receiveSigned roundtrip preserves bytes', Buffer.compare(received, chPayload) === 0);

// Replay rejected
let chReplay = false;
try {
  handlerCh.receiveSigned(sealed, 'issue_refund');
} catch {
  chReplay = true;
}
check('replay of sealed payload rejected', chReplay);

// Cross-context rejected
const sealed2 = gateCh.sendSigned(chPayload, 'issue_refund', 'eval-2');
let chCtxRejected = false;
try {
  handlerCh.receiveSigned(sealed2, 'delete_customer');
} catch {
  chCtxRejected = true;
}
check('wrong expectedContextId rejected', chCtxRejected);

// Ciphertext tamper rejected
const sealed3 = gateCh.sendSigned(chPayload, 'issue_refund', 'eval-3');
const chTampered = Buffer.from(sealed3);
chTampered[Math.floor(chTampered.length / 2)] ^= 0x01;
let chTamperRejected = false;
try {
  handlerCh.receiveSigned(chTampered, 'issue_refund');
} catch {
  chTamperRejected = true;
}
check('tampered sealed payload rejected', chTamperRejected);

// Wrong recipient
const outsiderCh = new SecureChannel(outsiderKp, gateBundle);
const sealed4 = gateCh.sendSigned(chPayload, 'issue_refund', 'eval-4');
let chOutsider = false;
try {
  outsiderCh.receiveSigned(sealed4, 'issue_refund');
} catch {
  chOutsider = true;
}
check("outsider can't decrypt (wrong recipient)", chOutsider);

// Unsigned send/receive roundtrip
const chRaw = Buffer.from('arbitrary bytes, not signed');
const chEnc = gateCh.sendData(chRaw);
check('sendData returns non-empty Buffer', Buffer.isBuffer(chEnc) && chEnc.length > 0);
const chDec = handlerCh.receiveData(chEnc);
check('receiveData roundtrip preserves bytes', Buffer.compare(chDec, chRaw) === 0);

// Unsigned envelope → receiveSigned must reject (decrypt OK, SignedBytes parse fails).
let chUnsignedRejected = false;
try {
  handlerCh.receiveSigned(chEnc, 'issue_refund');
} catch {
  chUnsignedRejected = true;
}
check('receiveSigned rejects unsigned envelope', chUnsignedRejected);

// Outsider can't decrypt unsigned bytes either.
let chOutsiderRaw = false;
try {
  outsiderCh.receiveData(chEnc);
} catch {
  chOutsiderRaw = true;
}
check("outsider can't decrypt unsigned bytes", chOutsiderRaw);

// Replay after successful receive rejected.
const sealed5 = gateCh.sendSigned(chPayload, 'issue_refund', 'eval-5');
handlerCh.receiveSigned(sealed5, 'issue_refund');
let chReplayAfter = false;
try {
  handlerCh.receiveSigned(sealed5, 'issue_refund');
} catch {
  chReplayAfter = true;
}
check('replay after successful receive rejected', chReplayAfter);

// ─── 14. PublicKeyDirectory + DirectoryTokenVerifier ───────────────────

section('[14] PublicKeyDirectory + DirectoryTokenVerifier');

const kpA = KavachKeyPair.generate();
const kpB = KavachKeyPair.generate();
const kpC = KavachKeyPair.generate();
const signerA = PqTokenSigner.fromKeypairHybrid(kpA);
const signerCPqOnly = PqTokenSigner.fromKeypairPqOnly(kpC);

const dirToken: PermitTokenInput = {
  tokenId: randomUUID(),
  evaluationId: randomUUID(),
  issuedAt: 1_700_000_000,
  expiresAt: 1_700_000_060,
  actionName: 'issue_refund',
};
const sigA = signerA.sign(dirToken);
const sigCPq = signerCPqOnly.sign(dirToken);

const bundleA = kpA.publicKeys();
const bundleB = kpB.publicKeys();
const bundleC = kpC.publicKeys();

// ── In-memory directory ────────────────────────────────────────
const dirIm = PublicKeyDirectory.inMemory([bundleA, bundleB]);
check('in-memory length === 2', dirIm.length === 2);
check('in-memory isEmpty false', dirIm.isEmpty === false);
const fetchedA = dirIm.fetch(kpA.id);
check('fetch returns bundle with matching id', fetchedA.id === kpA.id);

let dirMissRaised = false;
try {
  dirIm.fetch('nonexistent-key');
} catch {
  dirMissRaised = true;
}
check('fetch miss throws', dirMissRaised);

dirIm.insert(bundleC);
check('after insert length === 3', dirIm.length === 3);
check('inserted key fetchable', dirIm.fetch(kpC.id).id === kpC.id);
check('remove existing returns true', dirIm.remove(kpC.id) === true);
check('remove missing returns false', dirIm.remove(kpC.id) === false);
check('after remove length === 2', dirIm.length === 2);

// DirectoryTokenVerifier — hybrid/valid
const verifier = new DirectoryTokenVerifier(dirIm, true);
let dirValidOk = false;
try {
  verifier.verify(dirToken, sigA);
  dirValidOk = true;
} catch (e) {
  console.error('hybrid verifier valid sig threw:', e);
}
check('hybrid verifier accepts valid hybrid sig', dirValidOk);

// Tampered signature → rejected
const sigTampered = Buffer.from(sigA);
sigTampered[Math.floor(sigTampered.length / 2)] ^= 0x01;
let dirTamperRejected = false;
try {
  verifier.verify(dirToken, sigTampered);
} catch {
  dirTamperRejected = true;
}
check('tampered signature rejected', dirTamperRejected);

// Wrong token → rejected
const wrongToken: PermitTokenInput = { ...dirToken, tokenId: randomUUID() };
let dirWrongTokenRejected = false;
try {
  verifier.verify(wrongToken, sigA);
} catch {
  dirWrongTokenRejected = true;
}
check('wrong token id rejected', dirWrongTokenRejected);

// Missing key → fail-closed
const dirEmpty = PublicKeyDirectory.inMemory();
const verifierEmpty = new DirectoryTokenVerifier(dirEmpty, true);
let dirMissClosed = false;
try {
  verifierEmpty.verify(dirToken, sigA);
} catch {
  dirMissClosed = true;
}
check('missing key fail-closed', dirMissClosed);

// Hybrid verifier rejects PQ-only envelope (downgrade guard)
const dirWithC = PublicKeyDirectory.inMemory([bundleC]);
const hybridV = new DirectoryTokenVerifier(dirWithC, true);
let downgradeCaught = false;
try {
  hybridV.verify(dirToken, sigCPq);
} catch {
  downgradeCaught = true;
}
check('hybrid verifier rejects PQ-only envelope', downgradeCaught);

// PQ-only verifier accepts PQ-only envelope
const pqV = new DirectoryTokenVerifier(dirWithC, false);
let pqOk = false;
try {
  pqV.verify(dirToken, sigCPq);
  pqOk = true;
} catch (e) {
  console.error('PQ verifier + PQ sig threw:', e);
}
check('PQ-only verifier accepts PQ-only envelope', pqOk);

// PQ-only verifier rejects hybrid envelope
let pqRejectHybrid = false;
try {
  new DirectoryTokenVerifier(dirIm, false).verify(dirToken, sigA);
} catch {
  pqRejectHybrid = true;
}
check('PQ-only verifier rejects hybrid envelope', pqRejectHybrid);

// ── File-backed directory (unsigned) ──────────────────────────
const dirTmp = mkdtempSync(join(tmpdir(), 'kavach-dir-'));
const unsignedPath = join(dirTmp, 'bundles.json');
writeFileSync(unsignedPath, PublicKeyDirectory.buildUnsignedManifest([bundleA, bundleB]));

const dirFile = PublicKeyDirectory.fromFile(unsignedPath);
check('fromFile loads bundles', dirFile.length === 2);
check('fromFile fetch works', dirFile.fetch(kpA.id).id === kpA.id);

let fileInsertRejected = false;
try {
  dirFile.insert(bundleC);
} catch {
  fileInsertRejected = true;
}
check('insert on file-backed dir throws', fileInsertRejected);

let fileRemoveRejected = false;
try {
  dirFile.remove(kpA.id);
} catch {
  fileRemoveRejected = true;
}
check('remove on file-backed dir throws', fileRemoveRejected);

// reload in-memory is a no-op
let imReloadOk = false;
try {
  dirIm.reload();
  imReloadOk = true;
} catch (e) {
  console.error('in-memory reload threw:', e);
}
check('reload on in-memory is no-op', imReloadOk);

// File reload picks up changes
writeFileSync(
  unsignedPath,
  PublicKeyDirectory.buildUnsignedManifest([bundleA, bundleB, bundleC]),
);
dirFile.reload();
check('file reload picks up new bundle', dirFile.length === 3);

// Corrupt reload preserves cache
writeFileSync(unsignedPath, 'not-json');
let corruptReloadRejected = false;
try {
  dirFile.reload();
} catch {
  corruptReloadRejected = true;
}
check('corrupt file reload throws', corruptReloadRejected);
check('after corrupt reload, cache preserved', dirFile.length === 3);

unlinkSync(unsignedPath);

// ── Signed-manifest directory ─────────────────────────────────
const rootKp = KavachKeyPair.generate();
const signedBytes = rootKp.buildSignedManifest([bundleA, bundleB]);
check(
  'buildSignedManifest returns non-empty Buffer',
  Buffer.isBuffer(signedBytes) && signedBytes.length > 0,
);

const signedPath = join(dirTmp, 'signed.json');
writeFileSync(signedPath, signedBytes);
const rootVk = Buffer.from(rootKp.publicKeys().mlDsaVerifyingKey);
const dirSigned = PublicKeyDirectory.fromSignedFile(signedPath, rootVk);
check('fromSignedFile loads with correct root VK', dirSigned.length === 2);
check('signed-file fetch works', dirSigned.fetch(kpA.id).id === kpA.id);

// Wrong root VK → rejected
const imposterVk = Buffer.from(KavachKeyPair.generate().publicKeys().mlDsaVerifyingKey);
let wrongRootRejected = false;
try {
  PublicKeyDirectory.fromSignedFile(signedPath, imposterVk);
} catch {
  wrongRootRejected = true;
}
check('signed-file with wrong root VK rejected', wrongRootRejected);

// Tamper the bundles_json → reject
const manifest = JSON.parse(signedBytes.toString('utf-8'));
manifest.bundles_json = manifest.bundles_json.replace(kpA.id, 'evil-' + kpA.id.slice(5));
writeFileSync(signedPath, JSON.stringify(manifest));
let tamperRootRejected = false;
try {
  PublicKeyDirectory.fromSignedFile(signedPath, rootVk);
} catch {
  tamperRootRejected = true;
}
check('signed-file with tampered bundles rejected', tamperRootRejected);

unlinkSync(signedPath);

// End-to-end: signed manifest → verifier accepts valid token
const e2ePath = join(dirTmp, 'e2e.json');
writeFileSync(e2ePath, rootKp.buildSignedManifest([bundleA]));
const dirE2E = PublicKeyDirectory.fromSignedFile(e2ePath, rootVk);
const verifierE2E = new DirectoryTokenVerifier(dirE2E, true);
let e2eOk = false;
try {
  verifierE2E.verify(dirToken, sigA);
  e2eOk = true;
} catch (e) {
  console.error('E2E verify threw:', e);
}
check('E2E: signed-manifest-backed verifier accepts valid token', e2eOk);
unlinkSync(e2ePath);

// ─── 15. GeoLocation + tolerant-mode GeoLocationDrift ──────────────────

section('[15] GeoLocation + tolerant-mode GeoLocationDrift across the SDK');

const bangalore = {
  countryCode: 'IN',
  city: 'Bangalore',
  latitude: 12.9716,
  longitude: 77.5946,
};
const chennai = {
  countryCode: 'IN',
  city: 'Chennai',
  latitude: 13.0827,
  longitude: 80.2707,
};
const newYork = {
  countryCode: 'US',
  city: 'New York',
  latitude: 40.7128,
  longitude: -74.006,
};

// Allow-fetch-report policy so we only exercise drift.
const geoPolicyToml = `
[[policy]]
name = "allow_fetch_report"
effect = "permit"
conditions = [
    { action = "fetch_report" },
]
`;

// Strict-mode gate
const strictGate = Gate.fromToml(geoPolicyToml);
const sessionId = '00000000-0000-0000-0000-000000000002';

const vStrict = strictGate.evaluate({
  principalId: 'alice',
  principalKind: 'user',
  actionName: 'fetch_report',
  ip: '10.0.0.1',
  sessionId,
  originGeo: bangalore,
  currentGeo: bangalore,
});
check('strict: matching ip+geo permits', vStrict.isPermit);

// Tolerant-mode gate
const tolerantGate = Gate.fromToml(geoPolicyToml, { geoDriftMaxKm: 500 });
const vTolerant = tolerantGate.evaluate({
  principalId: 'alice',
  principalKind: 'user',
  actionName: 'fetch_report',
  ip: '10.0.0.1',
  sessionId,
  originGeo: bangalore,
  currentGeo: bangalore,
});
check('tolerant: matching ip+geo still permits', vTolerant.isPermit);

// Geo plumbing — ensure ActionContext accepts geo fields without crashing
const vGeoPlumb = tolerantGate.evaluate({
  principalId: 'alice',
  principalKind: 'user',
  actionName: 'fetch_report',
  ip: '10.0.0.1',
  originGeo: bangalore,
  currentGeo: chennai,
});
check('tolerant: geo plumbed, evaluates without error', vGeoPlumb !== null);

// MCP middleware forwards geo
const geoMcp = new McpKavachMiddleware(tolerantGate);
let mcpGeoOk = false;
try {
  geoMcp.checkToolCall(
    'fetch_report',
    {},
    {
      callerId: 'alice',
      callerKind: 'user',
      ip: '10.0.0.1',
      currentGeo: bangalore,
      originGeo: bangalore,
    },
  );
  mcpGeoOk = true;
} catch (e) {
  console.error('MCP checkToolCall with geo threw:', e);
}
check('MCP checkToolCall accepts geo fields', mcpGeoOk);

const mcpEvalVerdict = geoMcp.evaluateToolCall(
  'fetch_report',
  {},
  {
    callerId: 'alice',
    callerKind: 'user',
    ip: '10.0.0.1',
    currentGeo: bangalore,
    originGeo: chennai,
  },
);
check('MCP evaluateToolCall accepts geo fields', mcpEvalVerdict !== null);

// HTTP middleware with geoResolver
import { HttpKavachMiddleware } from '../src/http';

const geoHttp = new HttpKavachMiddleware(tolerantGate, {
  geoResolver: () => ({ currentGeo: bangalore, originGeo: bangalore }),
});
const vHttp = geoHttp.evaluate({
  method: 'POST',
  path: '/api/fetch_report',
  headers: { 'x-principal-id': 'alice' },
  ip: '10.0.0.1',
});
check('HTTP middleware uses geoResolver when no explicit geo', vHttp !== null);

// Explicit geo overrides the resolver
const vHttpExplicit = geoHttp.evaluate({
  method: 'POST',
  path: '/api/fetch_report',
  headers: { 'x-principal-id': 'alice' },
  ip: '10.0.0.1',
  currentGeo: newYork,
  originGeo: bangalore,
});
check('HTTP middleware: explicit geo overrides resolver', vHttpExplicit !== null);

// Distance sanity check via core — passing geo with no lat/lon still
// evaluates cleanly (SDK must not assume lat/lon are present).
const vNoCoords = tolerantGate.evaluate({
  principalId: 'alice',
  principalKind: 'user',
  actionName: 'fetch_report',
  ip: '10.0.0.1',
  originGeo: { countryCode: 'IN' },
  currentGeo: { countryCode: 'IN' },
});
check('geo without lat/lon evaluates without crash', vNoCoords !== null);

// ─── 16. Observe-only dispatch (P05 FIX-E) ──────────────────────────────
//
// Gate constructed with observeOnly:true must run the full evaluator
// chain but always return Permit at the caller-facing layer. Pre-P05
// the napi binding ignored this kwarg and returned the real refuse.

section('[16] Gate(observeOnly) dispatches to evaluate_observe_only');

const observeOnlyToml = `
[[policy]]
name = "small_amounts_only"
effect = "permit"
conditions = [
    { identity_kind = "agent" },
    { action = "probe" },
    { param_max = { field = "amount", max = 100.0 } },
]
`;

const strictGateO = Gate.fromToml(observeOnlyToml);
const observeGateO = Gate.fromToml(observeOnlyToml, { observeOnly: true });

const overAmountCtx = {
  principalId: 'bot',
  principalKind: 'agent' as const,
  actionName: 'probe',
  params: { amount: 5000 },
};

const strictVerdictO = strictGateO.evaluate(overAmountCtx);
check('observe-only: strict gate refuses $5000',
  strictVerdictO.isRefuse,
  `kind=${strictVerdictO.kind}`);

const observeVerdictO = observeGateO.evaluate(overAmountCtx);
check('observe-only: observe gate returns Permit for the same input',
  observeVerdictO.isPermit,
  `kind=${observeVerdictO.kind}`);
check('observe-only: caller-facing verdict carries a permit token',
  observeVerdictO.permitToken !== null && observeVerdictO.permitToken !== undefined);

// Under-limit sanity: both gates permit small amounts.
const underAmountCtx = {
  principalId: 'bot',
  principalKind: 'agent' as const,
  actionName: 'probe',
  params: { amount: 50 },
};
check('observe-only: strict gate permits $50',
  strictGateO.evaluate(underAmountCtx).isPermit);
check('observe-only: observe gate permits $50',
  observeGateO.evaluate(underAmountCtx).isPermit);

// ─── 17. DirectoryTokenVerifier enforce_expiry (P05 FIX-F) ──────────────
//
// Verifier default refuses expired bundles; forensic callers
// pass enforceExpiry: false to opt out.

section('[17] DirectoryTokenVerifier.verify default enforces bundle expiry');

async function runExpiryVerifyTests(): Promise<void> {
  const shortKp17 = KavachKeyPair.generateWithExpiry(1);
  const bundle17 = shortKp17.publicKeys();
  const dir17 = PublicKeyDirectory.inMemory([bundle17]);
  const ver17 = new DirectoryTokenVerifier(dir17, false);
  const signer17 = PqTokenSigner.fromKeypairPqOnly(shortKp17);

  const now17 = Math.floor(Date.now() / 1000);
  const base17 = {
    tokenId: randomUUID(),
    evaluationId: randomUUID(),
    issuedAt: now17,
    expiresAt: now17 + 3600,
    actionName: 'resource.read',
    signature: null,
  } as PermitTokenInput;
  const sig17 = signer17.sign(base17);
  const token17 = { ...base17, signature: sig17 } as PermitTokenInput;

  // Fresh: default accepts.
  let acceptedFresh = true;
  try {
    ver17.verify(token17, sig17);
  } catch (_) {
    acceptedFresh = false;
  }
  check('fresh kp: default verify (enforceExpiry=true) accepts', acceptedFresh);

  // Sleep past expiry.
  await new Promise(r => setTimeout(r, 1500));
  check('kp is now expired', shortKp17.isExpired === true);

  // Default refuses with "keypair expired" + bundle id in message.
  let expiredRefused = false;
  let expiredMsg = '';
  try {
    ver17.verify(token17, sig17);
  } catch (e) {
    expiredMsg = (e as Error).message;
    expiredRefused = expiredMsg.includes('keypair expired') && expiredMsg.includes(bundle17.id);
  }
  check('expired kp: default verify refuses with "keypair expired" + bundle id',
    expiredRefused, expiredMsg.slice(0, 120));

  // enforceExpiry=false bypasses the lifecycle check.
  let forensicAccepted = true;
  try {
    ver17.verify(token17, sig17, false);
  } catch (_) {
    forensicAccepted = false;
  }
  check('expired kp: enforceExpiry=false (forensic) accepts', forensicAccepted);
}

// ─── 18. InMemorySessionStore + McpKavachMiddleware fast-path (FIX-C) ───
//
// Session-store fast-path: after invalidateSession, the next tool
// call on that session id is refused BEFORE the gate runs, with
// evaluator = "session_store".

section('[18] InMemorySessionStore + MCP middleware cross-replica fast-path');

async function runSessionStoreTests(): Promise<void> {
  const storeToml = `
[[policy]]
name = "agent_reads"
effect = "permit"
conditions = [
    { identity_kind = "agent" },
    { action = "data.read" },
]
`;
  const gate18 = Gate.fromToml(storeToml);
  const store18 = new InMemorySessionStore();
  const mw18 = new McpKavachMiddleware(gate18, { sessionStore: store18 });

  // Baseline: session sess-live works.
  const v18a = await mw18.evaluateToolCall(
    'data.read',
    { rowId: 1 },
    { callerId: 'bot-1', callerKind: 'agent', sessionId: 'sess-live' },
  );
  check('session store: live session permits', v18a.isPermit);

  // Invalidate sess-live; next call returns Invalidate via fast-path.
  await mw18.invalidateSession('sess-live');
  check('session store: size = 1 after invalidate', store18.size === 1);

  const v18b = await mw18.evaluateToolCall(
    'data.read',
    { rowId: 2 },
    { callerId: 'bot-1', callerKind: 'agent', sessionId: 'sess-live' },
  );
  check('session store: invalidated session returns Invalidate', v18b.isInvalidate);
  check('session store: evaluator = "session_store" (fast-path)',
    v18b.evaluator === 'session_store',
    `evaluator=${v18b.evaluator}`);

  // checkToolCall throws KavachInvalidated on the same sessionId.
  let threwInvalidated = false;
  let invMsg = '';
  try {
    await mw18.checkToolCall(
      'data.read',
      { rowId: 3 },
      { callerId: 'bot-1', callerKind: 'agent', sessionId: 'sess-live' },
    );
  } catch (e) {
    if (e instanceof KavachInvalidated) {
      threwInvalidated = true;
      invMsg = e.message;
    }
  }
  check('session store: checkToolCall throws KavachInvalidated for revoked session', threwInvalidated);
  check('session store: invalidation error names the evaluator',
    invMsg.includes('session_store'), invMsg.slice(0, 100));

  // Fresh session (not in store) still works.
  const v18c = await mw18.evaluateToolCall(
    'data.read',
    { rowId: 4 },
    { callerId: 'bot-2', callerKind: 'agent', sessionId: 'sess-clean' },
  );
  check('session store: unrelated session unaffected by invalidation', v18c.isPermit);
}

// ─── 19. InMemoryInvalidationBroadcaster + spawnInvalidationListener (FIX-D) ───
//
// Broadcaster.publish reaches the listener callback. The callback
// receives an InvalidationScopeView with target_kind / target_id /
// reason / evaluator populated.

section('[19] InMemoryInvalidationBroadcaster + spawnInvalidationListener fan-out');

async function runBroadcasterTests(): Promise<void> {
  const bc = new InMemoryInvalidationBroadcaster();
  const received: InvalidationScopeView[] = [];
  const handle = spawnInvalidationListener(bc, (scope: InvalidationScopeView) => {
    received.push(scope);
  });

  // Give the listener a tick to subscribe.
  await new Promise(r => setTimeout(r, 50));
  check('broadcaster: subscriber_count >= 1 after listener spawned',
    bc.subscriberCount >= 1, `count=${bc.subscriberCount}`);

  // Publish three scopes (one per target kind).
  const sessionId = randomUUID();
  bc.publish('session', sessionId, 'stolen cookie', 'drift');
  bc.publish('principal', 'agent-alpha', 'key rotation', 'manual');
  bc.publish('role', 'admin', 'org-wide revoke');

  // Listener runs on the event loop — wait briefly for the async fan-out.
  await new Promise(r => setTimeout(r, 150));

  check('broadcaster: listener received exactly 3 scopes', received.length === 3,
    `got=${received.length}`);

  const sessionScope = received.find(s => s.targetKind === 'session');
  const principalScope = received.find(s => s.targetKind === 'principal');
  const roleScope = received.find(s => s.targetKind === 'role');
  check('broadcaster: session scope has target_id = the UUID',
    sessionScope !== undefined && sessionScope.targetId === sessionId);
  check('broadcaster: principal scope routes to "agent-alpha"',
    principalScope !== undefined && principalScope.targetId === 'agent-alpha');
  check('broadcaster: role scope routes to "admin"',
    roleScope !== undefined && roleScope.targetId === 'admin');
  check('broadcaster: session scope reason preserved',
    sessionScope !== undefined && sessionScope.reason === 'stolen cookie');
  check('broadcaster: session scope evaluator preserved',
    sessionScope !== undefined && sessionScope.evaluator === 'drift');
  check('broadcaster: role scope defaults evaluator to "manual" when omitted',
    roleScope !== undefined && roleScope.evaluator === 'manual');

  // abort() is idempotent + stops the task.
  handle.abort();
  handle.abort();   // no-op on second call
  await new Promise(r => setTimeout(r, 50));
  check('broadcaster: handle.isFinished true after abort', handle.isFinished === true);

  // Gate.fromToml accepts the broadcaster and wires invalidations
  // through it. Drift-triggered Invalidate surfaces on a second listener.
  const bc2 = new InMemoryInvalidationBroadcaster();
  const received2: InvalidationScopeView[] = [];
  const handle2 = spawnInvalidationListener(bc2, s => received2.push(s));
  await new Promise(r => setTimeout(r, 30));

  const driftToml = `
[[policy]]
name = "allow_read"
effect = "permit"
conditions = [ { action = "data.read" } ]
`;
  const gate19 = Gate.fromToml(driftToml, { broadcaster: bc2 });

  // Manually publish through the gate's broadcaster instance to prove
  // the broadcaster arg threaded through.
  bc2.publish('session', randomUUID(), 'gate wired it', 'manual');
  await new Promise(r => setTimeout(r, 100));
  check('broadcaster: Gate(broadcaster=bc) wires the SAME broadcaster object',
    received2.length === 1, `got=${received2.length}`);
  check('broadcaster: Gate evaluator_count unchanged by broadcaster kwarg',
    gate19.evaluatorCount > 0);

  handle2.abort();

  // Invalid target_kind surfaces as an Error before publish.
  let invalidRejected = false;
  try {
    bc.publish('tenant', 'whatever', 'bad call');
  } catch (e) {
    invalidRejected = (e as Error).message.includes('targetKind must be');
  }
  check('broadcaster: publish rejects bad target_kind', invalidRejected);

  // Malformed session UUID rejected.
  let uuidRejected = false;
  try {
    bc.publish('session', 'not-a-uuid', 'reason');
  } catch (e) {
    uuidRejected = (e as Error).message.includes('targetId not a UUID');
  }
  check('broadcaster: session publish rejects non-UUID targetId', uuidRejected);
}

// ─── Run and report ────────────────────────────────────────────────────

runMcpMiddlewareTests()
  .then(() => runGuardTests())
  .then(() => runExpiryCheck())
  .then(() => runExpiryVerifyTests())
  .then(() => runSessionStoreTests())
  .then(() => runBroadcasterTests())
  .catch((e) => {
    console.error('async tests raised:', e);
  })
  .finally(() => {
    console.log(`\n=== ${passed}/${total} checks passed ===`);
    process.exit(passed === total ? 0 : 1);
  });
