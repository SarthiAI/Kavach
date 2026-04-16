# kavach

**Post-quantum execution boundary enforcement for AI agents, APIs, and distributed systems — TypeScript SDK.**

Kavach separates *possession of credentials* from *permission to act*. Every action passes through a gate that evaluates identity, policy, drift, and invariants before producing a verdict. All evaluation runs in compiled Rust via napi-rs; this package is the idiomatic TypeScript wrapper.

```
Action attempted ──▶ Gate (identity · policy · drift · invariants) ──▶ Permit / Refuse / Invalidate
```

---

## Install

```bash
npm install kavach
```

Native addons are published for Linux x64/arm64 and macOS x64/arm64.

---

## 60-second quickstart

```typescript
import { Gate } from 'kavach';

const POLICY = `
[[policy]]
name = "agent_small_refunds"
effect = "permit"
conditions = [
    { identity_kind = "agent" },
    { action = "issue_refund" },
    { param_max = { field = "amount", max = 1000.0 } },
]
`;

const gate = Gate.fromToml(POLICY, {
  invariants: [{ name: 'hard_cap', field: 'amount', maxValue: 50_000 }],
});

const verdict = gate.evaluate({
  principalId: 'agent-bot',
  principalKind: 'agent',
  actionName: 'issue_refund',
  params: { amount: 500 },
});

if (verdict.isPermit) {
  processRefund();
} else {
  console.log(`blocked: [${verdict.code}] ${verdict.evaluator}: ${verdict.reason}`);
}
```

A policy set with no matching permit Refuses by default — there is no implicit allow.

---

## MCP tool gating

```typescript
import { Gate, McpKavachMiddleware } from 'kavach';

const gate = Gate.fromFile('kavach.toml');
const kavach = new McpKavachMiddleware(gate);

// In your MCP tool handler:
kavach.checkToolCall(
  'issue_refund',
  { amount: 500, orderId: 'ORD-123' },
  { callerId: 'agent-bot', callerKind: 'agent' },
);
// Throws KavachRefused if blocked, KavachInvalidated if session revoked.
```

## Express middleware

```typescript
import express from 'express';
import { Gate, createExpressMiddleware } from 'kavach';

const app = express();
const gate = Gate.fromFile('kavach.toml');
app.use(createExpressMiddleware(gate, { gateMutationsOnly: true }));
```

## Fastify hook

```typescript
import Fastify from 'fastify';
import { Gate, createFastifyHook } from 'kavach';

const app = Fastify();
const gate = Gate.fromFile('kavach.toml');
app.addHook('preHandler', createFastifyHook(gate));
```

## guardTool wrapper

```typescript
const guardedRefund = kavach.guardTool(
  'issue_refund',
  async (params) => processRefund(params),
  { callerId: 'agent-bot', callerKind: 'agent' },
);

const result = await guardedRefund({ amount: 500, orderId: 'ORD-123' });
```

---

## Feature surface

### Signed permit tokens (`PqTokenSigner`)

When a `PqTokenSigner` is attached to a gate, every Permit verdict carries an ML-DSA-65 (or ML-DSA-65 + Ed25519 hybrid) signed envelope. Downstream services verify independently.

```typescript
import { Gate, PqTokenSigner } from 'kavach';

const signer = PqTokenSigner.generateHybrid();
const gate = Gate.fromToml(POLICY, { tokenSigner: signer });

const verdict = gate.evaluate({ /* ... */ });
if (verdict.isPermit) {
  const ok = signer.verify(
    {
      tokenId: verdict.permitToken!.tokenId,
      evaluationId: verdict.permitToken!.evaluationId,
      issuedAt: verdict.permitToken!.issuedAt,
      expiresAt: verdict.permitToken!.expiresAt,
      actionName: verdict.permitToken!.actionName,
    },
    verdict.permitToken!.signature!,
  );
  console.assert(ok);
}
```

Hybrid signers sign with both ML-DSA-65 and Ed25519; a hybrid verifier rejects PQ-only envelopes as a signature-downgrade guard.

### Key pairs

```typescript
import { KavachKeyPair } from 'kavach';

const kp = KavachKeyPair.generate();                      // no expiry
const kp2 = KavachKeyPair.generateWithExpiry(3600);       // 1-hour lifetime

console.assert(!kp.isExpired);
const bundle = kp.publicKeys();   // PublicKeyBundleView — safe to share
```

### Signed audit chain

Append-only, tamper-evident audit log. `verify` rejects tampered entries, wrong keys, and mode mismatches (e.g., a PQ-only verifier on a hybrid chain — a silent downgrade).

```typescript
import { AuditEntry, SignedAuditChain } from 'kavach';

const chain = new SignedAuditChain(kp, true);  // hybrid
chain.append(new AuditEntry({
  principalId: 'agent-bot',
  actionName: 'issue_refund',
  verdict: 'permit',
  verdictDetail: 'within policy',
}));
chain.verify(kp.publicKeys());

// Portable JSONL for off-node storage:
const blob = chain.exportJsonl();
SignedAuditChain.verifyJsonl(blob, kp.publicKeys());
```

### Secure channel

Hybrid-encrypted, PQ-signed byte channel between two peers. Sealed payloads are opaque — ship them over any transport.

```typescript
import { SecureChannel, KavachKeyPair } from 'kavach';

const alice = KavachKeyPair.generate();
const bob = KavachKeyPair.generate();
const aliceCh = new SecureChannel(alice, bob.publicKeys());
const bobCh   = new SecureChannel(bob,   alice.publicKeys());

const sealed = aliceCh.sendSigned(Buffer.from('hello bob'), 'greeting');
const plaintext = bobCh.receiveSigned(sealed, 'greeting');
console.assert(plaintext.toString() === 'hello bob');
```

Replay, cross-context, and wrong-recipient attacks all fail closed.

### Public key directory

```typescript
import { PublicKeyDirectory, DirectoryTokenVerifier, KavachKeyPair } from 'kavach';
import { writeFileSync } from 'fs';

const signingKey = KavachKeyPair.generate();
const manifest = signingKey.buildSignedManifest([bundleA, bundleB]);
writeFileSync('directory.json', manifest);

const directory = PublicKeyDirectory.fromSignedFile(
  'directory.json',
  signingKey.publicKeys().mlDsaVerifyingKey,
);

const verifier = new DirectoryTokenVerifier(directory, true /* hybrid */);
verifier.verify(token, signedEnvelope);  // throws on tamper/miss/downgrade
```

In-memory (`PublicKeyDirectory.inMemory([...])`) and unsigned-file variants are also available.

### Geo drift (tolerant mode)

Same-country IP hops become Warnings instead of Violations when you provide lat/lon and a threshold:

```typescript
const gate = Gate.fromToml(POLICY, { geoDriftMaxKm: 500 });

const verdict = gate.evaluate({
  principalId: 'u',
  principalKind: 'user',
  actionName: 'view_profile',
  ip: '2.3.4.5',
  sessionId: 'sess-1',
  currentGeo: { countryCode: 'IN', city: 'Chennai',   latitude: 13.08, longitude: 80.27 },
  originGeo:  { countryCode: 'IN', city: 'Bangalore', latitude: 12.97, longitude: 77.59 },
});
```

Missing geo with a threshold set still **fails closed** — the SDK does not silently bypass.

### Policy hot reload

```typescript
gate.reload(newPolicyToml);   // parse error → throws, previous set preserved
```

---

## Observe mode

Roll out incrementally: log verdicts without blocking.

```typescript
const gate = Gate.fromFile('kavach.toml', { observeOnly: true });
```

---

## What's in the Rust engine

Every `evaluate()` call crosses FFI into compiled Rust via napi-rs. The TypeScript layer is pure wrappers. The engine implements:

- **Policy** — TOML rules with conditions (`identity_kind`, `action`, `param_max`, `rate_limit`, `time_window` with optional timezone, etc.).
- **Drift detectors** — IP/geo, session age, device, behavior.
- **Invariants** — hard per-action limits that cannot be overridden by policy.
- **Post-quantum crypto** — ML-DSA-65, ML-KEM-768, Ed25519, X25519, ChaCha20-Poly1305.
- **Fail-closed** — any evaluator error, store failure, or broadcast issue errs on the side of Refuse.

---

## License

Apache-2.0.
