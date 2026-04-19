# kavach

**Post-quantum execution boundary enforcement for AI agents, APIs, and distributed systems. TypeScript SDK.**

Kavach separates *possession of credentials* from *permission to act*. Every action passes through a gate that evaluates identity, policy, drift, and invariants before producing a verdict. All evaluation runs in compiled Rust via napi-rs; this package is the idiomatic TypeScript wrapper.

```
Action attempted ──▶ Gate (identity · policy · drift · invariants) ──▶ Permit / Refuse / Invalidate
```

---

## Install

```bash
npm install kavach
```

Native addons are published for Linux x64/arm64 and macOS x64/arm64. Node 20+.

---

## 60-second quickstart

```typescript
import { Gate, type EvaluateOptions } from 'kavach';

// Policy as a plain JS object. No separate config format to learn.
const POLICY = {
  policies: [
    {
      name: 'agent_small_refunds',
      effect: 'permit',
      conditions: [
        { identity_kind: 'agent' },
        { action: 'issue_refund' },
        { param_max: { field: 'amount', max: 1000 } },
      ],
    },
  ],
};

const gate = Gate.fromObject(POLICY, {
  invariants: [{ name: 'hard_cap', field: 'amount', maxValue: 50_000 }],
});

const verdict = gate.evaluate({
  principalId: 'agent-bot',
  principalKind: 'agent',
  actionName: 'issue_refund',
  params: { amount: 500 },
});

if (verdict.isPermit) {
  console.log('permit', verdict.tokenId);
} else {
  console.log(`blocked: [${verdict.code}] ${verdict.evaluator}: ${verdict.reason}`);
}
```

A policy set with no matching permit Refuses by default. There is no implicit allow.

### Loading a policy

The recommended surface for Node is a plain JS object (admin UI submissions, database rows, feature flags):

```typescript
const gate = Gate.fromObject(policyObject);      // native object (recommended)
const gate = Gate.fromJsonString(jsonString);    // JSON over the wire
const gate = Gate.fromJsonFile('kavach.json');   // JSON file on disk
```

For operator-owned config that lives in git and is hand-edited, use TOML:

```typescript
const gate = Gate.fromToml(tomlString);          // operator-edited TOML
const gate = Gate.fromFile('kavach.toml');       // TOML file on disk
```

Typo'd field names (`{ idnetity_kind: 'agent' }`) throw a clear error in every loader instead of being silently dropped, so a misspelled condition cannot quietly weaken a policy. The full TOML workflow (rendered in Rust, Python, and Node) lives at [docs/guides/toml-policies.md](https://github.com/SarthiAI/Kavach/blob/main/docs/guides/toml-policies.md).

---

## Feature surface

### Signed permit tokens (`PqTokenSigner`)

When a `PqTokenSigner` is attached to a gate, every Permit verdict carries an ML-DSA-65 (or ML-DSA-65 + Ed25519 hybrid) signed envelope. Downstream services verify independently.

```typescript
import { Gate, PqTokenSigner } from 'kavach';

const signer = PqTokenSigner.generateHybrid();
const gate = Gate.fromObject(POLICY, { tokenSigner: signer });

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
const bundle = kp.publicKeys();   // PublicKeyBundleView, safe to share
```

### Signed audit chain

Append-only, tamper-evident audit log. `verify` rejects tampered entries, wrong keys, and mode mismatches (e.g., a PQ-only verifier on a hybrid chain, which is a silent downgrade).

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

Hybrid-encrypted, PQ-signed byte channel between two peers. Sealed payloads are opaque; ship them over any transport.

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
const gate = Gate.fromObject(POLICY, { geoDriftMaxKm: 500 });

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

Missing geo with a threshold set still **fails closed**. The SDK does not silently bypass.

### Policy hot reload

`gate.reload(...)` accepts a TOML string; it throws on parse error and leaves the previous good set in place. See [docs/guides/toml-policies.md](https://github.com/SarthiAI/Kavach/blob/main/docs/guides/toml-policies.md) for the full reload workflow (including the file-watcher pattern and the empty-TOML kill switch).

```typescript
gate.reload(newPolicyToml);   // parse error throws, previous set preserved
```

### In-process invalidation

Fan out `Invalidate` verdicts to anything on this node that needs to react (metrics, kill-session hooks, downstream caches):

```typescript
import {
  Gate, InMemoryInvalidationBroadcaster, spawnInvalidationListener,
} from 'kavach';

const broadcaster = new InMemoryInvalidationBroadcaster();
const gate = Gate.fromObject(POLICY, { broadcaster });

const handle = spawnInvalidationListener(broadcaster, (scope) => {
  console.log(`invalidated: ${scope.target} (${scope.reason})`);
});
// handle.abort() on shutdown
```

The Node SDK ships the in-process broadcaster only. Multi-replica Redis fan-out lives on the Rust side (see [docs/guides/distributed.md](https://github.com/SarthiAI/Kavach/blob/main/docs/guides/distributed.md)).

---

## Observe mode

Roll out incrementally: log verdicts without blocking.

```typescript
const gate = Gate.fromObject(POLICY, { observeOnly: true });
```

---

## What's in the Rust engine

Every `evaluate()` call crosses FFI into compiled Rust via napi-rs. The TypeScript layer is pure wrappers. The engine implements:

- **Policy:** a small, fixed condition vocabulary (`identity_kind`, `action`, `param_max`, `rate_limit`, `time_window` with optional timezone, etc.) expressed as a JS object, JSON, or operator-edited TOML.
- **Drift detectors:** IP / geo, session age, device, behavior.
- **Invariants:** hard per-action limits that cannot be overridden by policy.
- **Post-quantum crypto:** ML-DSA-65, ML-KEM-768, Ed25519, X25519, ChaCha20-Poly1305.
- **Fail-closed:** any evaluator error, store failure, or broadcast issue errs on the side of Refuse.

---

## License

Elastic License 2.0. Source-available; free to use, embed, and modify for any purpose, including commercially. You may not offer Kavach itself as a hosted or managed service that competes with SarthiAI. See the [LICENSE](https://github.com/SarthiAI/Kavach/blob/main/LICENSE) file for the full text.
