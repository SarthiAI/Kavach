# TypeScript / Node integration guide

The Node SDK is a napi-rs binding to the compiled Rust engine. Every `evaluate()` call crosses FFI into `kavach-core`; no gate logic runs in JavaScript. This guide covers the idiomatic TS surface: the `Gate` wrapper, options shapes, error classes, middleware factories, PQ crypto helpers, and hot reload.

For the Rust surface underneath, see [rust.md](rust.md). For the Python equivalent, see [python.md](python.md).

---

## Install

```bash
npm install kavach
```

Native addons ship for Linux x64/arm64 and macOS x64/arm64. Node 20+ is supported.

```typescript
import { Gate } from 'kavach';                   // core
import { createExpressMiddleware } from 'kavach'; // http
import { McpKavachMiddleware } from 'kavach';     // mcp
```

---

## First call

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
  console.log('permit', verdict.tokenId);
} else {
  console.log(`blocked: [${verdict.code}] ${verdict.evaluator}: ${verdict.reason}`);
}
```

An empty policy string is valid. It default-denies, which is the kill-switch shape.

---

## Constructing a `Gate`

Five factories, all accepting the same `GateOptions`. Pick whichever fits how you store or generate policies; they all produce identical behavior.

```typescript
import { Gate, GateOptions } from 'kavach';

Gate.fromToml(policyToml: string,    options?: GateOptions): Gate  // TOML string
Gate.fromFile(path: string,          options?: GateOptions): Gate  // TOML file
Gate.fromObject(policies: object,    options?: GateOptions): Gate  // native JS object
Gate.fromJsonString(json: string,    options?: GateOptions): Gate  // JSON string (wire body)
Gate.fromJsonFile(path: string,      options?: GateOptions): Gate  // JSON file on disk
```

All five share the same condition vocabulary; see [reference/policy-language.md](../reference/policy-language.md) for the full grammar. Typo'd or unknown field names throw a clear error in every loader. Example:

```typescript
const gate = Gate.fromObject({
  policies: [
    {
      name: 'agent_small_refunds',
      effect: 'permit',
      conditions: [
        { identity_kind: 'agent' },
        { action: 'issue_refund' },
        { param_max: { field: 'amount', max: 5000 } },
        { rate_limit: { max: 50, window: '24h' } },
      ],
    },
  ],
});
```

For programmatic policy construction (admin UI submissions, database rows, feature flags), `fromObject` is usually the cleanest path: build the object however you like, hand it to the gate, no string templating.

`GateOptions` shape:

```typescript
interface GateOptions {
  invariants?: Array<{ name: string; field: string; maxValue: number }>;
  observeOnly?: boolean;
  maxSessionActions?: number;
  enableDrift?: boolean;                 // default true
  tokenSigner?: PqTokenSigner;           // signs every Permit; fails closed on error
  geoDriftMaxKm?: number;                // tolerant GeoLocationDrift; missing geo still fails closed
  broadcaster?: InMemoryInvalidationBroadcaster; // publishes Invalidate verdicts; see "In-process invalidation"
}
```

---

## `EvaluateOptions`

`Gate.evaluate(opts)` and `Gate.check(opts)` accept a flat record that the binding reshapes into a Rust `ActionContext`.

```typescript
interface EvaluateOptions {
  principalId: string;
  principalKind: 'user' | 'agent' | 'service' | 'scheduler' | 'external';
  actionName: string;
  roles?: string[];
  resource?: string;
  params?: Record<string, number>;        // numeric only, policy & invariant inputs
  ip?: string;
  sessionId?: string;
  currentGeo?: GeoLocationInput;          // EnvContext.geo
  originGeo?: GeoLocationInput;           // SessionState.origin_geo
}
```

`GeoLocationInput`:

```typescript
interface GeoLocationInput {
  countryCode: string;        // required, ISO alpha-2
  region?: string;
  city?: string;
  latitude?: number;          // required for tolerant-mode distance drift
  longitude?: number;
}
```

---

## Evaluate and throw

Three styles:

```typescript
const verdict = gate.evaluate(opts);   // VerdictResult
verdict.isPermit;         // boolean
verdict.isRefuse;
verdict.isInvalidate;
verdict.kind;             // 'permit' | 'refuse' | 'invalidate'
verdict.code;             // e.g. 'POLICY_DENIED'
verdict.evaluator;        // which evaluator decided
verdict.reason;           // human-readable
verdict.tokenId;          // on Permit
verdict.permitToken;      // full PermitTokenView on Permit (with signature when signer attached)
verdict.signature;        // Buffer, mirrors permitToken.signature

gate.check(opts);         // throws KavachRefused / KavachInvalidated on block
```

Error classes carry structured fields:

```typescript
import { KavachRefused, KavachInvalidated } from 'kavach';

try {
  gate.check(opts);
} catch (err) {
  if (err instanceof KavachRefused) {
    // err.code, err.evaluator, err.reason
  } else if (err instanceof KavachInvalidated) {
    // err.evaluator, err.reason, kill the session
  } else {
    throw err;
  }
}
```

---

## `guardTool` for MCP

`McpKavachMiddleware` wraps MCP tool handlers.

```typescript
import { Gate, McpKavachMiddleware, KavachRefused } from 'kavach';

const gate = Gate.fromFile('kavach.toml');
const kavach = new McpKavachMiddleware(gate);

// Style 1: throw on block.
kavach.checkToolCall(
  'issue_refund',
  { amount: 500, orderId: 'ORD-123' },
  { callerId: 'agent-bot', callerKind: 'agent', roles: ['support'] },
);

// Style 2: get the verdict back.
const verdict = kavach.evaluateToolCall(
  'issue_refund',
  { amount: 500 },
  { callerId: 'agent-bot', callerKind: 'agent' },
);

// Style 3: wrap a handler.
const guardedRefund = kavach.guardTool(
  'issue_refund',
  async (params) => processRefund(params),
  { callerId: 'agent-bot', callerKind: 'agent' },
);
const result = await guardedRefund({ amount: 500, orderId: 'ORD-123' });
```

`McpCallerInfo` accepts `callerId`, `callerKind`, `roles`, `sessionId`, `ip`, `currentGeo`, `originGeo`.

---

## HTTP middleware

### Express

```typescript
import express from 'express';
import { Gate, createExpressMiddleware } from 'kavach';

const app = express();
app.use(express.json());

const gate = Gate.fromFile('kavach.toml');
app.use(createExpressMiddleware(gate, {
  gateMutationsOnly: true,                     // default
  excludedPaths: ['/health', '/ready', '/metrics'],
  principalHeader: 'x-principal-id',           // headers are configurable
  rolesHeader: 'x-roles',
  kindHeader: 'x-principal-kind',
  geoResolver: ({ headers, ip }) => {
    // Plug in MaxMind, CDN edge headers, whatever.
    return { currentGeo: undefined, originGeo: undefined };
  },
}));

app.post('/api/refunds', (req, res) => {
  // If we reach here, Kavach permitted.
  res.json({ status: 'refunded' });
});
```

Express middleware returns `403` on Refuse and `401` on Invalidate by default.

### Fastify

```typescript
import Fastify from 'fastify';
import { Gate, createFastifyHook } from 'kavach';

const app = Fastify();
const gate = Gate.fromFile('kavach.toml');
app.addHook('preHandler', createFastifyHook(gate));
```

### Framework-agnostic core

`HttpKavachMiddleware` is the framework-agnostic core; both factories wrap it. Use it directly for Hono, Koa, or custom handlers:

```typescript
import { HttpKavachMiddleware } from 'kavach';

const middleware = new HttpKavachMiddleware(gate, { gateMutationsOnly: true });
const verdict = middleware.evaluate({
  method: 'POST',
  path: '/api/v1/refunds',
  headers: req.headers,
  body: req.body,
  ip: req.ip,
  currentGeo: undefined,    // explicit geo beats the configured resolver
  originGeo: undefined,
});
```

Action names are auto-derived from HTTP method + path via `deriveActionName`: `POST /api/v1/refunds` becomes `refunds.create`.

---

## Signed permit tokens: `PqTokenSigner`

```typescript
import { Gate, PqTokenSigner } from 'kavach';

const signer = PqTokenSigner.generateHybrid();    // ML-DSA-65 + Ed25519
// const signer = PqTokenSigner.generatePqOnly(); // ML-DSA-65 only

const gate = Gate.fromToml(POLICY, { tokenSigner: signer });
const verdict = gate.evaluate({ /* ... */ });

if (verdict.isPermit && verdict.permitToken && verdict.signature) {
  const pt = verdict.permitToken;
  signer.verify(
    {
      tokenId: pt.tokenId,
      evaluationId: pt.evaluationId,
      issuedAt: pt.issuedAt,
      expiresAt: pt.expiresAt,
      actionName: pt.actionName,
    },
    verdict.signature,
  );
}
```

A hybrid signer signs with both ML-DSA and Ed25519. Hybrid verifiers reject PQ-only envelopes (downgrade defense); PQ-only verifiers reject hybrid envelopes. Sign failures at the gate always fail closed.

Signer identity helpers:

```typescript
signer.keyId;        // matches the source KavachKeyPair.id
signer.isHybrid;     // boolean
```

---

## Key pairs: `KavachKeyPair.generate()`

```typescript
import { KavachKeyPair } from 'kavach';

const kp = KavachKeyPair.generate();                  // no expiry
const short = KavachKeyPair.generateWithExpiry(3600); // seconds

kp.id;                          // UUID string
kp.createdAt;                   // unix seconds
kp.expiresAt;                   // number | null
kp.isExpired;                   // boolean

const bundle = kp.publicKeys(); // PublicKeyBundleView, safe to share
// bundle.id, bundle.mlDsaVerifyingKey (Buffer),
// bundle.ed25519VerifyingKey (Buffer, 32 bytes),
// bundle.x25519PublicKey (Buffer, 32 bytes),
// bundle.mlKemEncapsulationKey (Buffer)
```

Signer factories from a keypair:

```typescript
PqTokenSigner.fromKeypairHybrid(kp);
PqTokenSigner.fromKeypairPqOnly(kp);

// Verifier-only signer (no signing key material):
PqTokenSigner.pqOnly(Buffer.alloc(0), bundle.mlDsaVerifyingKey, kp.id);
```

---

## Signed audit chain

```typescript
import { AuditEntry, KavachKeyPair, SignedAuditChain } from 'kavach';

const kp = KavachKeyPair.generate();
const chain = new SignedAuditChain(kp, true);   // hybrid

chain.append(AuditEntry.new('agent-alice', 'issue_refund', 'permit',     'token=abc'));
chain.append(AuditEntry.new('agent-bob',   'issue_refund', 'refuse',     '[POLICY_DENIED]'));
chain.append(AuditEntry.new('agent-bob',   'delete_customer', 'invalidate', 'drift'));

chain.verify(kp.publicKeys());

const blob: Buffer = chain.exportJsonl();
SignedAuditChain.verifyJsonl(blob, kp.publicKeys());          // mode inferred
SignedAuditChain.verifyJsonl(blob, kp.publicKeys(), true);    // strict hybrid assertion
```

Tampered blobs, wrong-key bundles, and mode mismatches (PQ-only verifier presented with a hybrid chain) all throw. Passing `false` on a hybrid blob is rejected outright: the silent-downgrade defense.

---

## Public key directory

```typescript
import {
  DirectoryTokenVerifier, KavachKeyPair, PublicKeyDirectory,
} from 'kavach';
import { writeFileSync } from 'fs';

// In-memory, supports insert / remove.
const dirIm = PublicKeyDirectory.inMemory([bundleA, bundleB]);
dirIm.insert(bundleC);
dirIm.remove(keyPairA.id);
dirIm.reload();                  // no-op, kept for polymorphism

// Plain JSON manifest on disk.
writeFileSync('bundles.json',
  PublicKeyDirectory.buildUnsignedManifest([bundleA, bundleB]),
);
const dirFile = PublicKeyDirectory.fromFile('bundles.json');
dirFile.reload();                // re-reads file; corrupt reload throws, cache preserved

// Root-signed manifest, tamper-evident.
const rootKp = KavachKeyPair.generate();
writeFileSync('directory.json', rootKp.buildSignedManifest([bundleA, bundleB]));
const dirSigned = PublicKeyDirectory.fromSignedFile(
  'directory.json',
  Buffer.from(rootKp.publicKeys().mlDsaVerifyingKey),
);

// Mount any of the three into a verifier.
const verifier = new DirectoryTokenVerifier(dirSigned, true /* hybrid */);
verifier.verify(token, signature);   // throws on tamper / miss / downgrade
```

Insert / remove on file-backed directories throw. Missing keys fail closed, not silently.

---

## Secure channel (bytes flow)

```typescript
import { KavachKeyPair, SecureChannel } from 'kavach';

const alice = KavachKeyPair.generate();
const bob = KavachKeyPair.generate();

const aliceCh = new SecureChannel(alice, bob.publicKeys());
const bobCh   = new SecureChannel(bob,   alice.publicKeys());

const sealed = aliceCh.sendSigned(
  Buffer.from('permit: issue_refund'),
  'issue_refund',        // context_id, bound into the signature
  'eval-1',              // correlation_id, bound into the signature
);
const payload = bobCh.receiveSigned(sealed, 'issue_refund');
// payload is a Buffer.

// Unsigned helper when the caller signs its own payload.
const enc = aliceCh.sendData(Buffer.from('opaque'));
const raw = bobCh.receiveData(enc);
```

Replay, ciphertext tamper, wrong recipient, wrong `expectedContextId`, and unsigned-into-`receiveSigned` all throw.

`aliceCh.localKeyId` and `aliceCh.remoteKeyId` expose the bound key IDs for diagnostics.

---

## In-process invalidation

The Node SDK ships an in-process `InMemoryInvalidationBroadcaster` plus a listener bridge. Wire them up when you want every `Invalidate` verdict in the process to fan out to an MCP session store, an HTTP session cache, a metrics sink, or anything else that needs to react.

```typescript
import {
  Gate,
  InMemoryInvalidationBroadcaster, InMemorySessionStore,
  McpKavachMiddleware, spawnInvalidationListener,
} from 'kavach';

const broadcaster = new InMemoryInvalidationBroadcaster();
const gate = Gate.fromToml(POLICY, { broadcaster });

// McpKavachMiddleware can share a session store so invalidations propagate
// to every tool call on this process.
const mcp = new McpKavachMiddleware(gate, { sessionStore: new InMemorySessionStore() });

const handle = spawnInvalidationListener(broadcaster, (scope) => {
  console.log(`invalidated: ${scope.target} (${scope.reason})`);
});

// On shutdown:
handle.abort();
```

`InvalidationScopeView` exposes `.target` (session / principal / role), `.reason`, and `.evaluator`. Listener callback errors are caught and logged; they do not kill the listener.

For multi-replica deployments the canonical fan-out is Redis Pub/Sub; the Rust-side `RedisInvalidationBroadcaster` is documented in [guides/distributed.md](distributed.md). The Node SDK does not ship a Redis binding yet; bridge to the Rust layer through a sidecar, or pair this in-process broadcaster with a Redis-backed listener you implement alongside your session cache.

---

## Hot reload

```typescript
gate.reload(newPolicyToml);
```

Throws on parse error; the previous good set stays live. Empty TOML is valid and default-denies.

For file-watched reload, pair with `chokidar` or `fs.watch`:

```typescript
import { watch } from 'fs';
import { readFileSync } from 'fs';

watch('kavach.toml', { persistent: true }, () => {
  try {
    gate.reload(readFileSync('kavach.toml', 'utf-8'));
  } catch (err) {
    console.error('bad policy file, keeping previous set:', err);
  }
});
```

---

## End-to-end example

One file, runnable end to end. Exercises policies, invariants, signed tokens, audit chain, directory, secure channel, hot reload, and the Express middleware.

```typescript
// examples/ts_guide.ts
import express from 'express';
import { writeFileSync } from 'fs';
import { randomUUID } from 'crypto';
import {
  AuditEntry,
  DirectoryTokenVerifier,
  Gate,
  KavachKeyPair,
  KavachRefused,
  McpKavachMiddleware,
  PqTokenSigner,
  PublicKeyDirectory,
  SecureChannel,
  SignedAuditChain,
  createExpressMiddleware,
  type PermitTokenInput,
} from 'kavach';

const POLICY = `
[[policy]]
name = "support_small_refunds"
effect = "permit"
conditions = [
    { identity_role = "support" },
    { action = "refunds.create" },
    { param_max = { field = "amount", max = 5000.0 } },
]

[[policy]]
name = "allow_fetch_report"
effect = "permit"
conditions = [
    { action = "fetch_report" },
]
`;

async function main() {
  // 1. Signed gate.
  const signer = PqTokenSigner.generateHybrid();
  const gate = Gate.fromToml(POLICY, {
    invariants: [{ name: 'hard_cap', field: 'amount', maxValue: 10_000 }],
    tokenSigner: signer,
    geoDriftMaxKm: 500,
  });

  // 2. Permit path + signature roundtrip.
  const v = gate.evaluate({
    principalId: 'agent-alice',
    principalKind: 'agent',
    actionName: 'refunds.create',
    roles: ['support'],
    params: { amount: 1500 },
  });
  if (v.isPermit && v.permitToken && v.signature) {
    signer.verify(
      {
        tokenId: v.permitToken.tokenId,
        evaluationId: v.permitToken.evaluationId,
        issuedAt: v.permitToken.issuedAt,
        expiresAt: v.permitToken.expiresAt,
        actionName: v.permitToken.actionName,
      },
      v.signature,
    );
    console.log('signed permit verified:', v.permitToken.tokenId);
  }

  // 3. Invariant override.
  const blocked = gate.evaluate({
    principalId: 'agent-alice',
    principalKind: 'agent',
    actionName: 'refunds.create',
    roles: ['support'],
    params: { amount: 25_000 },
  });
  console.log('over-cap blocked:', blocked.isRefuse, blocked.reason);

  // 4. MCP middleware with guardTool.
  const mcp = new McpKavachMiddleware(gate);
  const guardedRefund = mcp.guardTool(
    'refunds.create',
    async (params: Record<string, unknown>) => ({ ok: true, amount: params.amount }),
    { callerId: 'agent-alice', callerKind: 'agent', roles: ['support'] },
  );
  console.log('mcp permit:', await guardedRefund({ amount: 500 }));

  try {
    await guardedRefund({ amount: 999_999 });
  } catch (err) {
    if (err instanceof KavachRefused) {
      console.log('mcp blocked:', err.code, err.reason);
    }
  }

  // 5. Signed audit chain.
  const kp = KavachKeyPair.generate();
  const chain = new SignedAuditChain(kp, true);
  chain.append(AuditEntry.new('agent-alice', 'refunds.create', 'permit', 'token=abc'));
  chain.append(AuditEntry.new('agent-alice', 'refunds.create', 'refuse', 'over cap'));
  chain.verify(kp.publicKeys());
  const blob = chain.exportJsonl();
  SignedAuditChain.verifyJsonl(blob, kp.publicKeys());

  // 6. Directory + DirectoryTokenVerifier.
  const root = KavachKeyPair.generate();
  const manifestPath = '/tmp/kavach-directory.json';
  writeFileSync(manifestPath, root.buildSignedManifest([kp.publicKeys()]));
  const directory = PublicKeyDirectory.fromSignedFile(
    manifestPath,
    Buffer.from(root.publicKeys().mlDsaVerifyingKey),
  );

  const svcSigner = PqTokenSigner.fromKeypairHybrid(kp);
  const token: PermitTokenInput = {
    tokenId: randomUUID(),
    evaluationId: randomUUID(),
    issuedAt: 1_700_000_000,
    expiresAt: 1_700_000_030,
    actionName: 'refunds.create',
  };
  const sig = svcSigner.sign(token);
  new DirectoryTokenVerifier(directory, true).verify(token, sig);
  console.log('directory-backed verify ok');

  // 7. Secure channel.
  const alice = KavachKeyPair.generate();
  const bob = KavachKeyPair.generate();
  const aliceCh = new SecureChannel(alice, bob.publicKeys());
  const bobCh   = new SecureChannel(bob,   alice.publicKeys());
  const sealed = aliceCh.sendSigned(Buffer.from('hello bob'), 'greet', 'c-1');
  const plaintext = bobCh.receiveSigned(sealed, 'greet');
  console.log('secure channel ok:', plaintext.toString());

  // 8. Hot reload.
  gate.reload('');
  console.log('default-deny after reload(""):', gate.evaluate({
    principalId: 'agent-alice', principalKind: 'agent', actionName: 'refunds.create',
    roles: ['support'], params: { amount: 100 },
  }).isRefuse);
  gate.reload(POLICY);

  // 9. Express integration, fire up a small server if RUN_SERVER is set.
  if (process.env.RUN_SERVER) {
    const app = express();
    app.use(express.json());
    app.use(createExpressMiddleware(gate, { gateMutationsOnly: true }));
    app.post('/api/refunds', (req, res) => res.json({ status: 'refunded', body: req.body }));
    app.listen(3000, () => console.log('listening on :3000'));
  }
}

main().catch((err) => { console.error(err); process.exit(1); });
```

Run with `ts-node examples/ts_guide.ts`, or compile + run:

```bash
npx tsc examples/ts_guide.ts --target es2020 --module commonjs --esModuleInterop
node examples/ts_guide.js
```

The smoke test at `Kavach/kavach-node/npm/tests/smoke_test.ts` is the authoritative reference for every SDK surface (15 groups covering Gate, signer, keypair, audit chain, secure channel, directory, geo drift, and middleware).

---

## Next

- [concepts/gate-and-verdicts.md](../concepts/gate-and-verdicts.md), Permit / Refuse / Invalidate semantics.
- [concepts/post-quantum.md](../concepts/post-quantum.md), what hybrid means, and why.
- [concepts/audit.md](../concepts/audit.md), SignedAuditChain internals.
- [guides/distributed.md](distributed.md), multi-node invalidation + Redis stores.
- [reference/policy-language.md](../reference/policy-language.md), full condition reference.
