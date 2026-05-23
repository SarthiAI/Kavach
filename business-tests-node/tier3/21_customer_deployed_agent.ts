/**
 * Scenario 21: AI agent in the customer's VPC, user-held keys, Kavach in the middle.
 *
 * The business story
 * ------------------
 * A B2B SaaS vendor ships an AI agent as a container the customer
 * runs in their own VPC. Law firm, insurer, healthcare group, all
 * of them cannot hand their data to the vendor cloud (data
 * residency, HIPAA, GDPR, contracts). The agent still calls the
 * vendor's central API to log activity, fetch model updates, and
 * reconcile billing.
 *
 * Two facts change the threat model:
 *
 *     The agent runs ON THE CUSTOMER'S SIDE. The vendor cannot
 *     assume the host is clean. Customer admins have root. A
 *     compromise inside the customer VPC is plausible.
 *
 *     The only actor the vendor trusts for that user's data is
 *     the user at their laptop. Not the VPC. Not the container
 *     image. Not the 3am SSH session.
 *
 * Why OAuth breaks here. The typical answer is a long-lived
 * OAuth token in the container. That tells the vendor 'this
 * container is allowed' but not 'the user clicked this right
 * now'. A compromised VPC (or a prompt injection from a document
 * the agent reads) can drive the agent to exfiltrate, modify
 * records, or call the vendor API in ways the user never
 * intended.
 *
 * What Kavach does
 * ----------------
 * The signing keypair stays on the user's device (laptop, phone,
 * hardware key). The container holds only a verifying bundle and
 * the short-lived permits the user has signed in the last few
 * seconds. Every user click produces a fresh Kavach permit with
 * the scope bound in via an ML-DSA-65 signature. The vendor API
 * verifies Kavach's signature and refuses anything outside the
 * signed scope.
 *
 * Short timescales in this demo
 * -----------------------------
 * The signing keypair in this scenario expires in 2 seconds to
 * keep the script fast. In production this tracks the user's
 * active session, typically seconds to minutes.
 *
 * Five cases:
 *
 *     A. User signs an intent on the laptop, vendor permits.
 *     B. VPC attacker signs a rogue permit. Refused.
 *     C. Prompt injection widens allowed_actions. Refused.
 *     D. Past TTL, any captured permit stops working.
 *     E. User re-signs. Fresh bundle pinned, next action runs.
 *
 * Run this file directly:
 *
 *   node dist/tier3/21_customer_deployed_agent.js
 */

import { createHash } from 'node:crypto';

import {
  DirectoryTokenVerifier,
  Gate,
  KavachKeyPair,
  PqTokenSigner,
  PublicKeyDirectory,
  type PermitTokenView,
} from 'kavach-sdk';

const USER_TTL_SECONDS = 2;
const INTENT_ACTION = 'agent.intent';

const USER_INTENT_POLICIES = {
  policies: [
    {
      name: 'user_signs_agent_intent',
      description: 'Customer user signs a short lived agent action intent',
      effect: 'permit',
      priority: 10,
      conditions: [
        { identity_role: 'customer_user' },
        { param_max: { field: 'max_tokens', max: 4000.0 } },
      ],
    },
  ],
};

type Scope = {
  user_id: string;
  resource: string;
  allowed_actions: string[];
  max_tokens: number;
};

function canonicalScopeBytes(scope: Scope): Buffer {
  const keys = Object.keys(scope).sort() as (keyof Scope)[];
  const obj: Record<string, unknown> = {};
  for (const k of keys) obj[k] = scope[k];
  return Buffer.from(JSON.stringify(obj), 'utf-8');
}

function scopeHash(scope: Scope): string {
  return createHash('sha256').update(canonicalScopeBytes(scope)).digest('hex');
}

function bindAction(base: string, scope: Scope): string {
  return `${base}:${scopeHash(scope)}`;
}

/**
 * Stands in for the user's laptop / phone / hardware key.
 *
 * Holds the signing keypair. Signs intent permits in response to
 * explicit user clicks. The rest of the customer VPC never has
 * direct access to this object's inner keypair, only the permits
 * it emits.
 */
class UserDevice {
  readonly userId: string;
  private readonly keypair: KavachKeyPair;
  private readonly gate: Gate;

  constructor(userId: string, ttlSeconds: number) {
    this.userId = userId;
    this.keypair = KavachKeyPair.generateWithExpiry(ttlSeconds);
    const signer = PqTokenSigner.fromKeypairPqOnly(this.keypair);
    this.gate = Gate.fromObject(USER_INTENT_POLICIES, { tokenSigner: signer });
  }

  bundle() {
    return this.keypair.publicKeys();
  }

  keyId(): string {
    return this.keypair.id;
  }

  signIntent(actionScope: {
    resource?: string;
    allowed_actions?: string[];
    max_tokens?: number;
  }): { permit: PermitTokenView; scope: Scope } {
    const scope: Scope = {
      user_id: this.userId,
      resource: actionScope.resource ?? '',
      allowed_actions: [...(actionScope.allowed_actions ?? [])],
      max_tokens: actionScope.max_tokens ?? 4000,
    };
    const verdict = this.gate.evaluate({
      principalId: this.userId,
      principalKind: 'user',
      actionName: bindAction(INTENT_ACTION, scope),
      roles: ['customer_user'],
      params: { max_tokens: scope.max_tokens },
    });
    return { permit: verdict.permitToken!, scope };
  }
}

type ToolCall = {
  action: string;
  resource?: string;
  on_behalf_of?: string;
};

type VendorResult = {
  kind: 'permit' | 'refuse';
  reason: string;
  error?: string;
  got_action?: string;
  requested?: string;
  allowed?: string[];
  requested_resource?: string;
  allowed_resource?: string;
  permit_token_id?: string;
};

function vendorApiCall(args: {
  toolCall: ToolCall;
  permit: PermitTokenView;
  scope: Scope;
  verifier: DirectoryTokenVerifier;
}): VendorResult {
  const { toolCall, permit, scope, verifier } = args;

  try {
    verifier.verify(
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
    return {
      kind: 'refuse',
      reason: 'permit expired or tampered',
      error: (e as Error).message.slice(0, 180),
    };
  }

  const [base] = permit.actionName.split(':');
  if (base !== INTENT_ACTION) {
    return { kind: 'refuse', reason: 'permit is not an agent intent', got_action: base };
  }
  if (permit.actionName !== bindAction(INTENT_ACTION, scope)) {
    return {
      kind: 'refuse',
      reason: 'scope does not match the signed intent (hash mismatch)',
    };
  }

  if (toolCall.on_behalf_of !== scope.user_id) {
    return {
      kind: 'refuse',
      reason: 'tool call principal does not match the scope principal',
    };
  }
  if (!scope.allowed_actions.includes(toolCall.action)) {
    return {
      kind: 'refuse',
      reason: "action not in user's signed scope",
      requested: toolCall.action,
      allowed: scope.allowed_actions,
    };
  }
  if (toolCall.resource !== scope.resource) {
    return {
      kind: 'refuse',
      reason: "resource not in user's signed scope",
      requested_resource: toolCall.resource,
      allowed_resource: scope.resource,
    };
  }

  return {
    kind: 'permit',
    reason: 'ran under user signed intent',
    permit_token_id: permit.tokenId,
  };
}

async function main(): Promise<number> {
  console.log('='.repeat(70));
  console.log("Scenario 21: agent in the customer's VPC, user-held keys, Kavach in between");
  console.log('='.repeat(70));
  console.log();
  console.log("The user's laptop holds the signing key. The VPC agent container");
  console.log('holds no long-lived credentials, just whatever permits the user');
  console.log('has signed in the last few seconds. The vendor API verifies every');
  console.log("call against Kavach's signature and refuses anything outside the");
  console.log("user's signed scope. Below we walk the happy path, a VPC attacker,");
  console.log('a prompt injection, the TTL expiring, and the user re-signing.');
  console.log();

  const results: [string, boolean][] = [];

  // -----------------------------------------------------------------
  // On the user's device.
  // -----------------------------------------------------------------
  console.log(`User's device generates a signing keypair (TTL = ${USER_TTL_SECONDS}s).`);
  console.log('(2 seconds keeps this script fast; in production this tracks the');
  console.log(" user's active session, typically seconds to minutes.)");
  const device = new UserDevice('user-ava', USER_TTL_SECONDS);
  const userBundle = device.bundle();
  console.log(`  user.key_id: ${device.keyId()}`);
  console.log();

  // -----------------------------------------------------------------
  // Vendor side.
  // -----------------------------------------------------------------
  console.log("Vendor API bootstraps a directory pinned to the user's bundle.");
  const directory = PublicKeyDirectory.inMemory([userBundle]);
  const verifier = new DirectoryTokenVerifier(directory, false);
  console.log(`  directory.length: ${directory.length}`);
  console.log();

  // -----------------------------------------------------------------
  // Case A.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log("Case A: user clicks 'summarise contract contract-2026-042'.");
  console.log('-'.repeat(70));
  console.log("User's device signs an intent, with the scope hash bound into");
  console.log("the permit's action_name. The permit plus the scope bytes travel");
  console.log('through the VPC agent container to the vendor API. Vendor');
  console.log('verifies the signature, recomputes the hash, and runs the action.');
  console.log('The container never saw the signing key.');
  console.log();
  const actionScope = {
    resource: 'contract-2026-042',
    allowed_actions: ['summarise', 'draft_reply'],
    max_tokens: 4000,
  };
  const { permit, scope } = device.signIntent(actionScope);
  console.log(`  permit token_id:   ${permit.tokenId}`);
  console.log(`  action_name:       ${permit.actionName}`);
  console.log(`  issued/expires at: ${permit.issuedAt} / ${permit.expiresAt}`);

  let r = vendorApiCall({
    toolCall: {
      action: 'summarise',
      resource: 'contract-2026-042',
      on_behalf_of: 'user-ava',
    },
    permit,
    scope,
    verifier,
  });
  console.log(`  vendor API: ${r.kind} (${r.reason})`);
  console.log();
  results.push(['Case A: in TTL summarise permits', r.kind === 'permit']);

  // -----------------------------------------------------------------
  // Case B: VPC compromise tries to mint its own permit.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case B: attacker inside the VPC tries to mint a new permit.');
  console.log('-'.repeat(70));
  console.log("The attacker is inside the customer's VPC and has root on the");
  console.log('agent container. They generate their own Kavach keypair and');
  console.log('sign a fresh permit locally, impersonating user-ava. They');
  console.log('present this rogue permit to the vendor API. The vendor');
  console.log("resolves the permit's embedded key_id against its pinned");
  console.log('directory and finds nothing (the rogue key is not trusted).');
  console.log();
  const rogueKp = KavachKeyPair.generate();
  const rogueSigner = PqTokenSigner.fromKeypairPqOnly(rogueKp);
  const rogueGate = Gate.fromObject(USER_INTENT_POLICIES, { tokenSigner: rogueSigner });
  const rogueScope: Scope = {
    user_id: 'user-ava',
    resource: 'contract-2026-042',
    allowed_actions: ['summarise', 'draft_reply'],
    max_tokens: 4000,
  };
  const roguePermit: PermitTokenView = rogueGate.evaluate({
    principalId: 'user-ava',
    principalKind: 'user',
    actionName: bindAction(INTENT_ACTION, rogueScope),
    roles: ['customer_user'],
    params: { max_tokens: 4000.0 },
  }).permitToken!;
  console.log(`  rogue key_id:          ${rogueKp.id}`);
  console.log(`  rogue permit.token_id: ${roguePermit.tokenId}`);

  r = vendorApiCall({
    toolCall: {
      action: 'summarise',
      resource: 'contract-2026-042',
      on_behalf_of: 'user-ava',
    },
    permit: roguePermit,
    scope: rogueScope,
    verifier,
  });
  console.log(`  vendor API: ${r.kind} (${r.reason})`);
  console.log(`  error:      ${(r.error ?? '').slice(0, 180)}`);
  console.log();
  results.push(['Case B: rogue keypair from VPC refused', r.kind === 'refuse']);

  // -----------------------------------------------------------------
  // Case C: prompt injection tries to widen the scope.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case C: prompt injection widens the in-memory scope.');
  console.log('-'.repeat(70));
  console.log('User signed a fresh permit for {summarise, draft_reply} on');
  console.log('contract-2026-042. An injection in the contract body tells');
  console.log('the agent to email a third party. The agent mutates its own');
  console.log("scope.allowed_actions to include 'send_email' and emits the");
  console.log('tool call. The vendor API recomputes the scope hash and finds');
  console.log('it no longer matches the one bound into the permit; refuse.');
  console.log();
  const { permit: freshPermit, scope: freshScope } = device.signIntent(actionScope);
  const tamperedScope: Scope = {
    ...freshScope,
    allowed_actions: [...freshScope.allowed_actions, 'send_email'],
  };
  r = vendorApiCall({
    toolCall: {
      action: 'send_email',
      resource: 'contract-2026-042',
      on_behalf_of: 'user-ava',
    },
    permit: freshPermit,
    scope: tamperedScope,
    verifier,
  });
  console.log(`  vendor API: ${r.kind} (${r.reason})`);
  console.log();
  const okC = r.kind === 'refuse' && r.reason.includes('hash mismatch');
  results.push(['Case C: scope widening refused via hash mismatch', okC]);

  // -----------------------------------------------------------------
  // Case D: past TTL.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log(`Case D: wait ${USER_TTL_SECONDS + 1}s past TTL, try any permit.`);
  console.log('-'.repeat(70));
  console.log('A VPC admin with transient access copies the permit out of');
  console.log("the container's memory. Nothing to do with it; the signing");
  console.log('bundle has expired. Vendor API refuses on expiry. No long');
  console.log('lived bearer material was available to capture in the first');
  console.log('place. This is why the short TTL matters: captured state');
  console.log('ages out before it can be reused.');
  console.log();
  console.log(`  sleeping ${USER_TTL_SECONDS + 1}s...`);
  await new Promise(r => setTimeout(r, (USER_TTL_SECONDS + 1) * 1000));
  r = vendorApiCall({
    toolCall: {
      action: 'summarise',
      resource: 'contract-2026-042',
      on_behalf_of: 'user-ava',
    },
    permit,
    scope,
    verifier,
  });
  console.log(`  vendor API: ${r.kind} (${r.reason})`);
  console.log();
  const okD = r.kind === 'refuse' && (r.error ?? '').toLowerCase().includes('expired');
  results.push(['Case D: past TTL captured permit refused', okD]);

  // -----------------------------------------------------------------
  // Case E: user re-signs.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case E: after TTL expiry, user re-signs and the vendor accepts.');
  console.log('-'.repeat(70));
  console.log('Case D showed that an expired permit stops working. Case E');
  console.log('completes the picture: the user clicks again, the device mints');
  console.log("a fresh keypair with a new TTL, the vendor's directory pins");
  console.log('the new bundle, and the next action goes through. There is no');
  console.log("offline window where 'the old key still works and the new one");
  console.log("does not'. Each action is anchored to a click that was");
  console.log('actually made.');
  console.log();
  const freshDevice = new UserDevice('user-ava', USER_TTL_SECONDS);
  const freshDirectory = PublicKeyDirectory.inMemory([freshDevice.bundle()]);
  const freshVerifier = new DirectoryTokenVerifier(freshDirectory, false);
  const { permit: freshPermitE, scope: freshScopeE } = freshDevice.signIntent(actionScope);
  r = vendorApiCall({
    toolCall: {
      action: 'summarise',
      resource: 'contract-2026-042',
      on_behalf_of: 'user-ava',
    },
    permit: freshPermitE,
    scope: freshScopeE,
    verifier: freshVerifier,
  });
  console.log(`  new device key_id: ${freshDevice.keyId()}`);
  console.log(`  vendor API:        ${r.kind} (${r.reason})`);
  console.log();
  results.push(['Case E: re-signed permit after expiry permits', r.kind === 'permit']);

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
