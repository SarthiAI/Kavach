/**
 * Scenario 19: one Kavach-signed intent, four SaaS systems.
 *
 * The business story
 * ------------------
 * The CFO clicks 'pay invoice INV-1234'. Behind that click, an
 * AI agent runs a flow across four unrelated SaaS products.
 * NetSuite pulls the invoice. Stripe sends the payout. Ramp
 * writes the GL entry. Slack posts the confirmation.
 *
 * Why OAuth is not enough. OAuth scopes are per platform.
 * Stripe's 'payouts.write' has nothing to say about NetSuite's
 * 'invoices.read'. You cannot express 'for this ONE invoice,
 * allow these four calls'. The usual fallback is broad tokens to
 * every platform, and a prompt injection inside any one of those
 * platforms' data can swing any of those tokens at anything.
 *
 * What Kavach does
 * ----------------
 * The CFO signs ONE Kavach intent at click time. The scope
 * (invoice, vendor, amount cap, target channel, principal) is
 * bound into the permit with an ML-DSA-65 signature. Every SaaS
 * adapter verifies Kavach's signature and refuses anything that
 * has drifted from the signed scope.
 *
 * The whole run lands in a Kavach signed audit chain that the
 * internal risk team or an external auditor can re-verify
 * independently.
 *
 * Six cases:
 *
 *     A. NetSuite reads INV-1234 under the intent.
 *     B. Stripe sends a $4,800 payout to vendor acme.
 *     C. Ramp writes the matching GL entry.
 *     D. Injection swaps the invoice to INV-9999. Refused.
 *     E. Attacker relabels the Stripe permit as a NetSuite delete. Refused.
 *     F. Amount escalation to $50,000. Refused.
 *
 * Run this file directly:
 *
 *   node dist/tier3/19_cross_saas_finance_agent.js
 */

import { createHash } from 'node:crypto';

import {
  AuditEntry,
  DirectoryTokenVerifier,
  Gate,
  KavachKeyPair,
  PqTokenSigner,
  PublicKeyDirectory,
  SignedAuditChain,
  type PermitTokenView,
} from 'kavach-sdk';

const INTENT_ACTION = 'finance.pay_invoice';

const INTENT_POLICIES = {
  policies: [
    {
      name: 'cfo_signs_pay_invoice',
      effect: 'permit',
      priority: 10,
      conditions: [
        { identity_role: 'cfo' },
        { param_max: { field: 'max_amount_usd', max: 5000.0 } },
      ],
    },
  ],
};

type Scope = {
  user_id: string;
  invoice_id: string;
  vendor_id: string;
  max_amount_usd: number;
  channel: string;
};

type AdapterCfg = {
  handles: string[];
  must_match: (keyof Scope)[];
  caps: [string, keyof Scope][];
};

const ADAPTERS: Record<string, AdapterCfg> = {
  netsuite: { handles: ['invoice.read'], must_match: ['invoice_id'], caps: [] },
  stripe: {
    handles: ['payment.initiate'],
    must_match: ['invoice_id', 'vendor_id'],
    caps: [['amount_usd', 'max_amount_usd']],
  },
  ramp: {
    handles: ['gl.write_entry'],
    must_match: ['invoice_id'],
    caps: [['amount_usd', 'max_amount_usd']],
  },
  slack: { handles: ['chat.post_message'], must_match: ['channel'], caps: [] },
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

type ToolCall = {
  action: string;
  on_behalf_of?: string;
  invoice_id?: string;
  vendor_id?: string;
  amount_usd?: number;
  channel?: string;
};

type AdapterResult = { system: string; kind: 'permit' | 'refuse'; reason: string };

function saasAdapter(
  system: string,
  toolCall: ToolCall,
  permit: PermitTokenView,
  scope: Scope,
  verifier: DirectoryTokenVerifier,
  chain: SignedAuditChain,
): AdapterResult {
  const cfg = ADAPTERS[system]!;

  const finish = (kind: 'permit' | 'refuse', reason: string): AdapterResult => {
    chain.append(
      AuditEntry.new(
        toolCall.on_behalf_of ?? 'unknown',
        `${system}.${toolCall.action}`,
        kind,
        reason,
      ),
    );
    return { system, kind, reason };
  };

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
    return finish('refuse', `permit invalid: ${(e as Error).message.slice(0, 80)}`);
  }

  const [base] = permit.actionName.split(':');
  if (base !== INTENT_ACTION) {
    return finish('refuse', `permit is not a ${INTENT_ACTION}`);
  }
  if (permit.actionName !== bindAction(INTENT_ACTION, scope)) {
    return finish('refuse', 'scope does not match the signed intent (hash mismatch)');
  }

  if (!cfg.handles.includes(toolCall.action)) {
    return finish('refuse', `${system} does not handle '${toolCall.action}'`);
  }
  for (const field of cfg.must_match) {
    const tcVal = (toolCall as Record<string, unknown>)[field];
    const scVal = scope[field];
    if (tcVal !== scVal) {
      return finish(
        'refuse',
        `${field} '${String(tcVal)}' != scope '${String(scVal)}'`,
      );
    }
  }
  for (const [toolField, scopeField] of cfg.caps) {
    const tcVal = (toolCall as Record<string, unknown>)[toolField] as number;
    const scVal = scope[scopeField] as unknown as number;
    if (tcVal > scVal) {
      return finish('refuse', `${toolField} $${tcVal} > cap $${scVal}`);
    }
  }

  return finish('permit', `ran under intent ${permit.tokenId}`);
}

function main(): number {
  console.log('='.repeat(70));
  console.log('Scenario 19: one Kavach-signed intent, four SaaS systems');
  console.log('='.repeat(70));
  console.log();
  console.log("The CFO clicks 'pay invoice INV-1234'. Kavach signs that click.");
  console.log('The AI agent then runs across NetSuite, Stripe, Ramp, and Slack.');
  console.log('Every one of those SaaS adapters refuses anything that does not');
  console.log("match the CFO's signed intent. Below we run the clean flow, three");
  console.log('injections, and verify the signed audit chain at the end.');
  console.log();

  // Setup.
  const cfoKp = KavachKeyPair.generateWithExpiry(300);
  const verifier = new DirectoryTokenVerifier(
    PublicKeyDirectory.inMemory([cfoKp.publicKeys()]),
    false,
  );
  const intentGate = Gate.fromObject(INTENT_POLICIES, {
    tokenSigner: PqTokenSigner.fromKeypairPqOnly(cfoKp),
  });
  const auditKp = KavachKeyPair.generate();
  const chain = new SignedAuditChain(auditKp, false);

  // CFO signs one intent.
  console.log("CFO clicks 'pay INV-1234'. One signed intent covers the whole run.");
  const scope: Scope = {
    user_id: 'cfo-kiran',
    invoice_id: 'INV-1234',
    vendor_id: 'vend-acme',
    max_amount_usd: 5000.0,
    channel: '#finance-ops',
  };
  console.log(`  scope: ${JSON.stringify(scope)}`);

  const permit: PermitTokenView = intentGate.evaluate({
    principalId: scope.user_id,
    principalKind: 'user',
    actionName: bindAction(INTENT_ACTION, scope),
    roles: ['cfo'],
    params: { max_amount_usd: scope.max_amount_usd },
  }).permitToken!;
  console.log(`  intent token id:  ${permit.tokenId}`);
  console.log(`  action_name:      ${permit.actionName}`);
  console.log();

  function call(
    system: string,
    toolCall: ToolCall,
    scopeForCall?: Scope,
  ): AdapterResult {
    toolCall.on_behalf_of = scope.user_id;
    const r = saasAdapter(
      system,
      toolCall,
      permit,
      scopeForCall ?? scope,
      verifier,
      chain,
    );
    console.log(`  ${r.system.padEnd(10)} ${r.kind.padEnd(7)} ${r.reason}`);
    return r;
  }

  const results: [string, boolean][] = [];

  console.log('Case A: NetSuite reads INV-1234.');
  let r = call('netsuite', { action: 'invoice.read', invoice_id: 'INV-1234' });
  results.push(['Case A: NetSuite read permits', r.kind === 'permit']);
  console.log();

  console.log('Case B: Stripe sends $4,800 payout to vend-acme.');
  r = call('stripe', {
    action: 'payment.initiate',
    invoice_id: 'INV-1234',
    vendor_id: 'vend-acme',
    amount_usd: 4800.0,
  });
  results.push(['Case B: Stripe payment permits', r.kind === 'permit']);
  console.log();

  console.log('Case C: Ramp writes the GL entry for $4,800.');
  r = call('ramp', {
    action: 'gl.write_entry',
    invoice_id: 'INV-1234',
    amount_usd: 4800.0,
  });
  results.push(['Case C: Ramp GL entry permits', r.kind === 'permit']);
  console.log();

  console.log("Case D: injection in the invoice PDF says 'also pay INV-9999'. The");
  console.log('        agent builds a tampered scope and a matching tool call.');
  console.log("        Kavach's signature covers the original invoice; the adapter");
  console.log('        refuses.');
  const tamperedScopeD: Scope = {
    ...scope,
    invoice_id: 'INV-9999',
    vendor_id: 'vend-starfall',
  };
  r = call(
    'stripe',
    {
      action: 'payment.initiate',
      invoice_id: 'INV-9999',
      vendor_id: 'vend-starfall',
      amount_usd: 4900.0,
    },
    tamperedScopeD,
  );
  results.push([
    'Case D: wrong invoice refused via hash mismatch',
    r.kind === 'refuse' && r.reason.includes('hash mismatch'),
  ]);
  console.log();

  console.log('Case E: attacker relabels Stripe permit as a NetSuite delete.');
  r = call('netsuite', { action: 'invoice.delete', invoice_id: 'INV-1234' });
  results.push(['Case E: adapter action relabel refused', r.kind === 'refuse']);
  console.log();

  console.log('Case F: injection inflates the amount to $50,000. The agent raises');
  console.log("        its own scope to cover it. Kavach's signature was over the");
  console.log('        original scope; the adapter refuses.');
  const tamperedScopeF: Scope = { ...scope, max_amount_usd: 100000.0 };
  r = call(
    'stripe',
    {
      action: 'payment.initiate',
      invoice_id: 'INV-1234',
      vendor_id: 'vend-acme',
      amount_usd: 50000.0,
    },
    tamperedScopeF,
  );
  results.push([
    'Case F: amount escalation refused via hash mismatch',
    r.kind === 'refuse' && r.reason.includes('hash mismatch'),
  ]);
  console.log();

  console.log('Slack confirms to #finance-ops.');
  r = call('slack', { action: 'chat.post_message', channel: '#finance-ops' });
  results.push(['Final: Slack post permits', r.kind === 'permit']);
  console.log();

  // Reverify audit chain.
  const verified = SignedAuditChain.verifyJsonl(chain.exportJsonl(), auditKp.publicKeys());
  results.push(['Final: audit chain reverifies cleanly', verified === chain.length]);
  console.log(`audit entries verified: ${verified}/${chain.length}`);
  console.log();

  console.log('='.repeat(70));
  console.log('Summary');
  console.log('='.repeat(70));
  const passed = results.filter(([, ok]) => ok).length;
  for (const [label, ok] of results) {
    console.log(`  [${ok ? 'PASS' : 'FAIL'}] ${label}`);
  }
  console.log();
  console.log(`${passed}/${results.length} checks passed.`);
  console.log();
  return passed === results.length ? 0 : 1;
}

try {
  process.exit(main());
} catch (e) {
  console.error(e);
  process.exit(1);
}
