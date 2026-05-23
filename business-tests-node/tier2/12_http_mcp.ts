/**
 * Scenario 12: HTTP middleware and MCP middleware end to end.
 *
 * Experimental surface
 * --------------------
 * The HTTP and MCP middlewares demoed here are shipped but not yet
 * thoroughly validated through the consumer workflow harness that
 * covers the rest of the Node SDK. The primitives work (the cases
 * below run green), and the API surface is stable, but if you are
 * standing this up in production today, treat these middlewares as
 * 'preview' rather than 'battle tested at scale'. The core gate,
 * signed permits, audit chains, SecureChannel, and drift detectors
 * (all other scenarios in this folder) are the battle tested surface.
 *
 * The story
 * ---------
 * Two of the most common ways people integrate Kavach are:
 *
 *     HTTP side. A web API (Express, Fastify, Hono, or any Node
 *     framework) wires HttpKavachMiddleware in front of its routes.
 *     Every request is evaluated by the gate before the handler runs.
 *     If the gate permits, the handler returns normally. If not, the
 *     middleware short circuits and returns a 403.
 *
 *     MCP side. An MCP server hosts tools that agents can call.
 *     McpKavachMiddleware wraps those tool calls and decides whether
 *     an agent is allowed to invoke a particular tool. It also tracks
 *     per session state so a session can be invalidated from outside
 *     (say, by an admin), and the next call on that session is
 *     rejected before the gate even runs.
 *
 * We will exercise both sides in this one scenario, calling each
 * middleware's evaluate / checkToolCall surface directly so we get
 * deterministic coverage without standing up a real HTTP server.
 *
 * One extra thing we want to pin: HttpKavachMiddleware can take a
 * geoResolver function. That function gets called to look up a geo
 * location for the caller's IP when the request does not carry an
 * explicit geo. The rule is: explicit beats resolver. If the caller
 * (or the app) already passed currentGeo or originGeo, the resolver
 * is not called. We count resolver invocations to prove this.
 *
 * Eight cases:
 *
 *     A. HTTP POST with role=customer        , expect permit / 200
 *     B. HTTP POST with role=guest           , expect refuse / 403
 *     C. Resolver call counter after A and B , expect 2
 *     D. Direct evaluate with currentGeo set , resolver count unchanged
 *     E. Direct evaluate with originGeo set  , resolver count unchanged
 *     F. MCP checkToolCall on a whitelisted tool, no exception raised
 *     G. MCP checkToolCall on an unknown tool  , raises KavachRefused
 *     H. invalidateSession, next call on that sid raises
 *        KavachInvalidated, a fresh session still works.
 *
 * Run this file directly:
 *
 *   node dist/tier2/12_http_mcp.js
 */

import {
  Gate,
  HttpKavachMiddleware,
  InMemorySessionStore,
  KavachInvalidated,
  KavachRefused,
  McpKavachMiddleware,
  type GeoLocationInput,
} from 'kavach-sdk';

// ---------------------------------------------------------------------
// HTTP side: a single permit rule for 'customers posting orders'.
// The HTTP middleware derives the action name from the method and path
// (POST /api/v1/orders becomes 'orders.create'), so the rule matches
// action = 'orders.create'.
// ---------------------------------------------------------------------
const HTTP_POLICIES = {
  policies: [
    {
      name: 'customer_places_order',
      description: 'Authenticated customers may POST /api/v1/orders',
      effect: 'permit',
      priority: 10,
      conditions: [{ identity_role: 'customer' }, { action: 'orders.create' }],
    },
  ],
};

// ---------------------------------------------------------------------
// MCP side: two permit rules, one for list_files and one for read_file.
// 'danger_exec' is intentionally not in this list, so calls to it will
// fall through to default deny and the middleware will raise
// KavachRefused.
// ---------------------------------------------------------------------
const MCP_POLICIES = {
  policies: [
    {
      name: 'agent_list_files',
      description: 'Agents may call list_files',
      effect: 'permit',
      priority: 10,
      conditions: [{ identity_role: 'agent' }, { action: 'list_files' }],
    },
    {
      name: 'agent_read_file',
      description: 'Agents may call read_file',
      effect: 'permit',
      priority: 10,
      conditions: [{ identity_role: 'agent' }, { action: 'read_file' }],
    },
  ],
};

const NYC: GeoLocationInput = {
  countryCode: 'US',
  city: 'New York',
  latitude: 40.7128,
  longitude: -74.006,
};
const TOKYO: GeoLocationInput = {
  countryCode: 'JP',
  city: 'Tokyo',
  latitude: 35.6762,
  longitude: 139.6503,
};

interface ResolverCall {
  method: string;
  path: string;
  ip?: string;
}

class CountingResolver {
  // A tiny IP to geo resolver that records every call. The middleware
  // only calls this when neither originGeo nor currentGeo is set on
  // the evaluate call. We use the counter to prove that rule.
  public calls: ResolverCall[] = [];

  resolve = (req: {
    method: string;
    path: string;
    headers: Record<string, string | string[] | undefined>;
    ip?: string;
  }): { currentGeo?: GeoLocationInput; originGeo?: GeoLocationInput } => {
    this.calls.push({ method: req.method, path: req.path, ip: req.ip });
    return { currentGeo: NYC };
  };
}

async function main(): Promise<number> {
  console.log('='.repeat(70));
  console.log('Scenario 12: HTTP middleware and MCP middleware end to end');
  console.log('='.repeat(70));
  console.log();
  console.log('We are going to build two gates, wire each one through its');
  console.log('matching middleware (HTTP and MCP), and run real requests');
  console.log('through them. The HTTP half calls the middleware directly');
  console.log('with a request shape (same path an Express adapter exercises).');
  console.log('The MCP half uses the in memory session store so we can show');
  console.log('cross session invalidation.');
  console.log();

  const results: [string, boolean][] = [];

  // -----------------------------------------------------------------
  // Step 2. HTTP side setup.
  // -----------------------------------------------------------------
  console.log('Building the HTTP gate and middleware.');
  const httpGate = Gate.fromObject(HTTP_POLICIES, { geoDriftMaxKm: 500.0 });
  const resolver = new CountingResolver();
  const httpMw = new HttpKavachMiddleware(httpGate, { geoResolver: resolver.resolve });
  console.log(`  httpGate.evaluatorCount: ${httpGate.evaluatorCount}`);
  console.log(`  resolver class:          ${resolver.constructor.name}`);
  console.log();

  // -----------------------------------------------------------------
  // Case A: HTTP permit.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case A: POST /api/v1/orders with role=customer.');
  console.log('-'.repeat(70));
  console.log('The middleware reads x-principal-id and x-roles from the');
  console.log('request headers, builds an action name from the method and');
  console.log('path, and evaluates through the gate. The rule permits');
  console.log('role=customer on orders.create. The verdict is permit.');
  console.log('No explicit geo is passed, so the resolver should be called.');
  console.log();

  let verdict = httpMw.evaluate({
    method: 'POST',
    path: '/api/v1/orders',
    headers: { 'x-principal-id': 'alice', 'x-roles': 'customer' },
    body: { amount_usd: 250.0 },
    ip: '203.0.113.10',
  });
  const statusA = verdict.isPermit ? 200 : 403;
  const bodyA = verdict.isPermit
    ? { ok: true, order_id: 'ord_abc123' }
    : {
        error: verdict.reason ?? 'refused',
        code: verdict.code,
        evaluator: verdict.evaluator,
      };

  console.log(`HTTP status:       ${statusA}`);
  console.log(`Response body:     ${JSON.stringify(bodyA)}`);
  console.log(`resolver.calls so far: ${resolver.calls.length}`);
  console.log();

  results.push(['Case A: status 200', statusA === 200]);
  results.push([
    'Case A: body ok is True',
    (bodyA as { ok?: boolean }).ok === true,
  ]);
  results.push(['Case A: resolver was called once', resolver.calls.length === 1]);

  // -----------------------------------------------------------------
  // Case B: HTTP refuse.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case B: POST /api/v1/orders with role=guest.');
  console.log('-'.repeat(70));
  console.log('Same endpoint, but the role does not match the rule. The');
  console.log('gate falls through to default deny. The middleware returns');
  console.log('a verdict that maps to HTTP 403. The resolver still fires');
  console.log('for this call. The counter goes up to 2.');
  console.log();

  verdict = httpMw.evaluate({
    method: 'POST',
    path: '/api/v1/orders',
    headers: { 'x-principal-id': 'mallory', 'x-roles': 'guest' },
    body: { amount_usd: 250.0 },
    ip: '203.0.113.11',
  });
  const statusB = verdict.isPermit ? 200 : 403;
  const bodyB = verdict.isPermit
    ? { ok: true }
    : {
        error: verdict.reason ?? 'refused',
        code: verdict.code,
        evaluator: verdict.evaluator,
      };

  console.log(`HTTP status:       ${statusB}`);
  console.log(`Response body:     ${JSON.stringify(bodyB)}`);
  console.log(`resolver.calls so far: ${resolver.calls.length}`);
  console.log();

  results.push(['Case B: status 403', statusB === 403]);
  results.push([
    "Case B: error evaluator is 'policy'",
    (bodyB as { evaluator?: string }).evaluator === 'policy',
  ]);
  results.push([
    'Case B: error code is NO_POLICY_MATCH',
    (bodyB as { code?: string }).code === 'NO_POLICY_MATCH',
  ]);
  results.push(['Case B: resolver now called twice', resolver.calls.length === 2]);

  // -----------------------------------------------------------------
  // Case C: resolver counter summary.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case C: confirming the resolver counter is at 2.');
  console.log('-'.repeat(70));
  console.log('We also peek at the first recorded resolver call to confirm');
  console.log('the middleware passed the right method and path into it.');
  console.log();

  const firstCall = resolver.calls[0] ?? ({} as ResolverCall);
  console.log(`resolver.calls length: ${resolver.calls.length}`);
  console.log(`first call method:     ${firstCall.method}`);
  console.log(`first call path:       ${firstCall.path}`);
  console.log(`first call ip:         ${firstCall.ip}`);
  console.log();

  results.push(['Case C: resolver called exactly twice', resolver.calls.length === 2]);
  results.push([
    'Case C: resolver saw the /api/v1/orders path',
    firstCall.path === '/api/v1/orders',
  ]);

  // -----------------------------------------------------------------
  // Case D: explicit currentGeo skips the resolver.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case D: direct evaluate call with explicit currentGeo=TOKYO.');
  console.log('-'.repeat(70));
  console.log('We call httpMw.evaluate directly with currentGeo already set.');
  console.log('The middleware only falls back to the resolver when both');
  console.log('originGeo and currentGeo are missing, so it should NOT call');
  console.log('the resolver here. We check that the counter does not move.');
  console.log();

  let before = resolver.calls.length;
  let v = httpMw.evaluate({
    method: 'POST',
    path: '/api/v1/orders',
    headers: {
      'x-principal-id': 'explicit-geo-alice',
      'x-roles': 'customer',
      'x-principal-kind': 'user',
    },
    ip: '198.51.100.50',
    currentGeo: TOKYO,
  });
  let after = resolver.calls.length;
  console.log(`Verdict kind: ${v.kind}`);
  console.log(`Is permit:    ${v.isPermit}`);
  console.log(`resolver.calls before: ${before}`);
  console.log(`resolver.calls after:  ${after}`);
  console.log();

  results.push(['Case D: direct evaluate permits', v.isPermit]);
  results.push([
    'Case D: resolver counter unchanged (explicit currentGeo wins)',
    after === before,
  ]);

  // -----------------------------------------------------------------
  // Case E: explicit originGeo also skips the resolver.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case E: direct evaluate call with explicit originGeo=NYC.');
  console.log('-'.repeat(70));
  console.log('Same idea, but this time only originGeo is set. The rule is');
  console.log("'either explicit is enough to skip the resolver'. Counter");
  console.log('should not move.');
  console.log();

  before = resolver.calls.length;
  v = httpMw.evaluate({
    method: 'POST',
    path: '/api/v1/orders',
    headers: {
      'x-principal-id': 'explicit-origin-bob',
      'x-roles': 'customer',
      'x-principal-kind': 'user',
    },
    ip: '198.51.100.51',
    originGeo: NYC,
  });
  after = resolver.calls.length;
  console.log(`Verdict kind: ${v.kind}`);
  console.log(`Is permit:    ${v.isPermit}`);
  console.log(`resolver.calls before: ${before}`);
  console.log(`resolver.calls after:  ${after}`);
  console.log();

  results.push(['Case E: direct evaluate permits', v.isPermit]);
  results.push([
    'Case E: resolver counter unchanged (explicit originGeo wins)',
    after === before,
  ]);

  // -----------------------------------------------------------------
  // Step 3. MCP side setup.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Now the MCP side.');
  console.log('-'.repeat(70));
  console.log('Building the MCP gate, the in memory session store, and the');
  console.log('MCP middleware. The session store is what lets us invalidate');
  console.log('a session from outside; the middleware consults it at the');
  console.log('start of every tool call.');
  console.log();

  const mcpGate = Gate.fromObject(MCP_POLICIES);
  const mcpStore = new InMemorySessionStore();
  const mcpMw = new McpKavachMiddleware(mcpGate, { sessionStore: mcpStore });
  console.log(`  mcpGate.evaluatorCount: ${mcpGate.evaluatorCount}`);
  console.log(`  store type:             ${mcpStore.constructor.name}`);
  console.log(`  store.size (initial):   ${mcpStore.size}`);
  console.log();

  const SESSION_A = 'sess-aa11bbcc';
  const SESSION_B = 'sess-ffeedd99';

  // -----------------------------------------------------------------
  // Case F: MCP permit.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log("Case F: checkToolCall('list_files') from an agent.");
  console.log('-'.repeat(70));
  console.log('list_files is on the whitelist. The middleware evaluates');
  console.log('through the gate, gets a permit, and returns without');
  console.log('raising. We expect: no exception raised, and the session is');
  console.log('not invalidated in the store.');
  console.log();

  let raised: unknown = null;
  try {
    await mcpMw.checkToolCall(
      'list_files',
      {},
      {
        callerId: 'tool-runner-01',
        callerKind: 'agent',
        roles: ['agent'],
        sessionId: SESSION_A,
      },
    );
  } catch (e) {
    raised = e;
  }

  const storeInvalidatedA = await Promise.resolve(mcpStore.isInvalidated(SESSION_A));
  console.log(`raised:                    ${raised ? (raised as Error).name : null}`);
  console.log(`store.isInvalidated(A):    ${storeInvalidatedA}`);
  console.log();

  results.push(['Case F: checkToolCall did not raise', raised === null]);
  results.push([
    'Case F: session A not invalidated in store',
    storeInvalidatedA === false,
  ]);

  // -----------------------------------------------------------------
  // Case G: MCP refuse.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log("Case G: checkToolCall('danger_exec') from the same agent.");
  console.log('-'.repeat(70));
  console.log('danger_exec is not on the whitelist. The gate returns a');
  console.log('refuse verdict. The middleware turns that into a');
  console.log('KavachRefused exception. We expect: KavachRefused raised.');
  console.log();

  let refusedOk = false;
  try {
    await mcpMw.checkToolCall(
      'danger_exec',
      {},
      {
        callerId: 'tool-runner-01',
        callerKind: 'agent',
        roles: ['agent'],
        sessionId: SESSION_A,
      },
    );
  } catch (e) {
    if (e instanceof KavachRefused) {
      refusedOk = true;
      console.log(`raised KavachRefused as expected: ${e.message}`);
    } else {
      console.log(`raised wrong exception type: ${(e as Error).name}: ${(e as Error).message}`);
    }
  }
  console.log();

  results.push(['Case G: danger_exec raised KavachRefused', refusedOk]);

  // -----------------------------------------------------------------
  // Case H: invalidation fan out.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case H: invalidateSession, then next call raises KavachInvalidated.');
  console.log('-'.repeat(70));
  console.log('An admin calls invalidateSession(SESSION_A). That writes to');
  console.log('the store. The next call on the same session, even for an');
  console.log('otherwise whitelisted tool, short circuits in the middleware');
  console.log('before the gate runs and raises KavachInvalidated. A call on');
  console.log('a different session still works, because invalidation is');
  console.log('scoped to that one session id.');
  console.log();

  await mcpMw.invalidateSession(SESSION_A);
  const storeInvalidatedAfter = await Promise.resolve(mcpStore.isInvalidated(SESSION_A));
  console.log(`store.isInvalidated(A): ${storeInvalidatedAfter}`);
  console.log();

  results.push([
    'Case H: store reports session A invalidated',
    storeInvalidatedAfter === true,
  ]);

  let invalidatedOk = false;
  try {
    await mcpMw.checkToolCall(
      'list_files',
      {},
      {
        callerId: 'tool-runner-01',
        callerKind: 'agent',
        roles: ['agent'],
        sessionId: SESSION_A,
      },
    );
  } catch (e) {
    if (e instanceof KavachInvalidated) {
      invalidatedOk = true;
      console.log(`raised KavachInvalidated as expected: ${e.message}`);
    } else {
      console.log(`raised wrong exception type: ${(e as Error).name}: ${(e as Error).message}`);
    }
  }
  console.log();

  results.push([
    'Case H: next call on session A raises KavachInvalidated',
    invalidatedOk,
  ]);

  // Fresh session B should still work.
  let raisedB: unknown = null;
  try {
    await mcpMw.checkToolCall(
      'list_files',
      {},
      {
        callerId: 'tool-runner-01',
        callerKind: 'agent',
        roles: ['agent'],
        sessionId: SESSION_B,
      },
    );
  } catch (e) {
    raisedB = e;
  }
  const storeInvalidatedB = await Promise.resolve(mcpStore.isInvalidated(SESSION_B));
  console.log(`Session B raised: ${raisedB ? (raisedB as Error).name : null}`);
  console.log(`store.isInvalidated(B): ${storeInvalidatedB}`);
  console.log();

  results.push(['Case H: fresh session B still permits', raisedB === null]);
  results.push([
    'Case H: store reports session B not invalidated',
    storeInvalidatedB === false,
  ]);

  // -----------------------------------------------------------------
  // Summary
  // -----------------------------------------------------------------
  console.log('='.repeat(70));
  console.log('Summary');
  console.log('='.repeat(70));
  const passed = results.filter(([, k]) => k).length;
  for (const [label, k] of results) {
    const mark = k ? 'PASS' : 'FAIL';
    console.log(`  [${mark}] ${label}`);
  }
  console.log();
  console.log(`${passed}/${results.length} checks passed.`);
  console.log();

  return passed === results.length ? 0 : 1;
}

main()
  .then((rc) => process.exit(rc))
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });
