/**
 * Example: MCP Server with Kavach (TypeScript)
 *
 * Shows how to protect an MCP server's tool handlers with Kavach.
 * Every tool call is evaluated by the Rust engine before execution.
 *
 * Install:
 *   npm install kavach @modelcontextprotocol/sdk
 *
 * Run:
 *   npx tsx example_mcp_server.ts
 */

import { Gate, KavachRefused, KavachInvalidated } from 'kavach';
import { McpKavachMiddleware } from 'kavach/mcp';

// ── 1. Set up the gate ───────────────────────────────────────────

const POLICIES = `
[[policy]]
name = "agent_read_orders"
effect = "permit"
conditions = [
    { identity_kind = "agent" },
    { action = "read_order" },
    { rate_limit = { max = 100, window = "1h" } },
]

[[policy]]
name = "agent_small_refunds"
effect = "permit"
conditions = [
    { identity_kind = "agent" },
    { action = "issue_refund" },
    { param_max = { field = "amount", max = 5000.0 } },
    { rate_limit = { max = 20, window = "1h" } },
]
`;

const gate = Gate.fromToml(POLICIES, {
  invariants: [{ name: 'max_single_refund', field: 'amount', maxValue: 50_000 }],
  maxSessionActions: 500,
});

const kavach = new McpKavachMiddleware(gate);

// ── 2. Your tool handlers ────────────────────────────────────────

function readOrder(orderId: string) {
  return { orderId, amount: 2499.0, status: 'delivered' };
}

function issueRefund(orderId: string, amount: number) {
  console.log(`  >> Processing refund: ₹${amount} for ${orderId}`);
  return { refundId: 'ref_001', amount, status: 'processed' };
}

// ── 3. Simulate tool calls ───────────────────────────────────────

function handleToolCall(toolName: string, params: Record<string, unknown>) {
  console.log(`\nTool: ${toolName} | Params: ${JSON.stringify(params)}`);

  try {
    // Gate the call through Rust engine, throws if blocked
    kavach.checkToolCall(toolName, params, {
      callerId: 'support-bot',
      callerKind: 'agent',
      roles: ['support'],
      sessionId: 'session_001',
    });

    // If we reach here, the gate permitted
    let result: unknown;
    if (toolName === 'read_order') {
      result = readOrder(params.orderId as string);
    } else if (toolName === 'issue_refund') {
      result = issueRefund(params.orderId as string, params.amount as number);
    }
    console.log(`  ✓ PERMITTED, result: ${JSON.stringify(result)}`);
  } catch (err) {
    if (err instanceof KavachRefused) {
      console.log(`  ✗ REFUSED, [${err.code}] ${err.evaluator}: ${err.reason}`);
    } else if (err instanceof KavachInvalidated) {
      console.log(`  ⊘ INVALIDATED, ${err.reason}`);
    } else {
      throw err;
    }
  }
}

// ── 4. Also: guardTool wrapper pattern ───────────────────────────

// This wraps a handler so Kavach is automatic
const guardedRefund = kavach.guardTool(
  'issue_refund',
  async (params) => issueRefund(params.orderId as string, params.amount as number),
  { callerId: 'support-bot', callerKind: 'agent', roles: ['support'] },
);

// ── 5. Run scenarios ─────────────────────────────────────────────

console.log('=== Kavach TypeScript MCP Example ===');

// Should permit
handleToolCall('read_order', { orderId: 'ORD-7890' });

// Should permit (under ₹5,000 limit)
handleToolCall('issue_refund', { orderId: 'ORD-7890', amount: 500 });

// Should REFUSE (over ₹5,000 agent limit)
handleToolCall('issue_refund', { orderId: 'ORD-7890', amount: 25_000 });

// Should REFUSE (no policy, default deny)
handleToolCall('delete_customer', { customerId: 'cust_456' });

// Using the guardTool wrapper
console.log('\n--- guardTool wrapper pattern ---');
guardedRefund({ orderId: 'ORD-111', amount: 200 })
  .then(result => console.log(`  ✓ guardTool PERMITTED: ${JSON.stringify(result)}`))
  .catch(err => console.log(`  ✗ guardTool REFUSED: ${err.message}`));

console.log('\n=== Done ===');
