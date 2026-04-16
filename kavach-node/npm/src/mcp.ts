/**
 * Kavach middleware for MCP TypeScript servers.
 *
 * Wraps the official @modelcontextprotocol/sdk tool handlers
 * so every call passes through the Rust gate.
 *
 * @example
 * ```typescript
 * import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
 * import { Gate, McpKavachMiddleware } from 'kavach';
 *
 * const gate = Gate.fromFile('kavach.toml');
 * const kavach = new McpKavachMiddleware(gate);
 *
 * const server = new McpServer({ name: 'my-server', version: '1.0' });
 *
 * server.tool('issue_refund', { amount: z.number(), orderId: z.string() },
 *   async ({ amount, orderId }) => {
 *     // Gate the call — throws KavachRefused if blocked
 *     kavach.checkToolCall('issue_refund', { amount, orderId }, {
 *       callerId: 'agent-bot',
 *       callerKind: 'agent',
 *       roles: ['support'],
 *     });
 *
 *     // If we reach here, the gate permitted
 *     const result = await processRefund(orderId, amount);
 *     return { content: [{ type: 'text', text: JSON.stringify(result) }] };
 *   }
 * );
 * ```
 */

import {
  Gate,
  type PrincipalKind,
  type EvaluateOptions,
  type GeoLocationInput,
} from './index';
import type { VerdictResult } from 'kavach-engine';

export interface McpCallerInfo {
  callerId: string;
  callerKind?: PrincipalKind;
  roles?: string[];
  sessionId?: string;
  ip?: string;
  /**
   * Current geographic location. Pair with `originGeo` and a
   * tolerant-mode `GeoLocationDrift` evaluator to tolerate
   * same-country IP hops.
   */
  currentGeo?: GeoLocationInput;
  /** Geographic location captured at session start. */
  originGeo?: GeoLocationInput;
}

/**
 * Kavach middleware for MCP servers.
 * All evaluation runs in the compiled Rust engine.
 */
export class McpKavachMiddleware {
  private gate: Gate;
  private sessions = new Map<string, { actionCount: number; invalidated: boolean }>();

  constructor(gate: Gate) {
    this.gate = gate;
  }

  /**
   * Check a tool call against the gate. Throws if blocked.
   *
   * @param toolName - The MCP tool being called
   * @param params - Tool parameters (numeric values checked against invariants)
   * @param caller - Caller identity information
   * @throws KavachRefused if the gate blocks the action
   * @throws KavachInvalidated if the session is revoked
   */
  checkToolCall(
    toolName: string,
    params: Record<string, unknown>,
    caller: McpCallerInfo,
  ): void {
    this.gate.check(this.buildContext(toolName, params, caller));
    this.recordAction(caller.sessionId);
  }

  /**
   * Evaluate a tool call without throwing. Returns the Verdict.
   */
  evaluateToolCall(
    toolName: string,
    params: Record<string, unknown>,
    caller: McpCallerInfo,
  ): VerdictResult {
    const verdict = this.gate.evaluate(this.buildContext(toolName, params, caller));
    if (verdict.isPermit) {
      this.recordAction(caller.sessionId);
    }
    return verdict;
  }

  /**
   * Create a wrapper function that gates any tool handler.
   *
   * @example
   * ```typescript
   * const guardedRefund = kavach.guardTool(
   *   'issue_refund',
   *   async (params) => processRefund(params),
   *   { callerId: 'agent-bot', callerKind: 'agent' },
   * );
   *
   * // Later:
   * const result = await guardedRefund({ amount: 500, orderId: 'ORD-123' });
   * ```
   */
  guardTool<T>(
    toolName: string,
    handler: (params: Record<string, unknown>) => T | Promise<T>,
    defaultCaller: McpCallerInfo,
  ): (params: Record<string, unknown>, callerOverride?: Partial<McpCallerInfo>) => Promise<T> {
    return async (params, callerOverride) => {
      const caller = { ...defaultCaller, ...callerOverride };
      this.checkToolCall(toolName, params, caller);
      return handler(params);
    };
  }

  invalidateSession(sessionId: string): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.invalidated = true;
    }
  }

  private buildContext(
    toolName: string,
    params: Record<string, unknown>,
    caller: McpCallerInfo,
  ): EvaluateOptions {
    const numericParams: Record<string, number> = {};
    for (const [k, v] of Object.entries(params)) {
      if (typeof v === 'number') {
        numericParams[k] = v;
      }
    }

    return {
      principalId: caller.callerId,
      principalKind: caller.callerKind ?? 'agent',
      actionName: toolName,
      roles: caller.roles,
      params: Object.keys(numericParams).length > 0 ? numericParams : undefined,
      ip: caller.ip,
      sessionId: caller.sessionId,
      currentGeo: caller.currentGeo,
      originGeo: caller.originGeo,
    };
  }

  private recordAction(sessionId?: string): void {
    if (!sessionId) return;
    const session = this.sessions.get(sessionId) ?? { actionCount: 0, invalidated: false };
    session.actionCount++;
    this.sessions.set(sessionId, session);
  }
}
