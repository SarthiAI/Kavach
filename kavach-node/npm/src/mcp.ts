/**
 * Kavach middleware for MCP TypeScript servers.
 *
 * Wraps the official @modelcontextprotocol/sdk tool handlers
 * so every call passes through the Rust gate.
 *
 * @example
 * ```typescript
 * import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
 * import { Gate, McpKavachMiddleware, InMemorySessionStore } from 'kavach';
 *
 * const gate = Gate.fromFile('kavach.toml');
 * const kavach = new McpKavachMiddleware(gate, {
 *   sessionStore: new InMemorySessionStore(),
 * });
 *
 * const server = new McpServer({ name: 'my-server', version: '1.0' });
 *
 * server.tool('issue_refund', { amount: z.number(), orderId: z.string() },
 *   async ({ amount, orderId }) => {
 *     // Gate the call, throws KavachRefused if blocked,
 *     // KavachInvalidated if the session has been revoked.
 *     kavach.checkToolCall('issue_refund', { amount, orderId }, {
 *       callerId: 'agent-bot',
 *       callerKind: 'agent',
 *       sessionId: 'sess-42',
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
  KavachInvalidated,
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
 * Pluggable per-session invalidation store.
 *
 * The MCP middleware calls `isInvalidated(sessionId)` before every
 * gated tool call so a peer-revoked session is refused without
 * reaching the gate, and `invalidate(sessionId)` on
 * `invalidateSession(...)` so the revocation fans out.
 *
 * The default backend is `InMemorySessionStore` (process-local
 * `Set`). Multi-replica deployments should swap in a Redis-backed
 * implementation: the interface is narrow enough that any
 * async-capable store fits without changes to the middleware.
 */
export interface SessionStore {
  isInvalidated(sessionId: string): boolean | Promise<boolean>;
  invalidate(sessionId: string): void | Promise<void>;
}

/**
 * Process-local session store, default backend for
 * `McpKavachMiddleware`. Tracks revoked session ids in a `Set`.
 * All operations are synchronous; the interface signature allows
 * Promise returns so Redis-backed stores slot in without changes
 * to the middleware.
 */
export class InMemorySessionStore implements SessionStore {
  private revoked = new Set<string>();

  isInvalidated(sessionId: string): boolean {
    return this.revoked.has(sessionId);
  }

  invalidate(sessionId: string): void {
    this.revoked.add(sessionId);
  }

  /** Number of revoked session ids currently held (observability / tests). */
  get size(): number {
    return this.revoked.size;
  }
}

export interface McpMiddlewareOptions {
  /**
   * Pluggable session store used for cross-replica invalidation
   * fan-out. Defaults to a fresh {@link InMemorySessionStore}.
   */
  sessionStore?: SessionStore;
}

/**
 * Kavach middleware for MCP servers.
 * All evaluation runs in the compiled Rust engine.
 */
export class McpKavachMiddleware {
  private gate: Gate;
  private store: SessionStore;
  private sessions = new Map<string, { actionCount: number }>();

  constructor(gate: Gate, options: McpMiddlewareOptions = {}) {
    this.gate = gate;
    this.store = options.sessionStore ?? new InMemorySessionStore();
  }

  /**
   * Check a tool call against the gate. Throws if blocked.
   *
   * When the call carries a `sessionId`, the middleware fast-paths
   * a session-store `isInvalidated` check BEFORE building the gate
   * context, a peer-revoked session surfaces as a
   * `KavachInvalidated` with `evaluator = "session_store"`.
   *
   * @param toolName - The MCP tool being called
   * @param params - Tool parameters (numeric values checked against invariants)
   * @param caller - Caller identity information
   * @throws KavachRefused if the gate blocks the action
   * @throws KavachInvalidated if the session is revoked (either via
   *   session-store fast-path or by a drift evaluator inside the gate)
   */
  async checkToolCall(
    toolName: string,
    params: Record<string, unknown>,
    caller: McpCallerInfo,
  ): Promise<void> {
    await this.fastPathInvalidationCheck(caller.sessionId);
    this.gate.check(this.buildContext(toolName, params, caller));
    this.recordAction(caller.sessionId);
  }

  /**
   * Evaluate a tool call without throwing. Returns the Verdict.
   *
   * If the session has been invalidated through the session store,
   * this returns a synthesised Invalidate verdict with
   * `evaluator = "session_store"`, the gate's own evaluator chain
   * is not run in that case, matching the Python middleware's
   * fast-path behaviour.
   */
  async evaluateToolCall(
    toolName: string,
    params: Record<string, unknown>,
    caller: McpCallerInfo,
  ): Promise<VerdictResult> {
    if (caller.sessionId && (await this.store.isInvalidated(caller.sessionId))) {
      return {
        kind: 'invalidate',
        evaluator: 'session_store',
        reason: `session ${caller.sessionId} has been invalidated`,
        code: null,
        tokenId: null,
        isPermit: false,
        isRefuse: false,
        isInvalidate: true,
        permitToken: null,
        signature: null,
      } as unknown as VerdictResult;
    }
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
      await this.checkToolCall(toolName, params, caller);
      return handler(params);
    };
  }

  /**
   * Revoke a session across every replica that shares the
   * configured session store. Subsequent `checkToolCall` /
   * `evaluateToolCall` on the same session id will be refused
   * at the session-store fast-path.
   */
  async invalidateSession(sessionId: string): Promise<void> {
    await this.store.invalidate(sessionId);
  }

  private async fastPathInvalidationCheck(sessionId?: string): Promise<void> {
    if (!sessionId) return;
    if (await this.store.isInvalidated(sessionId)) {
      throw new KavachInvalidated(
        `session ${sessionId} has been invalidated`,
        'session_store',
      );
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
    const session = this.sessions.get(sessionId) ?? { actionCount: 0 };
    session.actionCount++;
    this.sessions.set(sessionId, session);
  }
}
