/**
 * Kavach middleware for Node.js HTTP frameworks.
 *
 * Works with Express, Fastify, Hono, and any framework
 * that supports middleware functions.
 *
 * @example Express
 * ```typescript
 * import express from 'express';
 * import { Gate, createExpressMiddleware } from 'kavach';
 *
 * const gate = Gate.fromFile('kavach.toml');
 * const app = express();
 *
 * // Gate all mutating requests
 * app.use(createExpressMiddleware(gate));
 *
 * app.post('/api/refunds', (req, res) => {
 *   // If we reach here, Kavach permitted the action
 *   res.json({ status: 'refunded' });
 * });
 * ```
 */

import {
  Gate,
  KavachRefused,
  KavachInvalidated,
  type PrincipalKind,
  type GeoLocationInput,
} from './index';
import type { VerdictResult } from 'kavach-engine';

export interface HttpMiddlewareOptions {
  /** Only gate mutating requests (POST/PUT/DELETE/PATCH). Default: true */
  gateMutationsOnly?: boolean;
  /** Paths to exclude from gating. Default: ['/health', '/ready'] */
  excludedPaths?: string[];
  /** Header containing principal ID. Default: 'x-principal-id' */
  principalHeader?: string;
  /** Header containing roles (comma-separated). Default: 'x-roles' */
  rolesHeader?: string;
  /** Header containing principal kind. Default: 'x-principal-kind' */
  kindHeader?: string;
  /**
   * Optional geo resolver — integrators plug in their GeoIP lookup
   * (MaxMind, CDN edge headers, etc.) to populate `currentGeo` and
   * `originGeo`. Return `undefined` for either to leave it unset.
   * Needed to drive tolerant-mode `GeoLocationDrift`.
   */
  geoResolver?: (req: {
    method: string;
    path: string;
    headers: Record<string, string | string[] | undefined>;
    ip?: string;
  }) => { currentGeo?: GeoLocationInput; originGeo?: GeoLocationInput } | undefined;
}

const VERB_MAP: Record<string, string> = {
  GET: 'read',
  POST: 'create',
  PUT: 'update',
  PATCH: 'update',
  DELETE: 'delete',
};

/**
 * Derive an action name from HTTP method + path.
 * POST /api/v1/refunds → refunds.create
 */
export function deriveActionName(method: string, path: string): string {
  const parts = path
    .split('/')
    .filter(p => p && p !== 'api' && !p.startsWith('v') && !/^\d+$/.test(p));
  const resource = parts[parts.length - 1] || 'unknown';
  const verb = VERB_MAP[method.toUpperCase()] || 'unknown';
  return `${resource}.${verb}`;
}

/**
 * Core HTTP gate — framework agnostic.
 */
export class HttpKavachMiddleware {
  private gate: Gate;
  private opts: Required<HttpMiddlewareOptions>;

  constructor(gate: Gate, options: HttpMiddlewareOptions = {}) {
    this.gate = gate;
    this.opts = {
      gateMutationsOnly: options.gateMutationsOnly ?? true,
      excludedPaths: options.excludedPaths ?? ['/health', '/ready', '/metrics'],
      principalHeader: options.principalHeader ?? 'x-principal-id',
      rolesHeader: options.rolesHeader ?? 'x-roles',
      kindHeader: options.kindHeader ?? 'x-principal-kind',
      geoResolver: options.geoResolver ?? (() => undefined),
    };
  }

  shouldGate(method: string, path: string): boolean {
    if (this.opts.excludedPaths.some(p => path.startsWith(p))) return false;
    if (this.opts.gateMutationsOnly && method.toUpperCase() === 'GET') return false;
    return true;
  }

  evaluate(req: {
    method: string;
    path: string;
    headers: Record<string, string | string[] | undefined>;
    body?: Record<string, unknown>;
    ip?: string;
    /**
     * Current geographic location for this request (→ `EnvContext.geo`).
     * Integrators populate from GeoIP / CDN headers / edge metadata.
     */
    currentGeo?: GeoLocationInput;
    /**
     * Geographic location captured at session start
     * (→ `SessionState.origin_geo`). Integrators pass this from
     * wherever session state lives.
     */
    originGeo?: GeoLocationInput;
  }): VerdictResult {
    const header = (name: string) => {
      const v = req.headers[name];
      return typeof v === 'string' ? v : v?.[0] ?? '';
    };

    const numericParams: Record<string, number> = {};
    if (req.body) {
      for (const [k, v] of Object.entries(req.body)) {
        if (typeof v === 'number') numericParams[k] = v;
      }
    }

    // If the caller didn't pass explicit geo, fall back to the configured
    // resolver. Keeps factories and direct callers symmetric.
    const resolved =
      req.currentGeo === undefined && req.originGeo === undefined
        ? this.opts.geoResolver({
            method: req.method,
            path: req.path,
            headers: req.headers,
            ip: req.ip,
          })
        : undefined;

    return this.gate.evaluate({
      principalId: header(this.opts.principalHeader) || 'anonymous',
      principalKind: (header(this.opts.kindHeader) || 'user') as PrincipalKind,
      actionName: deriveActionName(req.method, req.path),
      roles: header(this.opts.rolesHeader).split(',').filter(Boolean),
      resource: req.path,
      params: Object.keys(numericParams).length > 0 ? numericParams : undefined,
      ip: req.ip,
      currentGeo: req.currentGeo ?? resolved?.currentGeo,
      originGeo: req.originGeo ?? resolved?.originGeo,
    });
  }
}

// ─── Express middleware factory ──────────────────────────────────

/**
 * Create Express middleware that gates requests through Kavach.
 *
 * @example
 * ```typescript
 * app.use(createExpressMiddleware(gate, { gateMutationsOnly: true }));
 * ```
 */
export function createExpressMiddleware(
  gate: Gate,
  options?: HttpMiddlewareOptions,
) {
  const middleware = new HttpKavachMiddleware(gate, options);

  return (req: any, res: any, next: any) => {
    if (!middleware.shouldGate(req.method, req.path)) {
      return next();
    }

    const verdict = middleware.evaluate({
      method: req.method,
      path: req.path,
      headers: req.headers,
      body: req.body,
      ip: req.ip,
    });

    if (verdict.isPermit) {
      return next();
    }

    if (verdict.isInvalidate) {
      return res.status(401).json({
        error: 'session_invalidated',
        reason: verdict.reason,
      });
    }

    return res.status(403).json({
      error: 'forbidden',
      code: verdict.code,
      reason: verdict.reason,
    });
  };
}

// ─── Fastify plugin factory ─────────────────────────────────────

/**
 * Create a Fastify onRequest hook that gates requests through Kavach.
 *
 * @example
 * ```typescript
 * fastify.addHook('onRequest', createFastifyHook(gate));
 * ```
 */
export function createFastifyHook(
  gate: Gate,
  options?: HttpMiddlewareOptions,
) {
  const middleware = new HttpKavachMiddleware(gate, options);

  return (request: any, reply: any, done: any) => {
    if (!middleware.shouldGate(request.method, request.url)) {
      return done();
    }

    const verdict = middleware.evaluate({
      method: request.method,
      path: request.url,
      headers: request.headers,
      body: request.body,
      ip: request.ip,
    });

    if (verdict.isPermit) {
      return done();
    }

    reply.code(verdict.isInvalidate ? 401 : 403).send({
      error: verdict.isInvalidate ? 'session_invalidated' : 'forbidden',
      code: verdict.code,
      reason: verdict.reason,
    });
  };
}
