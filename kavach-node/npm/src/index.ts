/**
 * Kavach कवच — Post-quantum execution boundary enforcement.
 *
 * All gate evaluation runs in compiled Rust via the native addon.
 * This package provides idiomatic TypeScript wrappers and middleware.
 *
 * @example
 * ```typescript
 * import { Gate } from 'kavach';
 *
 * const gate = Gate.fromFile('kavach.toml');
 * const verdict = gate.evaluate({
 *   principalId: 'agent-bot',
 *   principalKind: 'agent',
 *   actionName: 'issue_refund',
 *   params: { amount: 500 },
 * });
 *
 * if (verdict.isPermit) {
 *   // proceed
 * }
 * ```
 */

// Import the compiled Rust engine
import {
  AuditEntry,
  DirectoryTokenVerifier,
  KavachGate,
  KavachKeyPair,
  PqTokenSigner,
  PublicKeyDirectory,
  SecureChannel,
  SignedAuditChain,
  type ActionContextInput,
  type AuditEntryOptions,
  type GeoLocationInput,
  type PermitTokenInput,
  type PermitTokenView,
  type PublicKeyBundleView,
  type VerdictResult,
} from 'kavach-engine';
import { readFileSync } from 'fs';

// ─── Public types ────────────────────────────────────────────────

export type PrincipalKind = 'user' | 'agent' | 'service' | 'scheduler' | 'external';

export interface EvaluateOptions {
  principalId: string;
  principalKind: PrincipalKind;
  actionName: string;
  roles?: string[];
  resource?: string;
  params?: Record<string, number>;
  ip?: string;
  sessionId?: string;
  /**
   * Current geographic location (→ `EnvContext.geo`). Pair with
   * `originGeo` and a tolerant-mode `GeoLocationDrift` evaluator
   * (`max_distance_km` set) to downgrade same-country IP hops from
   * Violation to Warning.
   */
  currentGeo?: GeoLocationInput;
  /**
   * Geographic location captured at session start
   * (→ `SessionState.origin_geo`). Needed alongside `currentGeo` for
   * tolerant-mode `GeoLocationDrift`.
   */
  originGeo?: GeoLocationInput;
}

export interface Invariant {
  name: string;
  field: string;
  maxValue: number;
}

export interface GateOptions {
  invariants?: Invariant[];
  observeOnly?: boolean;
  maxSessionActions?: number;
  enableDrift?: boolean;
  /**
   * Optional `PqTokenSigner`. When set, every Permit verdict carries a
   * signed envelope on `verdict.signature` / `verdict.permitToken.signature`.
   * Sign failures fail closed (Refuse).
   */
  tokenSigner?: PqTokenSigner;
  /**
   * Tolerance (km) for `GeoLocationDrift`. When unset, any mid-session
   * IP change is a Violation. When set, an IP change within this distance
   * downgrades to a Warning — but only when both `currentGeo` and
   * `originGeo` carry latitude/longitude. Missing geo with a threshold
   * set fails closed (Violation).
   */
  geoDriftMaxKm?: number;
}

export { VerdictResult as Verdict };
export {
  PqTokenSigner,
  KavachKeyPair,
  AuditEntry,
  SignedAuditChain,
  SecureChannel,
  PublicKeyDirectory,
  DirectoryTokenVerifier,
};
export type {
  AuditEntryOptions,
  GeoLocationInput,
  PermitTokenInput,
  PermitTokenView,
  PublicKeyBundleView,
};

// ─── Gate ────────────────────────────────────────────────────────

/**
 * Kavach execution gate. All evaluation runs in compiled Rust.
 */
export class Gate {
  private engine: KavachGate;

  private constructor(engine: KavachGate) {
    this.engine = engine;
  }

  /**
   * Create a gate from a TOML policy string.
   */
  static fromToml(policyToml: string, options: GateOptions = {}): Gate {
    const engine = new KavachGate(
      policyToml,
      options.invariants?.map(i => ({
        name: i.name,
        field: i.field,
        maxValue: i.maxValue,
      })),
      options.observeOnly,
      options.maxSessionActions,
      options.enableDrift,
      options.tokenSigner,
      options.geoDriftMaxKm,
    );
    return new Gate(engine);
  }

  /**
   * Create a gate from a TOML policy file.
   */
  static fromFile(path: string, options: GateOptions = {}): Gate {
    const content = readFileSync(path, 'utf-8');
    return Gate.fromToml(content, options);
  }

  /**
   * Evaluate an action context. Returns a Verdict.
   *
   * All evaluation logic (policy, drift, invariants) runs in Rust.
   */
  /**
   * Hot-reload the policy set from a fresh TOML string.
   *
   * Throws on parse errors; the previous good set stays in place.
   * Empty TOML is valid (= default-deny everything).
   */
  reload(policyToml: string): void {
    this.engine.reload(policyToml);
  }

  evaluate(opts: EvaluateOptions): VerdictResult {
    const ctx: ActionContextInput = {
      principalId: opts.principalId,
      principalKind: opts.principalKind,
      actionName: opts.actionName,
      roles: opts.roles ?? [],
      resource: opts.resource ?? undefined,
      params: opts.params ?? undefined,
      ip: opts.ip ?? undefined,
      sessionId: opts.sessionId ?? undefined,
      currentGeo: opts.currentGeo ?? undefined,
      originGeo: opts.originGeo ?? undefined,
    };
    return this.engine.evaluate(ctx);
  }

  /**
   * Evaluate and throw if not permitted.
   */
  check(opts: EvaluateOptions): void {
    const verdict = this.evaluate(opts);
    if (verdict.isRefuse) {
      throw new KavachRefused(verdict.reason!, verdict.evaluator!, verdict.code!);
    }
    if (verdict.isInvalidate) {
      throw new KavachInvalidated(verdict.reason!, verdict.evaluator!);
    }
  }

  get evaluatorCount(): number {
    return this.engine.evaluatorCount;
  }
}

// ─── Errors ──────────────────────────────────────────────────────

export class KavachRefused extends Error {
  constructor(
    public readonly reason: string,
    public readonly evaluator: string,
    public readonly code: string,
  ) {
    super(`[${code}] ${evaluator}: ${reason}`);
    this.name = 'KavachRefused';
  }
}

export class KavachInvalidated extends Error {
  constructor(
    public readonly reason: string,
    public readonly evaluator: string,
  ) {
    super(`session invalidated by ${evaluator}: ${reason}`);
    this.name = 'KavachInvalidated';
  }
}

// ─── Re-exports — middleware helpers ─────────────────────────────

export { McpKavachMiddleware, type McpCallerInfo } from './mcp';
export {
  HttpKavachMiddleware,
  type HttpMiddlewareOptions,
  deriveActionName,
  createExpressMiddleware,
  createFastifyHook,
} from './http';
