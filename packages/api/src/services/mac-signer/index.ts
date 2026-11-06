/**
 * MAC signer client abstraction (ADR-0001 A4-M2 Phase 1).
 *
 * Phase 0 (PR #48) landed the signer-side `/v1/mac/{session,sign,verify}`
 * endpoints. Phase 1 wires this interface on the API side so animated-QR
 * session creation and frame verification can optionally run through the
 * signer in *shadow* alongside the existing local HKDF derivation.
 *
 * Phase 1 semantics:
 *   - `MAC_BACKEND=local`  → NoopMacSignerClient. No RPC traffic. Existing
 *                            local-derivation path is the only one exercised.
 *   - `MAC_BACKEND=dual`   → HttpMacSignerClient. Local remains authoritative
 *                            for response; signer calls run fire-and-forget
 *                            and feed the divergence comparator.
 *   - `MAC_BACKEND=signer` → HttpMacSignerClient (Phase 2+). Code path exists
 *                            but not exercised in production during Phase 1.
 *
 * Result contract:
 *   `ok: true` means the RPC completed with a parseable response. `{ valid:
 *   false }` on verify or `{ ok: false, reason: 'session_not_found' }` on
 *   sign are both "completed" outcomes — the signer answered cleanly. Only
 *   transport / circuit-breaker / malformed conditions yield `{ ok: false }`
 *   with a transport-flavoured reason.
 */

export interface RegisterSessionInput {
  sessionId: string;
  binding: string;
  ttlSeconds: number;
}

export interface SignInput {
  sessionId: string;
  payload: Buffer;
}

export interface VerifyInput {
  sessionId: string;
  payload: Buffer;
  tag: string;
}

export type MacClientError =
  | 'timeout'
  | 'network'
  | 'server_5xx'
  | 'session_not_found'
  | 'session_exists'
  | 'registry_full'
  | 'circuit_open'
  | 'malformed';

export type MacClientResult<T> =
  | ({ ok: true } & T)
  | { ok: false; reason: MacClientError };

export type RegisterSessionResult = MacClientResult<{ expiresAtUnix: number }>;
export type SignResult = MacClientResult<{ tag: string }>;
export type VerifyResult = MacClientResult<{ valid: boolean }>;

export interface MacSignerClient {
  /**
   * Register a new animated-QR session with the signer. Idempotent on the
   * (sessionId, binding, ttlSeconds) tuple — a replay with the same inputs
   * returns the same `expiresAtUnix`. Mismatched binding yields
   * `session_exists`. Registry full yields `registry_full`.
   */
  registerSession(input: RegisterSessionInput): Promise<RegisterSessionResult>;

  /**
   * Compute an 8-byte compact HMAC tag (16 hex chars) for the payload under
   * the session's signer-held key. `session_not_found` is terminal and never
   * retried — the session expired or was never registered.
   */
  sign(input: SignInput): Promise<SignResult>;

  /**
   * Constant-time verify a supplied tag. `{ valid: false }` is an OK
   * response, not a transport failure — the signer answered cleanly.
   */
  verify(input: VerifyInput): Promise<VerifyResult>;
}

export { NoopMacSignerClient } from './noop.js';
export { HttpMacSignerClient } from './http.js';
export type { HttpMacSignerClientOptions } from './http.js';
export {
  createCircuitBreaker,
  type CircuitBreaker,
  type CircuitBreakerOptions,
  type CircuitBreakerState,
} from './circuit-breaker.js';
export {
  createMacSignerStatsCollector,
  type MacSignerStats,
  type MacSignerStatsCollector,
} from './stats.js';
