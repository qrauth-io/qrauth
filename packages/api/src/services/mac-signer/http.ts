import { z } from 'zod';
import type {
  MacClientError,
  MacSignerClient,
  RegisterSessionInput,
  RegisterSessionResult,
  SignInput,
  SignResult,
  VerifyInput,
  VerifyResult,
} from './index.js';
import type { CircuitBreaker } from './circuit-breaker.js';
import type { MacSignerStatsCollector } from './stats.js';

/**
 * HTTP MAC signer client (ADR-0001 A4-M2 Phase 1).
 *
 * Talks to the signer service's `/v1/mac/{session,sign,verify}` endpoints.
 * Resilience envelope (ADR §Resilience Requirements):
 *   - Per-attempt deadline `deadlineMsPerAttempt` (default 50ms) enforced
 *     via AbortController.
 *   - Up to `maxRetries` retries on timeout / network / 5xx. 4xx is
 *     terminal and never retried.
 *   - Full-jitter backoff between retries: `random(0, seed * 2^attempt)`.
 *   - Overall call budget hard-ceilinged at `overallBudgetMs` (default
 *     200ms). Exceeding it aborts the retry loop with `timeout`.
 *   - Circuit breaker: `tryAcquire` before dispatch. On `false`, returns
 *     `circuit_open` without touching the network. Transport failures
 *     (timeout/network/server_5xx) are `recordFailure`; 4xx and 2xx are
 *     `recordSuccess` — a 4xx means the signer is up and answering, it's
 *     the request payload that's wrong.
 *   - Dual-token fallback: a 401 with the primary bearer retries exactly
 *     once with the rotation token (if configured). Mirrors H-5.
 */

export interface HttpMacSignerClientOptions {
  baseUrl: string;
  token: string;
  tokenNext?: string;
  deadlineMsPerAttempt?: number;
  maxRetries?: number;
  overallBudgetMs?: number;
  backoffSeedMs?: number;
  circuit: CircuitBreaker;
  stats: MacSignerStatsCollector;
  now?: () => number;
  /** Injectable for deterministic tests. */
  random?: () => number;
  /** Injectable for deterministic tests. */
  sleep?: (ms: number) => Promise<void>;
  /** Injectable for tests. Defaults to global fetch. */
  fetchImpl?: typeof fetch;
  logger?: {
    warn: (obj: unknown, msg: string) => void;
    error: (obj: unknown, msg: string) => void;
  };
}

const registerResponseSchema = z.object({
  registered: z.literal(true),
  expiresAt: z.number().int().positive(),
});

const signResponseSchema = z.object({
  tag: z.string().regex(/^[0-9a-f]{16}$/),
});

const verifyResponseSchema = z.object({
  valid: z.boolean(),
});

type RetryableReason = Extract<MacClientError, 'timeout' | 'network' | 'server_5xx'>;

export class HttpMacSignerClient implements MacSignerClient {
  private readonly baseUrl: string;
  private readonly token: string;
  private readonly tokenNext: string | undefined;
  private readonly deadlineMsPerAttempt: number;
  private readonly maxRetries: number;
  private readonly overallBudgetMs: number;
  private readonly backoffSeedMs: number;
  private readonly circuit: CircuitBreaker;
  private readonly stats: MacSignerStatsCollector;
  private readonly now: () => number;
  private readonly random: () => number;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly fetchImpl: typeof fetch;
  private readonly logger: HttpMacSignerClientOptions['logger'];

  constructor(opts: HttpMacSignerClientOptions) {
    if (!opts.baseUrl) throw new Error('HttpMacSignerClient: baseUrl is required');
    if (!opts.token) throw new Error('HttpMacSignerClient: bearer token is required');
    this.baseUrl = opts.baseUrl.replace(/\/+$/, '');
    this.token = opts.token;
    this.tokenNext = opts.tokenNext;
    this.deadlineMsPerAttempt = opts.deadlineMsPerAttempt ?? 50;
    this.maxRetries = opts.maxRetries ?? 2;
    this.overallBudgetMs = opts.overallBudgetMs ?? 200;
    this.backoffSeedMs = opts.backoffSeedMs ?? 10;
    this.circuit = opts.circuit;
    this.stats = opts.stats;
    this.now = opts.now ?? (() => Date.now());
    this.random = opts.random ?? Math.random;
    this.sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.logger = opts.logger;
  }

  async registerSession(input: RegisterSessionInput): Promise<RegisterSessionResult> {
    const body = {
      sessionId: input.sessionId,
      binding: input.binding,
      ttlSeconds: input.ttlSeconds,
    };
    const res = await this.callEndpoint('/v1/mac/session', body);
    if (!res.ok) return { ok: false, reason: res.reason };
    const parsed = registerResponseSchema.safeParse(res.body);
    if (!parsed.success) return { ok: false, reason: 'malformed' };
    return { ok: true, expiresAtUnix: parsed.data.expiresAt };
  }

  async sign(input: SignInput): Promise<SignResult> {
    const body = {
      sessionId: input.sessionId,
      payload: input.payload.toString('base64'),
    };
    const res = await this.callEndpoint('/v1/mac/sign', body);
    if (!res.ok) return { ok: false, reason: res.reason };
    const parsed = signResponseSchema.safeParse(res.body);
    if (!parsed.success) return { ok: false, reason: 'malformed' };
    return { ok: true, tag: parsed.data.tag };
  }

  async verify(input: VerifyInput): Promise<VerifyResult> {
    const body = {
      sessionId: input.sessionId,
      payload: input.payload.toString('base64'),
      tag: input.tag,
    };
    const res = await this.callEndpoint('/v1/mac/verify', body);
    if (!res.ok) return { ok: false, reason: res.reason };
    const parsed = verifyResponseSchema.safeParse(res.body);
    if (!parsed.success) return { ok: false, reason: 'malformed' };
    return { ok: true, valid: parsed.data.valid };
  }

  /**
   * Dispatch a POST with retry / circuit-breaker / overall-budget logic.
   * Returns either `{ ok: true, body }` (2xx + JSON parsed) or
   * `{ ok: false, reason }` (mapped terminal reason). The caller applies
   * the zod schema for the endpoint-specific response shape.
   */
  private async callEndpoint(
    path: string,
    body: unknown,
  ): Promise<{ ok: true; body: unknown } | { ok: false; reason: MacClientError }> {
    if (!this.circuit.tryAcquire()) {
      return { ok: false, reason: 'circuit_open' };
    }

    const start = this.now();
    let attempt = 0;
    let triedTokenNext = false;

    while (true) {
      const elapsed = this.now() - start;
      const remainingBudget = this.overallBudgetMs - elapsed;
      if (remainingBudget <= 0) {
        this.circuit.recordFailure();
        return { ok: false, reason: 'timeout' };
      }
      const attemptDeadline = Math.min(this.deadlineMsPerAttempt, remainingBudget);

      const attemptStart = this.now();
      const outcome = await this.singleAttempt(
        path,
        body,
        attemptDeadline,
        triedTokenNext ? this.tokenNext ?? this.token : this.token,
      );
      this.stats.recordRpcDurationMs(Math.max(1, this.now() - attemptStart));

      if (outcome.kind === 'ok') {
        this.circuit.recordSuccess();
        return { ok: true, body: outcome.body };
      }

      if (outcome.kind === 'terminal_4xx') {
        // 4xx proves the signer is reachable — don't feed the breaker.
        this.circuit.recordSuccess();
        return { ok: false, reason: outcome.reason };
      }

      if (outcome.kind === 'auth_fail' && this.tokenNext && !triedTokenNext) {
        // Dual-token: try rotation key exactly once, no backoff. Don't
        // feed the breaker — the signer answered.
        triedTokenNext = true;
        this.logger?.warn(
          { path },
          'MAC signer primary token rejected — retrying with SIGNER_MAC_TOKEN_NEXT',
        );
        continue;
      }

      if (outcome.kind === 'auth_fail') {
        // No rotation token or already tried — fold to malformed (bad config).
        this.circuit.recordSuccess();
        return { ok: false, reason: 'malformed' };
      }

      // Retryable: timeout / network / server_5xx.
      if (attempt >= this.maxRetries) {
        // Only credit the breaker once per call, after the retry budget
        // is exhausted. Per-attempt failure accounting would trip the
        // breaker on single transient bursts.
        this.circuit.recordFailure();
        return { ok: false, reason: outcome.reason };
      }

      const backoff = this.random() * this.backoffSeedMs * Math.pow(2, attempt);
      const elapsedBeforeSleep = this.now() - start;
      const remainingBeforeSleep = this.overallBudgetMs - elapsedBeforeSleep;
      if (backoff >= remainingBeforeSleep) {
        this.circuit.recordFailure();
        return { ok: false, reason: 'timeout' };
      }
      if (backoff > 0) await this.sleep(backoff);
      attempt += 1;
    }
  }

  private async singleAttempt(
    path: string,
    body: unknown,
    deadlineMs: number,
    bearer: string,
  ): Promise<
    | { kind: 'ok'; body: unknown }
    | { kind: 'terminal_4xx'; reason: Extract<MacClientError, 'session_not_found' | 'session_exists' | 'registry_full' | 'malformed'> }
    | { kind: 'auth_fail' }
    | { kind: 'retryable'; reason: RetryableReason }
  > {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), deadlineMs);

    let res: Response;
    try {
      res = await this.fetchImpl(`${this.baseUrl}${path}`, {
        method: 'POST',
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${bearer}`,
        },
        body: JSON.stringify(body),
      });
    } catch (err) {
      clearTimeout(timer);
      const isAbort =
        (err instanceof Error && err.name === 'AbortError') ||
        (typeof err === 'object' && err !== null && 'name' in err && (err as { name: string }).name === 'AbortError');
      return { kind: 'retryable', reason: isAbort ? 'timeout' : 'network' };
    }
    clearTimeout(timer);

    if (res.status >= 200 && res.status < 300) {
      try {
        const json = await res.json();
        return { kind: 'ok', body: json };
      } catch {
        return { kind: 'terminal_4xx', reason: 'malformed' };
      }
    }

    if (res.status === 401) {
      // Drain body so fetch doesn't leak sockets; ignore parse errors.
      try {
        await res.json();
      } catch {
        /* ignore */
      }
      return { kind: 'auth_fail' };
    }

    if (res.status >= 400 && res.status < 500) {
      try {
        await res.json();
      } catch {
        /* empty body is fine */
      }
      if (res.status === 404) {
        // Both sign (session_not_found) and verify (session_expired) return
        // 404. Collapse to the single transport-level reason — the
        // consumer (shadow comparator) doesn't distinguish.
        return { kind: 'terminal_4xx', reason: 'session_not_found' };
      }
      if (res.status === 409) return { kind: 'terminal_4xx', reason: 'session_exists' };
      // Any other 4xx (including 400 malformed_request) → malformed.
      return { kind: 'terminal_4xx', reason: 'malformed' };
    }

    // 5xx — terminal vs. retryable is decided by the error enum in the
    // body, not by the URL path. If the signer says `registry_full`, the
    // session registry is at capacity and more load won't help — don't
    // retry. Anything else (including an empty body) is genuine
    // unavailability and is eligible for retry under the normal envelope.
    if (res.status === 503) {
      let parsed: { error?: string } = {};
      try {
        parsed = (await res.json()) as { error?: string };
      } catch {
        /* ignore — empty/non-JSON body falls through to retryable */
      }
      if (parsed?.error === 'registry_full') {
        return { kind: 'terminal_4xx', reason: 'registry_full' };
      }
      return { kind: 'retryable', reason: 'server_5xx' };
    }

    // Any other 5xx — retryable.
    try {
      await res.json();
    } catch {
      /* ignore */
    }
    return { kind: 'retryable', reason: 'server_5xx' };
  }
}
