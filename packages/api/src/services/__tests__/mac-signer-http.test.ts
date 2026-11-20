import { describe, it, expect, vi, beforeEach } from 'vitest';
import { HttpMacSignerClient } from '../mac-signer/http.js';
import { createCircuitBreaker } from '../mac-signer/circuit-breaker.js';
import { createMacSignerStatsCollector } from '../mac-signer/stats.js';

/**
 * Unit tests for HttpMacSignerClient (ADR-0001 A4-M2 Phase 1).
 *
 * Uses a mock `fetch` plus injected `now`/`random`/`sleep` so every
 * timing-sensitive path is deterministic. No real network I/O.
 */

const BASE = 'https://signer.test';
const TOKEN = 'primary-token';
const TOKEN_NEXT = 'rotation-token';

function makeClock(start = 0) {
  let t = start;
  return {
    now: () => t,
    advance: (ms: number) => {
      t += ms;
    },
  };
}

function makeClient(opts: {
  fetchImpl: typeof fetch;
  now: () => number;
  tokenNext?: string;
  maxRetries?: number;
  deadlineMsPerAttempt?: number;
  overallBudgetMs?: number;
}) {
  const circuit = createCircuitBreaker({
    failureThreshold: 5,
    windowMs: 10_000,
    halfOpenProbeIntervalMs: 5_000,
    now: opts.now,
  });
  const stats = createMacSignerStatsCollector({ backend: 'dual', circuit });
  const client = new HttpMacSignerClient({
    baseUrl: BASE,
    token: TOKEN,
    tokenNext: opts.tokenNext,
    circuit,
    stats,
    fetchImpl: opts.fetchImpl,
    now: opts.now,
    random: () => 0, // no jitter — backoffs run as 0ms
    sleep: async () => undefined,
    maxRetries: opts.maxRetries ?? 2,
    deadlineMsPerAttempt: opts.deadlineMsPerAttempt ?? 50,
    overallBudgetMs: opts.overallBudgetMs ?? 200,
  });
  return { client, circuit, stats };
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

describe('HttpMacSignerClient — happy paths', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('registerSession returns parsed expiresAtUnix; sets bearer header', async () => {
    const clock = makeClock();
    const fetchImpl = vi.fn(async (url: string, init: RequestInit) => {
      expect(url).toBe(`${BASE}/v1/mac/session`);
      expect(init.method).toBe('POST');
      const headers = init.headers as Record<string, string>;
      expect(headers.Authorization).toBe(`Bearer ${TOKEN}`);
      expect(headers['Content-Type']).toBe('application/json');
      const body = JSON.parse(init.body as string);
      expect(body).toEqual({
        sessionId: 'abc',
        binding: 'authSession:abc',
        ttlSeconds: 300,
      });
      return jsonResponse(200, { registered: true, expiresAt: 1700000300 });
    });
    const { client } = makeClient({ fetchImpl: fetchImpl as typeof fetch, now: clock.now });
    const res = await client.registerSession({
      sessionId: 'abc',
      binding: 'authSession:abc',
      ttlSeconds: 300,
    });
    expect(res).toEqual({ ok: true, expiresAtUnix: 1700000300 });
  });

  it('sign returns the tag on 200', async () => {
    const clock = makeClock();
    const fetchImpl = vi.fn(async () =>
      jsonResponse(200, { tag: '0123456789abcdef' }),
    );
    const { client } = makeClient({ fetchImpl: fetchImpl as typeof fetch, now: clock.now });
    const res = await client.sign({ sessionId: 's', payload: Buffer.from('hi') });
    expect(res).toEqual({ ok: true, tag: '0123456789abcdef' });
  });

  it('verify returns valid: false cleanly (not a transport failure)', async () => {
    const clock = makeClock();
    const fetchImpl = vi.fn(async () => jsonResponse(200, { valid: false }));
    const { client } = makeClient({ fetchImpl: fetchImpl as typeof fetch, now: clock.now });
    const res = await client.verify({
      sessionId: 's',
      payload: Buffer.from('hi'),
      tag: '0123456789abcdef',
    });
    expect(res).toEqual({ ok: true, valid: false });
  });
});

describe('HttpMacSignerClient — terminal 4xx', () => {
  it('404 on sign → session_not_found, no retry', async () => {
    const clock = makeClock();
    const fetchImpl = vi.fn(async () =>
      jsonResponse(404, { error: 'session_not_found' }),
    );
    const { client } = makeClient({ fetchImpl: fetchImpl as typeof fetch, now: clock.now });
    const res = await client.sign({ sessionId: 's', payload: Buffer.from('hi') });
    expect(res).toEqual({ ok: false, reason: 'session_not_found' });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('409 on session → session_exists, no retry', async () => {
    const clock = makeClock();
    const fetchImpl = vi.fn(async () =>
      jsonResponse(409, { error: 'session_exists' }),
    );
    const { client } = makeClient({ fetchImpl: fetchImpl as typeof fetch, now: clock.now });
    const res = await client.registerSession({
      sessionId: 's',
      binding: 'b',
      ttlSeconds: 300,
    });
    expect(res).toEqual({ ok: false, reason: 'session_exists' });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('503 with { error: "registry_full" } on /session → terminal, zero retries', async () => {
    const clock = makeClock();
    const fetchImpl = vi.fn(async () =>
      jsonResponse(503, { error: 'registry_full' }),
    );
    const { client } = makeClient({ fetchImpl: fetchImpl as typeof fetch, now: clock.now });
    const res = await client.registerSession({
      sessionId: 's',
      binding: 'b',
      ttlSeconds: 300,
    });
    expect(res).toEqual({ ok: false, reason: 'registry_full' });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('503 with { error: "upstream_unavailable" } on /session → retries, final server_5xx', async () => {
    const clock = makeClock();
    const fetchImpl = vi.fn(async () =>
      jsonResponse(503, { error: 'upstream_unavailable' }),
    );
    const { client } = makeClient({
      fetchImpl: fetchImpl as typeof fetch,
      now: clock.now,
      maxRetries: 2,
    });
    const res = await client.registerSession({
      sessionId: 's',
      binding: 'b',
      ttlSeconds: 300,
    });
    expect(res).toEqual({ ok: false, reason: 'server_5xx' });
    expect(fetchImpl).toHaveBeenCalledTimes(3);
  });

  it('503 with empty body on any endpoint → retries, final server_5xx', async () => {
    const clock = makeClock();
    const fetchImpl = vi.fn(async () => new Response('', { status: 503 }));
    const { client } = makeClient({
      fetchImpl: fetchImpl as typeof fetch,
      now: clock.now,
      maxRetries: 2,
    });
    const res = await client.sign({ sessionId: 's', payload: Buffer.from('hi') });
    expect(res).toEqual({ ok: false, reason: 'server_5xx' });
    expect(fetchImpl).toHaveBeenCalledTimes(3);
  });

  it('503 with { error: "registry_full" } on /sign (hypothetical future) → terminal, zero retries', async () => {
    // Encodes the "body, not URL path" rule. If the signer ever adds a
    // capacity-bound sign endpoint the client must already handle it
    // without touching this file.
    const clock = makeClock();
    const fetchImpl = vi.fn(async () =>
      jsonResponse(503, { error: 'registry_full' }),
    );
    const { client } = makeClient({
      fetchImpl: fetchImpl as typeof fetch,
      now: clock.now,
      maxRetries: 2,
    });
    const res = await client.sign({ sessionId: 's', payload: Buffer.from('hi') });
    expect(res).toEqual({ ok: false, reason: 'registry_full' });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('400 on any endpoint → malformed', async () => {
    const clock = makeClock();
    const fetchImpl = vi.fn(async () =>
      jsonResponse(400, { error: 'malformed_request' }),
    );
    const { client } = makeClient({ fetchImpl: fetchImpl as typeof fetch, now: clock.now });
    const res = await client.sign({ sessionId: '', payload: Buffer.from('') });
    expect(res).toEqual({ ok: false, reason: 'malformed' });
  });

  it('2xx with a body that fails the zod schema → malformed', async () => {
    const clock = makeClock();
    const fetchImpl = vi.fn(async () => jsonResponse(200, { foo: 'bar' }));
    const { client } = makeClient({ fetchImpl: fetchImpl as typeof fetch, now: clock.now });
    const res = await client.sign({ sessionId: 's', payload: Buffer.from('hi') });
    expect(res).toEqual({ ok: false, reason: 'malformed' });
  });
});

describe('HttpMacSignerClient — retry / deadline / budget', () => {
  it('times out the per-attempt call via AbortController at the deadline', async () => {
    const clock = makeClock();
    // A fetch that never resolves, but respects the abort signal.
    const fetchImpl = vi.fn(async (_url: string, init: RequestInit) => {
      return new Promise<Response>((_resolve, reject) => {
        const signal = init.signal as AbortSignal;
        signal.addEventListener('abort', () => {
          const err = new Error('aborted');
          err.name = 'AbortError';
          reject(err);
        });
      });
    });
    const { client } = makeClient({
      fetchImpl: fetchImpl as typeof fetch,
      now: clock.now,
      maxRetries: 0,
      deadlineMsPerAttempt: 50,
      overallBudgetMs: 60,
    });
    const res = await client.sign({ sessionId: 's', payload: Buffer.from('hi') });
    expect(res).toEqual({ ok: false, reason: 'timeout' });
  });

  it('retries 5xx up to maxRetries and then returns server_5xx', async () => {
    const clock = makeClock();
    const fetchImpl = vi.fn(async () => new Response('boom', { status: 500 }));
    const { client } = makeClient({
      fetchImpl: fetchImpl as typeof fetch,
      now: clock.now,
      maxRetries: 2,
    });
    const res = await client.sign({ sessionId: 's', payload: Buffer.from('hi') });
    expect(res).toEqual({ ok: false, reason: 'server_5xx' });
    expect(fetchImpl).toHaveBeenCalledTimes(3); // 1 + 2 retries
  });

  it('succeeds on the 3rd attempt after two 5xx responses', async () => {
    const clock = makeClock();
    let call = 0;
    const fetchImpl = vi.fn(async () => {
      call += 1;
      if (call <= 2) return new Response('boom', { status: 500 });
      return jsonResponse(200, { tag: 'aaaaaaaaaaaaaaaa' });
    });
    const { client } = makeClient({
      fetchImpl: fetchImpl as typeof fetch,
      now: clock.now,
      maxRetries: 2,
    });
    const res = await client.sign({ sessionId: 's', payload: Buffer.from('hi') });
    expect(res).toEqual({ ok: true, tag: 'aaaaaaaaaaaaaaaa' });
    expect(fetchImpl).toHaveBeenCalledTimes(3);
  });

  it('does NOT retry 4xx responses', async () => {
    const clock = makeClock();
    const fetchImpl = vi.fn(async () =>
      jsonResponse(404, { error: 'session_not_found' }),
    );
    const { client } = makeClient({
      fetchImpl: fetchImpl as typeof fetch,
      now: clock.now,
      maxRetries: 5,
    });
    const res = await client.sign({ sessionId: 's', payload: Buffer.from('hi') });
    expect(res).toEqual({ ok: false, reason: 'session_not_found' });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });
});

describe('HttpMacSignerClient — dual-token fallback (H-5)', () => {
  it('retries once with SIGNER_MAC_TOKEN_NEXT when the primary returns 401', async () => {
    const clock = makeClock();
    const seenBearers: string[] = [];
    const fetchImpl = vi.fn(async (_url: string, init: RequestInit) => {
      const auth = (init.headers as Record<string, string>).Authorization;
      seenBearers.push(auth);
      if (auth === `Bearer ${TOKEN}`) {
        return jsonResponse(401, { error: 'unauthorized' });
      }
      return jsonResponse(200, { tag: 'abababababababab' });
    });
    const { client } = makeClient({
      fetchImpl: fetchImpl as typeof fetch,
      now: clock.now,
      tokenNext: TOKEN_NEXT,
    });
    const res = await client.sign({ sessionId: 's', payload: Buffer.from('hi') });
    expect(res).toEqual({ ok: true, tag: 'abababababababab' });
    expect(seenBearers).toEqual([`Bearer ${TOKEN}`, `Bearer ${TOKEN_NEXT}`]);
  });

  it('with no rotation token, 401 collapses to malformed (misconfig)', async () => {
    const clock = makeClock();
    const fetchImpl = vi.fn(async () =>
      jsonResponse(401, { error: 'unauthorized' }),
    );
    const { client } = makeClient({
      fetchImpl: fetchImpl as typeof fetch,
      now: clock.now,
    });
    const res = await client.sign({ sessionId: 's', payload: Buffer.from('hi') });
    expect(res).toEqual({ ok: false, reason: 'malformed' });
  });
});

describe('HttpMacSignerClient — circuit breaker integration', () => {
  it('circuit_open short-circuits before any fetch', async () => {
    const clock = makeClock();
    // Pre-trip the breaker by sharing one across two clients? Simpler:
    // build the client, force-trip the breaker via failures, then call.
    const fetchImpl500 = vi.fn(async () => new Response('', { status: 500 }));
    const { client, circuit } = makeClient({
      fetchImpl: fetchImpl500 as typeof fetch,
      now: clock.now,
      maxRetries: 0,
    });
    // 5 consecutive failed calls to trip.
    for (let i = 0; i < 5; i++) {
      await client.sign({ sessionId: 's', payload: Buffer.from('hi') });
    }
    expect(circuit.state()).toBe('open');
    const callsBefore = fetchImpl500.mock.calls.length;
    const res = await client.sign({ sessionId: 's', payload: Buffer.from('hi') });
    expect(res).toEqual({ ok: false, reason: 'circuit_open' });
    expect(fetchImpl500.mock.calls.length).toBe(callsBefore); // no new fetch
  });
});
