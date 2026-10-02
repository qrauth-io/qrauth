import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import type {
  MacSignerClient,
  RegisterSessionInput,
  RegisterSessionResult,
  SignInput,
  SignResult,
  VerifyInput,
  VerifyResult,
} from '../mac-signer/index.js';
import { createCircuitBreaker } from '../mac-signer/circuit-breaker.js';
import { createMacSignerStatsCollector } from '../mac-signer/stats.js';

/**
 * Dual-derive shadow comparator integration (ADR-0001 A4-M2 Phase 1).
 *
 * AnimatedQRService construction requires ANIMATED_QR_SECRET in the env,
 * so set it before the dynamic import.
 */

beforeAll(() => {
  process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
  process.env.REDIS_URL = 'redis://localhost:6379';
  process.env.JWT_SECRET = 'a'.repeat(32);
  process.env.ANIMATED_QR_SECRET = 'a'.repeat(64);
});

type CallLog = {
  register: RegisterSessionInput[];
  verify: VerifyInput[];
  sign: SignInput[];
};

function makeStubClient(fixtures: {
  registerResponses?: RegisterSessionResult[];
  verifyResponses?: VerifyResult[];
  signResponses?: SignResult[];
}): { client: MacSignerClient; calls: CallLog } {
  const calls: CallLog = { register: [], verify: [], sign: [] };
  const registerQueue = fixtures.registerResponses ?? [];
  const verifyQueue = fixtures.verifyResponses ?? [];
  const signQueue = fixtures.signResponses ?? [];
  const client: MacSignerClient = {
    async registerSession(input) {
      calls.register.push(input);
      return registerQueue.shift() ?? { ok: true, expiresAtUnix: 1700000000 };
    },
    async sign(input) {
      calls.sign.push(input);
      return signQueue.shift() ?? { ok: true, tag: '0000000000000000' };
    },
    async verify(input) {
      calls.verify.push(input);
      return verifyQueue.shift() ?? { ok: true, valid: true };
    },
  };
  return { client, calls };
}

// Flush queued setImmediate callbacks. `shadowVerify` schedules work via
// setImmediate; awaiting this ensures the stats side-effects have landed
// before the test reads them.
async function flushSetImmediate(): Promise<void> {
  await new Promise<void>((resolve) => setImmediate(resolve));
  // One more tick in case the signer call itself resolves on a microtask.
  await new Promise<void>((resolve) => setImmediate(resolve));
}

async function makeService(
  opts: {
    client: MacSignerClient;
    stats: ReturnType<typeof createMacSignerStatsCollector>;
    backend?: 'local' | 'dual' | 'signer';
    logger?: { warn: ReturnType<typeof vi.fn>; error: ReturnType<typeof vi.fn> };
  },
) {
  const mod = await import('../animated-qr.js');
  return new mod.AnimatedQRService({
    macSigner: opts.client,
    macSignerStats: opts.stats,
    backend: opts.backend ?? 'dual',
    logger: opts.logger ?? { warn: vi.fn(), error: vi.fn() },
  });
}

describe('AnimatedQRService — dual-derive shadow comparator', () => {
  let circuit: ReturnType<typeof createCircuitBreaker>;
  let stats: ReturnType<typeof createMacSignerStatsCollector>;

  beforeEach(() => {
    circuit = createCircuitBreaker({
      failureThreshold: 5,
      windowMs: 10_000,
      halfOpenProbeIntervalMs: 5_000,
    });
    stats = createMacSignerStatsCollector({ backend: 'dual', circuit });
  });

  it('binding derivation is stable and matches the pinned shape', async () => {
    // Grep-friendly: `authSession:<id>`. If this changes, the signer
    // registry view changes and Phase 2 flip becomes a hard cutover.
    const mod = await import('../animated-qr.js');
    expect(mod.AnimatedQRService.sessionBinding('abc-123')).toBe('authSession:abc-123');
    expect(mod.AnimatedQRService.sessionBinding('xyz')).toBe('authSession:xyz');
  });

  it('registerWithSigner calls registerSession with the pinned binding + clamped ttl', async () => {
    const { client, calls } = makeStubClient({});
    const svc = await makeService({ client, stats });
    await svc.registerWithSigner('sess-1', 300);
    expect(calls.register).toEqual([
      { sessionId: 'sess-1', binding: 'authSession:sess-1', ttlSeconds: 300 },
    ]);
    expect(stats.snapshot().register.ok).toBe(1);
  });

  it('registerWithSigner clamps TTL into the signer-allowed [60,3600] range', async () => {
    const { client, calls } = makeStubClient({});
    const svc = await makeService({ client, stats });
    await svc.registerWithSigner('short', 10);
    await svc.registerWithSigner('long', 9_999);
    expect(calls.register.map((c) => c.ttlSeconds)).toEqual([60, 3600]);
  });

  it('registerWithSigner is a no-op when backend=local', async () => {
    const { client, calls } = makeStubClient({});
    const svc = await makeService({ client, stats, backend: 'local' });
    await svc.registerWithSigner('x', 300);
    expect(calls.register).toHaveLength(0);
    expect(stats.snapshot().register.ok).toBe(0);
  });

  it('shadowVerify matching local+signer → frames_observed=1, divergence=0', async () => {
    const { client, calls } = makeStubClient({
      verifyResponses: [{ ok: true, valid: true }],
    });
    const svc = await makeService({ client, stats });
    svc.shadowVerify({
      sessionId: 's',
      baseUrl: 'https://qrauth.io/v/tok',
      frameIndex: 42,
      timestamp: 1_700_000_000_000,
      hmac: '0123456789abcdef',
      localValid: true,
    });
    await flushSetImmediate();
    expect(calls.verify).toHaveLength(1);
    expect(calls.verify[0].sessionId).toBe('s');
    expect(calls.verify[0].tag).toBe('0123456789abcdef');
    expect(calls.verify[0].payload.toString('utf8')).toBe(
      'https://qrauth.io/v/tok:1700000000000:42',
    );
    const s = stats.snapshot();
    expect(s.dual.frames_observed).toBe(1);
    expect(s.dual.divergence).toBe(0);
    expect(s.verify.ok_valid).toBe(1);
  });

  it('shadowVerify diverging local vs signer → divergence=1 and error log', async () => {
    const { client } = makeStubClient({
      verifyResponses: [{ ok: true, valid: false }],
    });
    const errorLog = vi.fn();
    const svc = await makeService({
      client,
      stats,
      logger: { warn: vi.fn(), error: errorLog },
    });
    svc.shadowVerify({
      sessionId: 's',
      baseUrl: 'https://qrauth.io/v/tok',
      frameIndex: 1,
      timestamp: 1_700_000_000_000,
      hmac: 'deadbeefdeadbeef',
      localValid: true, // local says valid, signer says invalid
    });
    await flushSetImmediate();
    const s = stats.snapshot();
    expect(s.dual.frames_observed).toBe(1);
    expect(s.dual.divergence).toBe(1);
    expect(errorLog).toHaveBeenCalledTimes(1);
    const [payload, msg] = errorLog.mock.calls[0];
    expect(msg).toBe('MAC divergence detected');
    expect(payload).toMatchObject({
      event: 'mac_divergence',
      sessionId: 's',
      localValid: true,
      signerValid: false,
      frameIndex: 1,
    });
  });

  it('shadowVerify with signer transport failure → transport counter, no dual/divergence change', async () => {
    const { client } = makeStubClient({
      verifyResponses: [{ ok: false, reason: 'timeout' }],
    });
    const svc = await makeService({ client, stats });
    svc.shadowVerify({
      sessionId: 's',
      baseUrl: 'https://qrauth.io/v/tok',
      frameIndex: 1,
      timestamp: 1_700_000_000_000,
      hmac: '0000000000000000',
      localValid: true,
    });
    await flushSetImmediate();
    const s = stats.snapshot();
    expect(s.dual.frames_observed).toBe(0);
    expect(s.dual.divergence).toBe(0);
    expect(s.verify.transport_failure).toBe(1);
  });

  it('shadowVerify with circuit_open → NOT counted as divergence', async () => {
    const { client } = makeStubClient({
      verifyResponses: [{ ok: false, reason: 'circuit_open' }],
    });
    const svc = await makeService({ client, stats });
    svc.shadowVerify({
      sessionId: 's',
      baseUrl: 'https://qrauth.io/v/tok',
      frameIndex: 1,
      timestamp: 1_700_000_000_000,
      hmac: '0000000000000000',
      localValid: false,
    });
    await flushSetImmediate();
    const s = stats.snapshot();
    expect(s.dual.frames_observed).toBe(0);
    expect(s.dual.divergence).toBe(0);
    expect(s.verify.transport_failure).toBe(1);
  });

  it('shadowVerify with session_expired on signer → counted as session_expired, not divergence', async () => {
    const { client } = makeStubClient({
      verifyResponses: [{ ok: false, reason: 'session_not_found' }],
    });
    const svc = await makeService({ client, stats });
    svc.shadowVerify({
      sessionId: 's',
      baseUrl: 'https://qrauth.io/v/tok',
      frameIndex: 1,
      timestamp: 1_700_000_000_000,
      hmac: '0000000000000000',
      localValid: true,
    });
    await flushSetImmediate();
    const s = stats.snapshot();
    expect(s.dual.frames_observed).toBe(0);
    expect(s.dual.divergence).toBe(0);
    expect(s.verify.session_expired).toBe(1);
  });

  it('shadowVerify is a no-op when backend=local', async () => {
    const { client, calls } = makeStubClient({});
    const svc = await makeService({ client, stats, backend: 'local' });
    svc.shadowVerify({
      sessionId: 's',
      baseUrl: 'https://qrauth.io/v/tok',
      frameIndex: 1,
      timestamp: 1_700_000_000_000,
      hmac: '0000000000000000',
      localValid: true,
    });
    await flushSetImmediate();
    expect(calls.verify).toHaveLength(0);
  });
});

// ===========================================================================
// ADR-0001 A4-M2 Phase 2 — signer-authoritative paths
// ===========================================================================

describe('AnimatedQRService — signer-authoritative (Phase 2)', () => {
  let circuit: ReturnType<typeof createCircuitBreaker>;
  let stats: ReturnType<typeof createMacSignerStatsCollector>;
  const NOW = 1_700_000_000_000;

  beforeEach(() => {
    circuit = createCircuitBreaker({
      failureThreshold: 5,
      windowMs: 10_000,
      halfOpenProbeIntervalMs: 5_000,
    });
    stats = createMacSignerStatsCollector({ backend: 'signer', circuit });
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
  });

  // ---------------------------------------------------------------------
  // signerVerifyFrame
  // ---------------------------------------------------------------------

  it('signerVerifyFrame returns signer result when signer responds ok+valid', async () => {
    const { client, calls } = makeStubClient({
      verifyResponses: [{ ok: true, valid: true }],
    });
    const svc = await makeService({ client, stats, backend: 'signer' });
    const result = await svc.signerVerifyFrame(
      'https://qrauth.io/v/tok',
      42,
      NOW,
      '0123456789abcdef',
      'sess-1',
    );
    expect(result).toEqual({ valid: true, reason: undefined, source: 'signer' });
    expect(calls.verify).toHaveLength(1);
    expect(calls.verify[0].sessionId).toBe('sess-1');
    expect(calls.verify[0].payload.toString('utf8')).toBe(
      'https://qrauth.io/v/tok:1700000000000:42',
    );
    const s = stats.snapshot();
    expect(s.signer_verify.primary_ok).toBe(1);
    expect(s.signer_verify.hard_fail).toBe(0);
    expect(s.verify.ok_valid).toBe(1);
  });

  it('signerVerifyFrame returns signer result when signer responds ok+invalid', async () => {
    const { client } = makeStubClient({
      verifyResponses: [{ ok: true, valid: false }],
    });
    const svc = await makeService({ client, stats, backend: 'signer' });
    const result = await svc.signerVerifyFrame(
      'https://qrauth.io/v/tok',
      42,
      NOW,
      'deadbeefdeadbeef',
      'sess-1',
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Invalid HMAC');
    expect(result.source).toBe('signer');
    expect(stats.snapshot().signer_verify.primary_ok).toBe(1);
    expect(stats.snapshot().signer_verify.hard_fail).toBe(0);
    expect(stats.snapshot().verify.ok_invalid).toBe(1);
  });

  it('signerVerifyFrame hard-fails (no local fallback) on circuit_open', async () => {
    const { client } = makeStubClient({
      verifyResponses: [{ ok: false, reason: 'circuit_open' }],
    });
    const errorLog = vi.fn();
    const svc = await makeService({
      client,
      stats,
      backend: 'signer',
      logger: { warn: vi.fn(), error: errorLog },
    });
    const result = await svc.signerVerifyFrame(
      'https://qrauth.io/v/tok',
      1,
      NOW,
      '0000000000000000',
      'sess-1',
    );
    // Phase 3: no local fallback. Signer down ⇒ frame rejected, source signer.
    expect(result.source).toBe('signer');
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('MAC verification unavailable');
    const s = stats.snapshot();
    expect(s.signer_verify.primary_ok).toBe(0);
    expect(s.signer_verify.hard_fail).toBe(1);
    expect(s.verify.transport_failure).toBe(1);
    expect(errorLog).toHaveBeenCalledWith(
      expect.objectContaining({ event: 'mac_signer_verify_hard_fail', reason: 'circuit_open' }),
      expect.stringContaining('no local fallback'),
    );
  });

  it('signerVerifyFrame hard-fails on transport error', async () => {
    const { client } = makeStubClient({
      verifyResponses: [{ ok: false, reason: 'timeout' }],
    });
    const svc = await makeService({ client, stats, backend: 'signer' });
    const result = await svc.signerVerifyFrame(
      'https://qrauth.io/v/tok',
      1,
      NOW,
      '0000000000000000',
      'sess-1',
    );
    expect(result.source).toBe('signer');
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('MAC verification unavailable');
    const s = stats.snapshot();
    expect(s.signer_verify.hard_fail).toBe(1);
    expect(s.verify.transport_failure).toBe(1);
  });

  it('signerVerifyFrame hard-fails on session_not_found', async () => {
    const { client } = makeStubClient({
      verifyResponses: [{ ok: false, reason: 'session_not_found' }],
    });
    const svc = await makeService({ client, stats, backend: 'signer' });
    const result = await svc.signerVerifyFrame(
      'https://qrauth.io/v/tok',
      1,
      NOW,
      '0000000000000000',
      'sess-1',
    );
    expect(result.source).toBe('signer');
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('MAC verification unavailable');
    const s = stats.snapshot();
    expect(s.signer_verify.hard_fail).toBe(1);
    expect(s.verify.session_expired).toBe(1);
  });

  it('signerVerifyFrame hard-fails when the client throws', async () => {
    const throwingClient: MacSignerClient = {
      async registerSession() { return { ok: true, expiresAtUnix: 1 }; },
      async sign() { return { ok: true, tag: '0000000000000000' }; },
      async verify() { throw new Error('boom'); },
    };
    const errorLog = vi.fn();
    const svc = await makeService({
      client: throwingClient,
      stats,
      backend: 'signer',
      logger: { warn: vi.fn(), error: errorLog },
    });
    const result = await svc.signerVerifyFrame(
      'https://qrauth.io/v/tok',
      1,
      NOW,
      '0000000000000000',
      'sess-1',
    );
    expect(result.source).toBe('signer');
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('MAC verification unavailable');
    expect(stats.snapshot().signer_verify.hard_fail).toBe(1);
    expect(errorLog).toHaveBeenCalledWith(
      expect.objectContaining({ event: 'mac_signer_verify_hard_fail' }),
      expect.any(String),
    );
  });

  it('signerVerifyFrame rejects expired frames WITHOUT calling the signer', async () => {
    const { client, calls } = makeStubClient({});
    const svc = await makeService({ client, stats, backend: 'signer' });
    const result = await svc.signerVerifyFrame(
      'https://qrauth.io/v/tok',
      1,
      NOW - 10_000, // 10 seconds old, past the 5s freshness window
      '0000000000000000',
      'sess-1',
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('older than 5 seconds');
    expect(result.source).toBe('signer');
    expect(calls.verify).toHaveLength(0);
    // No RPC, no stats movement on the signer counter:
    expect(stats.snapshot().signer_verify.primary_ok).toBe(0);
    expect(stats.snapshot().signer_verify.hard_fail).toBe(0);
  });

  it('signerVerifyFrame rejects future frames WITHOUT calling the signer', async () => {
    const { client, calls } = makeStubClient({});
    const svc = await makeService({ client, stats, backend: 'signer' });
    const result = await svc.signerVerifyFrame(
      'https://qrauth.io/v/tok',
      1,
      NOW + 5_000, // 5s in the future, past the -2s tolerance
      '0000000000000000',
      'sess-1',
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('future');
    expect(result.source).toBe('signer');
    expect(calls.verify).toHaveLength(0);
  });

  // ---------------------------------------------------------------------
  // registerWithSignerBlocking
  // ---------------------------------------------------------------------

  it('registerWithSignerBlocking resolves on signer ok', async () => {
    const { client, calls } = makeStubClient({
      registerResponses: [{ ok: true, expiresAtUnix: 1_700_000_300 }],
    });
    const svc = await makeService({ client, stats, backend: 'signer' });
    await expect(svc.registerWithSignerBlocking('sess-1', 300)).resolves.toBeUndefined();
    expect(calls.register).toEqual([
      { sessionId: 'sess-1', binding: 'authSession:sess-1', ttlSeconds: 300 },
    ]);
    expect(stats.snapshot().register.ok).toBe(1);
  });

  it('registerWithSignerBlocking resolves on session_exists (idempotent)', async () => {
    const { client } = makeStubClient({
      registerResponses: [{ ok: false, reason: 'session_exists' }],
    });
    const svc = await makeService({ client, stats, backend: 'signer' });
    await expect(svc.registerWithSignerBlocking('sess-1', 300)).resolves.toBeUndefined();
    expect(stats.snapshot().register.failure_conflict).toBe(1);
  });

  it('registerWithSignerBlocking throws on registry_full (no local fallback)', async () => {
    const { client } = makeStubClient({
      registerResponses: [{ ok: false, reason: 'registry_full' }],
    });
    const errorLog = vi.fn();
    const svc = await makeService({
      client,
      stats,
      backend: 'signer',
      logger: { warn: vi.fn(), error: errorLog },
    });
    await expect(svc.registerWithSignerBlocking('sess-1', 300)).rejects.toThrow(
      /MAC signer unavailable/i,
    );
    expect(stats.snapshot().register.failure_full).toBe(1);
    expect(errorLog).toHaveBeenCalledWith(
      expect.objectContaining({ event: 'mac_signer_register_blocking_failure', reason: 'registry_full' }),
      expect.stringContaining('registry_full'),
    );
  });

  it('registerWithSignerBlocking throws on transport failure', async () => {
    const { client } = makeStubClient({
      registerResponses: [{ ok: false, reason: 'timeout' }],
    });
    const svc = await makeService({ client, stats, backend: 'signer' });
    await expect(svc.registerWithSignerBlocking('sess-1', 300)).rejects.toThrow(
      /MAC signer unavailable/i,
    );
    expect(stats.snapshot().register.failure_transport).toBe(1);
  });

  it('registerWithSignerBlocking throws when the signer client throws', async () => {
    const throwingClient: MacSignerClient = {
      async registerSession() { throw new Error('boom'); },
      async sign() { return { ok: true, tag: '0000000000000000' }; },
      async verify() { return { ok: true, valid: true }; },
    };
    const svc = await makeService({ client: throwingClient, stats, backend: 'signer' });
    await expect(svc.registerWithSignerBlocking('sess-1', 300)).rejects.toThrow(
      /MAC signer unavailable/i,
    );
    expect(stats.snapshot().register.failure_transport).toBe(1);
  });

  it('registerWithSignerBlocking clamps TTL into [60, 3600]', async () => {
    const { client, calls } = makeStubClient({});
    const svc = await makeService({ client, stats, backend: 'signer' });
    await svc.registerWithSignerBlocking('short', 10);
    await svc.registerWithSignerBlocking('long', 9_999);
    expect(calls.register.map((c) => c.ttlSeconds)).toEqual([60, 3600]);
  });
});
