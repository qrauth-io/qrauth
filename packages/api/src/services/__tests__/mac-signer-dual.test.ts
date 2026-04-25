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
