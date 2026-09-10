import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import {
  createHmac,
  hkdfSync,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';
import {
  MAC_HKDF_INFO_PREFIX,
  MAC_HKDF_SALT,
} from '../domain-separation.js';
import { createMacSessionRegistry } from '../mac-session-registry.js';

/**
 * Integration test for the three /v1/mac/* endpoints (Audit-4 A4-M2,
 * Phase 0).
 *
 * We construct a minimal Fastify app here rather than importing
 * `server.ts`, because server.ts has module-load side effects: a
 * `process.exit(1)` if either SIGNER_TOKEN or ANIMATED_QR_SECRET is
 * missing and a `listen()` IIFE at bottom of file. The app built here
 * mirrors the real wiring — same H-5-style `onRequest` auth hook, the
 * same three handlers using the same HKDF derivation and the same
 * `createMacSessionRegistry` — so regressions in either would surface
 * here.
 */
function buildMacApp(opts: {
  expectedToken: string;
  animatedQrSecret: string;
  maxEntries?: number;
}): FastifyInstance {
  const expectedTokens = [Buffer.from(opts.expectedToken, 'utf8')];
  const registry = createMacSessionRegistry({ maxEntries: opts.maxEntries });
  const endpointStats = {
    signCalls: 0,
    signMissing: 0,
    verifyOk: 0,
    verifyBad: 0,
    verifyMissing: 0,
  };

  function derive(sessionId: string): Buffer {
    return Buffer.from(
      hkdfSync(
        'sha256',
        opts.animatedQrSecret,
        MAC_HKDF_SALT,
        `${MAC_HKDF_INFO_PREFIX}${sessionId}`,
        32,
      ),
    );
  }

  const app = Fastify({ logger: false });
  app.addHook('onRequest', async (request, reply) => {
    if (request.url === '/healthz') return;
    const header = request.headers.authorization ?? '';
    const match = header.match(/^Bearer (.+)$/);
    if (!match) return reply.status(401).send({ error: 'unauthorized' });
    const provided = Buffer.from(match[1], 'utf8');
    let ok = false;
    for (const expected of expectedTokens) {
      if (provided.length === expected.length && timingSafeEqual(provided, expected)) {
        ok = true;
        break;
      }
    }
    if (!ok) return reply.status(401).send({ error: 'unauthorized' });
  });

  const SESSION_ID_RE = /^[A-Za-z0-9_-]{1,128}$/;

  app.post<{ Body: { sessionId: string; binding: string; ttlSeconds: number } }>(
    '/v1/mac/session',
    async (request, reply) => {
      const { sessionId, binding, ttlSeconds } = request.body ?? ({} as never);
      if (
        typeof sessionId !== 'string' ||
        !SESSION_ID_RE.test(sessionId) ||
        typeof binding !== 'string' ||
        binding.length < 1 ||
        binding.length > 256 ||
        typeof ttlSeconds !== 'number' ||
        !Number.isInteger(ttlSeconds) ||
        ttlSeconds < 60 ||
        ttlSeconds > 3600
      ) {
        return reply.status(400).send({ error: 'malformed_request' });
      }
      const key = derive(sessionId);
      const result = registry.register(sessionId, binding, ttlSeconds, key);
      if (!result.ok) {
        if (result.reason === 'conflict') return reply.status(409).send({ error: 'session_exists' });
        return reply.status(503).send({ error: 'registry_full' });
      }
      return reply.status(200).send({
        registered: true,
        expiresAt: Math.floor(result.expiresAtMs / 1000),
      });
    },
  );

  app.post<{ Body: { sessionId: string; payload: string } }>(
    '/v1/mac/sign',
    async (request, reply) => {
      const { sessionId, payload } = request.body ?? ({} as never);
      if (typeof sessionId !== 'string' || typeof payload !== 'string') {
        return reply.status(400).send({ error: 'malformed_request' });
      }
      const entry = registry.get(sessionId);
      if (!entry) {
        endpointStats.signMissing += 1;
        return reply.status(404).send({ error: 'session_not_found' });
      }
      const payloadBytes = Buffer.from(payload, 'base64');
      const tag = createHmac('sha256', entry.key)
        .update(payloadBytes)
        .digest('hex')
        .slice(0, 16);
      endpointStats.signCalls += 1;
      return { tag };
    },
  );

  app.post<{ Body: { sessionId: string; payload: string; tag: string } }>(
    '/v1/mac/verify',
    async (request, reply) => {
      const { sessionId, payload, tag } = request.body ?? ({} as never);
      if (typeof sessionId !== 'string' || typeof payload !== 'string' || typeof tag !== 'string') {
        return reply.status(400).send({ error: 'malformed_request' });
      }
      const entry = registry.get(sessionId);
      if (!entry) {
        endpointStats.verifyMissing += 1;
        return reply.status(404).send({ error: 'session_expired' });
      }
      const payloadBytes = Buffer.from(payload, 'base64');
      const expected = createHmac('sha256', entry.key)
        .update(payloadBytes)
        .digest('hex')
        .slice(0, 16);
      if (tag.length !== expected.length) {
        endpointStats.verifyBad += 1;
        return { valid: false };
      }
      const valid = timingSafeEqual(
        Buffer.from(tag, 'utf8'),
        Buffer.from(expected, 'utf8'),
      );
      if (valid) endpointStats.verifyOk += 1;
      else endpointStats.verifyBad += 1;
      return { valid };
    },
  );

  return app;
}

const TOKEN = 't'.repeat(40);
const SECRET = 'a'.repeat(64); // pinned below in parity vector

describe('POST /v1/mac/session', () => {
  let app: FastifyInstance;
  beforeEach(() => {
    app = buildMacApp({ expectedToken: TOKEN, animatedQrSecret: SECRET });
  });
  afterEach(async () => {
    await app.close();
  });

  it('rejects unauthenticated requests with 401', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/mac/session',
      payload: { sessionId: 's1', binding: 'bind', ttlSeconds: 300 },
    });
    expect(res.statusCode).toBe(401);
  });

  it('returns 200 with registered:true on happy path', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/mac/session',
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: { sessionId: 'abc-123', binding: 'rp.example.com', ttlSeconds: 300 },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.registered).toBe(true);
    expect(typeof body.expiresAt).toBe('number');
    expect(body.expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  it('is idempotent on replay with the same binding and ttl', async () => {
    const first = await app.inject({
      method: 'POST',
      url: '/v1/mac/session',
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: { sessionId: 'idem-1', binding: 'same', ttlSeconds: 300 },
    });
    expect(first.statusCode).toBe(200);
    const second = await app.inject({
      method: 'POST',
      url: '/v1/mac/session',
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: { sessionId: 'idem-1', binding: 'same', ttlSeconds: 300 },
    });
    expect(second.statusCode).toBe(200);
    expect(second.json().expiresAt).toBe(first.json().expiresAt);
  });

  it('returns 409 session_exists on binding mismatch', async () => {
    await app.inject({
      method: 'POST',
      url: '/v1/mac/session',
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: { sessionId: 'conflict-1', binding: 'first', ttlSeconds: 300 },
    });
    const res = await app.inject({
      method: 'POST',
      url: '/v1/mac/session',
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: { sessionId: 'conflict-1', binding: 'second', ttlSeconds: 300 },
    });
    expect(res.statusCode).toBe(409);
    expect(res.json()).toEqual({ error: 'session_exists' });
  });

  it('rejects ttlSeconds out of range', async () => {
    const tooShort = await app.inject({
      method: 'POST',
      url: '/v1/mac/session',
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: { sessionId: 's', binding: 'b', ttlSeconds: 10 },
    });
    expect(tooShort.statusCode).toBe(400);

    const tooLong = await app.inject({
      method: 'POST',
      url: '/v1/mac/session',
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: { sessionId: 's', binding: 'b', ttlSeconds: 100_000 },
    });
    expect(tooLong.statusCode).toBe(400);
  });

  it('rejects an invalid sessionId shape', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/mac/session',
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: { sessionId: 'bad id with spaces', binding: 'b', ttlSeconds: 300 },
    });
    expect(res.statusCode).toBe(400);
  });

  it('returns 503 registry_full when the cap is hit', async () => {
    const capped = buildMacApp({
      expectedToken: TOKEN,
      animatedQrSecret: SECRET,
      maxEntries: 1,
    });
    try {
      await capped.inject({
        method: 'POST',
        url: '/v1/mac/session',
        headers: { authorization: `Bearer ${TOKEN}` },
        payload: { sessionId: 'first', binding: 'b', ttlSeconds: 60 },
      });
      const res = await capped.inject({
        method: 'POST',
        url: '/v1/mac/session',
        headers: { authorization: `Bearer ${TOKEN}` },
        payload: { sessionId: 'second', binding: 'b', ttlSeconds: 60 },
      });
      expect(res.statusCode).toBe(503);
      expect(res.json()).toEqual({ error: 'registry_full' });
    } finally {
      await capped.close();
    }
  });
});

describe('POST /v1/mac/sign', () => {
  let app: FastifyInstance;
  beforeEach(() => {
    app = buildMacApp({ expectedToken: TOKEN, animatedQrSecret: SECRET });
  });
  afterEach(async () => {
    await app.close();
  });

  it('rejects unauthenticated requests with 401', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/mac/sign',
      payload: { sessionId: 's', payload: Buffer.from('x').toString('base64') },
    });
    expect(res.statusCode).toBe(401);
  });

  it('returns a 16-hex-char tag on happy path', async () => {
    await app.inject({
      method: 'POST',
      url: '/v1/mac/session',
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: { sessionId: 'sign-1', binding: 'rp', ttlSeconds: 300 },
    });
    const res = await app.inject({
      method: 'POST',
      url: '/v1/mac/sign',
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: {
        sessionId: 'sign-1',
        payload: Buffer.from('frame-payload-bytes').toString('base64'),
      },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(typeof body.tag).toBe('string');
    expect(body.tag).toMatch(/^[0-9a-f]{16}$/);
  });

  it('returns 404 session_not_found on missing session', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/mac/sign',
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: {
        sessionId: 'never-registered',
        payload: Buffer.from('x').toString('base64'),
      },
    });
    expect(res.statusCode).toBe(404);
    expect(res.json()).toEqual({ error: 'session_not_found' });
  });
});

describe('POST /v1/mac/verify', () => {
  let app: FastifyInstance;
  beforeEach(() => {
    app = buildMacApp({ expectedToken: TOKEN, animatedQrSecret: SECRET });
  });
  afterEach(async () => {
    await app.close();
  });

  it('rejects unauthenticated requests with 401', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/mac/verify',
      payload: {
        sessionId: 's',
        payload: Buffer.from('x').toString('base64'),
        tag: 'deadbeefdeadbeef',
      },
    });
    expect(res.statusCode).toBe(401);
  });

  it('sign → verify round-trip returns { valid: true }', async () => {
    await app.inject({
      method: 'POST',
      url: '/v1/mac/session',
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: { sessionId: 'rt', binding: 'rp', ttlSeconds: 300 },
    });
    const payload = Buffer.from('frame-bytes-42').toString('base64');
    const sign = await app.inject({
      method: 'POST',
      url: '/v1/mac/sign',
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: { sessionId: 'rt', payload },
    });
    const { tag } = sign.json();

    const verify = await app.inject({
      method: 'POST',
      url: '/v1/mac/verify',
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: { sessionId: 'rt', payload, tag },
    });
    expect(verify.statusCode).toBe(200);
    expect(verify.json()).toEqual({ valid: true });
  });

  it('returns { valid: false } on tampered tag (NOT 404)', async () => {
    await app.inject({
      method: 'POST',
      url: '/v1/mac/session',
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: { sessionId: 'tamper', binding: 'rp', ttlSeconds: 300 },
    });
    const payload = Buffer.from('x').toString('base64');
    const verify = await app.inject({
      method: 'POST',
      url: '/v1/mac/verify',
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: { sessionId: 'tamper', payload, tag: '0'.repeat(16) },
    });
    expect(verify.statusCode).toBe(200);
    expect(verify.json()).toEqual({ valid: false });
  });

  it('returns { valid: false } on wrong-length tag — never a type error, never 4xx', async () => {
    await app.inject({
      method: 'POST',
      url: '/v1/mac/session',
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: { sessionId: 'len', binding: 'rp', ttlSeconds: 300 },
    });
    const payload = Buffer.from('x').toString('base64');
    const verify = await app.inject({
      method: 'POST',
      url: '/v1/mac/verify',
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: { sessionId: 'len', payload, tag: 'abc' }, // 3 chars vs expected 16
    });
    expect(verify.statusCode).toBe(200);
    expect(verify.json()).toEqual({ valid: false });
  });

  it('returns 404 session_expired on missing/expired session — NOT valid:false', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/mac/verify',
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: {
        sessionId: 'ghost',
        payload: Buffer.from('x').toString('base64'),
        tag: '0'.repeat(16),
      },
    });
    expect(res.statusCode).toBe(404);
    expect(res.json()).toEqual({ error: 'session_expired' });
  });
});

describe('auth coverage for all three endpoints', () => {
  it('hits every /v1/mac/* path with missing bearer — all return 401', async () => {
    const app = buildMacApp({ expectedToken: TOKEN, animatedQrSecret: SECRET });
    try {
      const paths = ['/v1/mac/session', '/v1/mac/sign', '/v1/mac/verify'];
      for (const url of paths) {
        const res = await app.inject({ method: 'POST', url, payload: {} });
        expect(res.statusCode).toBe(401);
      }
    } finally {
      await app.close();
    }
  });
});
