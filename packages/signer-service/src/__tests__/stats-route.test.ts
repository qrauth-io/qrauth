import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { timingSafeEqual } from 'node:crypto';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CACHE_MAX, CACHE_TTL_MS, createKeyCaches } from '../key-cache.js';
import { __resetMasterKeyCache } from '../key-at-rest.js';

/**
 * Integration test for the `/internal/stats` endpoint.
 *
 * We construct a minimal Fastify app here rather than importing
 * `server.ts`, because server.ts has module-load side effects (a
 * `process.exit(1)` if SIGNER_TOKEN is missing and a `listen()` IIFE at
 * bottom of file). The app built in this test mirrors the real wiring —
 * same `onRequest` auth hook pattern, same route handler using the real
 * `createKeyCaches(...).snapshot()` — so regressions in either would
 * surface here.
 */
function buildTestApp(expectedToken: string, dir: string): {
  app: FastifyInstance;
  startedAtMs: number;
} {
  const caches = createKeyCaches(dir);
  const expectedTokens = [Buffer.from(expectedToken, 'utf8')];
  const startedAtMs = Date.now();

  const app = Fastify({ logger: false });

  app.addHook('onRequest', async (request, reply) => {
    if (request.url === '/healthz') return;
    const header = request.headers.authorization ?? '';
    const match = header.match(/^Bearer (.+)$/);
    if (!match) {
      return reply.status(401).send({ error: 'unauthorized' });
    }
    const provided = Buffer.from(match[1], 'utf8');
    let authenticated = false;
    for (const expected of expectedTokens) {
      if (provided.length === expected.length && timingSafeEqual(provided, expected)) {
        authenticated = true;
        break;
      }
    }
    if (!authenticated) {
      return reply.status(401).send({ error: 'unauthorized' });
    }
  });

  app.get('/internal/stats', async () => ({
    ...caches.snapshot(),
    uptimeSeconds: Math.floor((Date.now() - startedAtMs) / 1000),
  }));

  return { app, startedAtMs };
}

describe('GET /internal/stats', () => {
  const TOKEN = 'x'.repeat(40);
  let dir: string;
  let app: FastifyInstance;

  beforeEach(() => {
    __resetMasterKeyCache();
    process.env.SIGNER_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
    dir = mkdtempSync(join(tmpdir(), 'signer-stats-test-'));
    app = buildTestApp(TOKEN, dir).app;
  });

  afterEach(async () => {
    await app.close();
    rmSync(dir, { recursive: true, force: true });
    delete process.env.SIGNER_MASTER_KEY;
    __resetMasterKeyCache();
  });

  it('returns 401 when no Authorization header is sent', async () => {
    const res = await app.inject({ method: 'GET', url: '/internal/stats' });
    expect(res.statusCode).toBe(401);
    expect(res.json()).toEqual({ error: 'unauthorized' });
  });

  it('returns 401 when the bearer token does not match', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/internal/stats',
      headers: { authorization: 'Bearer wrong-token-same-length-XXXXXXXXXXXXXXX' },
    });
    expect(res.statusCode).toBe(401);
  });

  it('returns 200 and the declared JSON shape when authenticated', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/internal/stats',
      headers: { authorization: `Bearer ${TOKEN}` },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();

    expect(body).toMatchObject({
      caches: {
        slhdsa: {
          entries: 0,
          hits: 0,
          misses: 0,
          evictions: { ttl: 0, lru: 0 },
        },
        ecdsa: {
          entries: 0,
          hits: 0,
          misses: 0,
          evictions: { ttl: 0, lru: 0 },
        },
      },
      config: { ttlMs: CACHE_TTL_MS, max: CACHE_MAX },
    });
    expect(typeof body.uptimeSeconds).toBe('number');
    expect(body.uptimeSeconds).toBeGreaterThanOrEqual(0);
  });
});
