import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * Integration test for GET /internal/mac-stats (ADR-0001 A4-M2 Phase 1).
 *
 * Constructs a minimal Fastify app that wires the mac-signer plugin and
 * the internal stats route — mirrors the real server.ts plumbing without
 * the DB / Redis / auth middleware weight. If wiring regresses (plugin
 * doesn't decorate, route doesn't auth correctly) this test surfaces it.
 */

beforeAll(() => {
  process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
  process.env.REDIS_URL = 'redis://localhost:6379';
  process.env.JWT_SECRET = 'a'.repeat(32);
  process.env.ANIMATED_QR_SECRET = 'a'.repeat(64);
  process.env.MAC_BACKEND = 'local';
  process.env.INTERNAL_STATS_TOKEN = 't'.repeat(40);
});

describe('GET /internal/mac-stats', () => {
  let app: FastifyInstance;

  beforeEach(async () => {
    const { default: macSignerPlugin } = await import('../../plugins/mac-signer.js');
    const { default: internalMacStatsRoutes } = await import('../internal-mac-stats.js');
    app = Fastify({ logger: false });
    await app.register(macSignerPlugin);
    await app.register(internalMacStatsRoutes, { prefix: '/internal' });
    await app.ready();
  });

  afterEach(async () => {
    await app.close();
  });

  it('returns 401 when no bearer is provided', async () => {
    const res = await app.inject({ method: 'GET', url: '/internal/mac-stats' });
    expect(res.statusCode).toBe(401);
  });

  it('returns 401 on a wrong bearer', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/internal/mac-stats',
      headers: { authorization: 'Bearer nope-nope-nope' },
    });
    expect(res.statusCode).toBe(401);
  });

  it('returns a plausible snapshot on a valid bearer', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/internal/mac-stats',
      headers: { authorization: `Bearer ${process.env.INTERNAL_STATS_TOKEN}` },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body).toMatchObject({
      backend: 'local',
      register: { ok: 0, failure_conflict: 0, failure_full: 0, failure_transport: 0 },
      sign: { ok: 0, session_not_found: 0, transport_failure: 0 },
      verify: {
        ok_valid: 0,
        ok_invalid: 0,
        session_expired: 0,
        transport_failure: 0,
      },
      circuit: { state: 'closed', opens: 0, fallback_seconds: 0 },
      dual: { frames_observed: 0, divergence: 0 },
    });
    expect(body.rpc_duration_ms).toBeDefined();
  });
});

