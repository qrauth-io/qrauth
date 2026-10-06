import { describe, it, expect, vi, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * Fail-closed gating of the /_test/* hooks.
 *
 * NODE_ENV is optional in config.ts (defaults to 'development' when unset),
 * so `!isProd` alone fails OPEN on an unset NODE_ENV. The hooks therefore
 * additionally require the explicit ENABLE_TEST_HOOKS=1 opt-in
 * (config.server.testHooksEnabled) — this suite pins the load-bearing case:
 * with NODE_ENV UNSET and no opt-in, the routes must not exist (404). The
 * gate matters most for /_test/ensure-platform-signing-keys, which mints
 * real signing-key material for the platform org with no auth.
 *
 * Routes gate REGISTRATION on the flag, and config is evaluated at import,
 * so each scenario resets the module registry and re-imports the route
 * plugin under a fresh environment.
 */

vi.mock('../../lib/cache.js', () => ({
  redis: {},
  cacheGet: async () => null,
  cacheSet: async () => {},
  cacheDel: async () => {},
  disconnectCache: async () => {},
}));

vi.mock('../../lib/email.js', () => ({
  sendPasswordResetEmail: async () => {},
  sendWelcomeVerificationEmail: async () => {},
  sendPasswordChangedEmail: async () => {},
  sendSuspiciousLoginEmail: async () => {},
}));

vi.mock('../../lib/queue.js', () => ({
  webhookQueue: { add: async () => ({ id: 'job' }) },
  scanQueue: {},
  fraudQueue: {},
  alertQueue: {},
  cleanupQueue: {},
  reconcileQueue: {},
  createQueueConnection: () => {
    throw new Error('unit tests must not open Redis connections');
  },
  closeQueues: async () => {},
}));

const BASE_ENV = {
  DATABASE_URL: 'postgresql://test:test@localhost:5432/test',
  REDIS_URL: 'redis://localhost:6379',
  JWT_SECRET: 'unit-test-secret-0123456789abcdef',
};

async function buildAppWithEnv(env: {
  NODE_ENV?: string;
  ENABLE_TEST_HOOKS?: string;
}): Promise<FastifyInstance> {
  vi.resetModules();
  Object.assign(process.env, BASE_ENV);
  delete process.env.NODE_ENV;
  delete process.env.ENABLE_TEST_HOOKS;
  if (env.NODE_ENV !== undefined) process.env.NODE_ENV = env.NODE_ENV;
  if (env.ENABLE_TEST_HOOKS !== undefined) process.env.ENABLE_TEST_HOOKS = env.ENABLE_TEST_HOOKS;

  const { default: authRoutes } = await import('../auth.js');
  const app = Fastify({ logger: false });
  // Minimal decorations auth.ts dereferences at registration/request time.
  app.decorate('authenticate', async () => {});
  app.decorate('prisma', {
    user: { updateMany: async () => ({ count: 1 }) },
    organization: { findUnique: async () => null },
  });
  await app.register(authRoutes);
  await app.ready();
  return app;
}

const HOOK_PATHS = ['/_test/mark-verified', '/_test/ensure-platform-signing-keys'] as const;

describe('/_test/* hook gating (fail-closed)', () => {
  beforeEach(() => {
    vi.resetModules();
  });

  it('routes do NOT exist when NODE_ENV is UNSET and ENABLE_TEST_HOOKS is absent', async () => {
    const app = await buildAppWithEnv({});
    try {
      for (const path of HOOK_PATHS) {
        const res = await app.inject({ method: 'POST', url: path, payload: {} });
        expect(res.statusCode, `${path} must 404 without the explicit opt-in`).toBe(404);
      }
    } finally {
      await app.close();
    }
  });

  it('routes do NOT exist in production even with ENABLE_TEST_HOOKS=1', async () => {
    // Production needs more required env; provide the minimum.
    process.env.WEBAUTHN_ORIGIN = 'https://qrauth.io';
    process.env.VISUAL_PROOF_SECRET = 'p'.repeat(40);
    process.env.MAC_BACKEND = 'signer';
    const app = await buildAppWithEnv({ NODE_ENV: 'production', ENABLE_TEST_HOOKS: '1' });
    try {
      for (const path of HOOK_PATHS) {
        const res = await app.inject({ method: 'POST', url: path, payload: {} });
        expect(res.statusCode, `${path} must never exist in production`).toBe(404);
      }
    } finally {
      await app.close();
      delete process.env.WEBAUTHN_ORIGIN;
      delete process.env.VISUAL_PROOF_SECRET;
      delete process.env.MAC_BACKEND;
    }
  });

  it('routes exist with ENABLE_TEST_HOOKS=1 outside production (even with NODE_ENV unset)', async () => {
    const app = await buildAppWithEnv({ ENABLE_TEST_HOOKS: '1' });
    try {
      const verified = await app.inject({
        method: 'POST',
        url: '/_test/mark-verified',
        payload: { email: 'x@example.com' },
      });
      expect(verified.statusCode).toBe(200);

      // Registered and reachable: the stub prisma has no platform org, so
      // the handler's own 500 (not a router 404) proves registration.
      const ensure = await app.inject({
        method: 'POST',
        url: '/_test/ensure-platform-signing-keys',
        payload: {},
      });
      expect(ensure.statusCode).toBe(500);
      expect(ensure.json().error).toContain('platform org missing');
    } finally {
      await app.close();
    }
  });
});
