import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * Audit 2026-10 FINDING-001 follow-up: stored emails are canonical (trimmed,
 * lowercased), so the passkey sign-in lookup must use the canonical form too
 * or an address typed in another case finds no account.
 */

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

vi.mock('../../lib/cache.js', () => ({
  redis: {},
  cacheGet: vi.fn(async () => null),
  cacheSet: vi.fn(async () => undefined),
  cacheDel: vi.fn(async () => undefined),
  disconnectCache: vi.fn(async () => undefined),
}));

const optionsRequestedFor: Array<string | undefined> = [];
vi.mock('../../services/webauthn.js', () => ({
  WebAuthnService: class {
    async generateAuthenticationOpts(userId?: string) {
      optionsRequestedFor.push(userId);
      return { options: {}, challengeKey: 'challenge' };
    }
  },
}));

const STORED = { id: 'user_1', email: 'owner@example.com' };
const prisma = {
  user: {
    findUnique: async ({ where }: { where: { email: string } }) =>
      where.email === STORED.email ? { id: STORED.id } : null,
  },
};

let app: FastifyInstance;

beforeAll(async () => {
  app = Fastify({ logger: false });
  app.decorate('prisma', prisma as never);
  app.decorate('authenticate', async () => undefined);
  const { default: webauthnRoutes } = await import('../webauthn.js');
  await app.register(webauthnRoutes, { prefix: '/api/v1/webauthn' });
  await app.ready();
});

afterAll(async () => {
  await app?.close();
});

describe('POST /webauthn/authenticate/options', () => {
  it('finds the account whatever case and padding the email is typed with', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/webauthn/authenticate/options',
      payload: { email: '  Owner@Example.COM ' },
    });

    expect(res.statusCode).toBe(200);
    expect(optionsRequestedFor).toEqual([STORED.id]);
  });
});
