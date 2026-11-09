import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * Audit 2026-10 FINDING-010: an API key tied to a user (createdByUserId set —
 * CLI keys) carries a role snapshot from when it was minted. Its effective
 * role is the lower of that snapshot and the user's CURRENT membership role,
 * and it stops working when the membership is gone. Keys with no creator
 * (dashboard-minted organization keys) are unaffected.
 */

process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

let apiKey: Record<string, unknown> | null = null;
let membershipRole: string | null = null;
let membershipLookups = 0;

const prisma = {
  apiKey: {
    findUnique: async () => apiKey,
    update: async () => ({}),
  },
  membership: {
    findUnique: async () => {
      membershipLookups += 1;
      return membershipRole ? { role: membershipRole } : null;
    },
  },
};

let app: FastifyInstance;

beforeAll(async () => {
  app = Fastify({ logger: false });
  app.decorate('prisma', prisma as never);
  const { authMiddleware } = await import('../auth.js');
  await app.register(authMiddleware);
  app.get('/whoami', { preHandler: [app.authenticate] }, async (request) => request.user);
  await app.ready();
});

afterAll(async () => {
  await app?.close();
});

beforeEach(() => {
  membershipLookups = 0;
  membershipRole = null;
  apiKey = { id: 'key_1', organizationId: 'org_1', role: 'ADMIN', createdByUserId: 'user_1', revokedAt: null };
});

const whoami = () => app.inject({ method: 'GET', url: '/whoami', headers: { 'x-api-key': 'raw-key' } });

describe('API key effective role (FINDING-010)', () => {
  it('a demoted member’s key is capped at the current membership role', async () => {
    membershipRole = 'VIEWER';

    const res = await whoami();

    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ orgId: 'org_1', role: 'VIEWER' });
  });

  it('a promoted member’s key keeps the lower role it was minted with', async () => {
    apiKey = { ...apiKey, role: 'MEMBER' };
    membershipRole = 'OWNER';

    const res = await whoami();

    expect(res.json().role).toBe('MEMBER');
  });

  it('an unchanged member’s key keeps its role', async () => {
    membershipRole = 'ADMIN';

    const res = await whoami();

    expect(res.json().role).toBe('ADMIN');
  });

  it('a key whose creator is no longer a member is rejected', async () => {
    membershipRole = null;

    const res = await whoami();

    expect(res.statusCode).toBe(401);
    expect(res.json().message).toBe('Invalid or revoked API key.');
  });

  it('a key with no creator keeps its stored role with no membership lookup', async () => {
    apiKey = { ...apiKey, createdByUserId: null };

    const res = await whoami();

    expect(res.statusCode).toBe(200);
    expect(res.json().role).toBe('ADMIN');
    expect(membershipLookups).toBe(0);
  });
});
