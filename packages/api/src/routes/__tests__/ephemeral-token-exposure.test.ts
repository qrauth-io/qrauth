import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * Audit 2026-10 FINDING-008: the ephemeral claim token is a bearer secret.
 * It is returned once, when the session is created, and never by list or get
 * (which any role in the organization can call).
 */

process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

const SESSION = {
  id: 'eph_1',
  organizationId: 'org_1',
  token: 'eph_tok_secret',
  claimUrl: 'https://qrauth.test/claim/eph_tok_secret',
  status: 'PENDING',
  scopes: ['read'],
  ttlSeconds: 300,
  maxUses: 1,
  useCount: 0,
  deviceBinding: false,
  expiresAt: new Date(Date.now() + 300_000),
  claimedAt: null,
  revokedAt: null,
  createdAt: new Date(),
  justExpired: false,
};

vi.mock('../../services/ephemeral.js', () => ({
  EphemeralSessionService: class {
    async createSession() {
      return SESSION;
    }
    async listSessions() {
      return { sessions: [SESSION], expiredSessionIds: [], total: 1, page: 1, pageSize: 20, totalPages: 1 };
    }
    async getSession() {
      return SESSION;
    }
  },
}));

vi.mock('../../services/usage.js', () => ({
  UsageService: class {
    async checkQuota() {
      return null;
    }
    async increment() {}
  },
}));

vi.mock('../../services/webhook.js', () => ({
  WebhookService: class {
    async emit() {}
  },
}));

let app: FastifyInstance;

beforeAll(async () => {
  app = Fastify({ logger: false });
  app.decorate('prisma', { organization: { findUnique: async () => ({ plan: 'FREE' }) } } as never);
  app.decorate('authenticate', async (req: never) => {
    const request = req as unknown as { headers: Record<string, string>; user?: unknown };
    request.user = { id: 'api-key', orgId: 'org_1', role: request.headers['x-test-role'], email: '' };
  });
  const { default: ephemeralRoutes } = await import('../ephemeral.js');
  await app.register(ephemeralRoutes, { prefix: '/api/v1/ephemeral' });
  await app.ready();
});

afterAll(async () => {
  await app?.close();
});

const headers = (role: string) => ({ 'x-api-key': 'key', 'x-test-role': role });

describe('ephemeral claim token exposure (FINDING-008)', () => {
  it('the create response carries the token and claim URL', async () => {
    const res = await app.inject({
      method: 'POST', url: '/api/v1/ephemeral', headers: headers('ADMIN'), payload: { scopes: ['read'] },
    });

    expect(res.statusCode).toBe(201);
    expect(res.json()).toMatchObject({ token: SESSION.token, claimUrl: SESSION.claimUrl });
  });

  it.each(['VIEWER', 'OWNER'])('the list response carries neither, for a %s', async (role) => {
    const res = await app.inject({ method: 'GET', url: '/api/v1/ephemeral', headers: headers(role) });

    expect(res.statusCode).toBe(200);
    const [session] = res.json().sessions;
    expect(session.sessionId).toBe(SESSION.id);
    expect(session).not.toHaveProperty('token');
    expect(session).not.toHaveProperty('claimUrl');
    expect(res.body).not.toContain(SESSION.token);
  });

  it.each(['VIEWER', 'OWNER'])('the get response carries neither, for a %s', async (role) => {
    const res = await app.inject({ method: 'GET', url: `/api/v1/ephemeral/${SESSION.id}`, headers: headers(role) });

    expect(res.statusCode).toBe(200);
    expect(res.json().sessionId).toBe(SESSION.id);
    expect(res.json()).not.toHaveProperty('token');
    expect(res.json()).not.toHaveProperty('claimUrl');
    expect(res.body).not.toContain(SESSION.token);
  });
});

describe('creating an ephemeral session with only a public client id (FINDING-009)', () => {
  it('is refused: a client id is not a credential', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/ephemeral',
      headers: { 'content-type': 'application/json', 'x-client-id': 'qrauth_app_public' },
      payload: { scopes: ['read'] },
    });

    expect(res.statusCode).toBe(401);
  });
});

