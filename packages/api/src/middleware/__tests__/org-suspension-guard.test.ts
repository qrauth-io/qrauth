import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { createHash } from 'node:crypto';

/**
 * The real `authenticate` refuses mutating requests of a suspended
 * organization (403 OrganizationSuspended) for both JWT and API-key callers,
 * lets reads through, and exempts superadmin routes and personal account
 * actions. A refused request never reaches its handler.
 */

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

const { isSuspensionExempt } = await import('../../lib/org-suspension.js');
const { constantTimeEqualString } = await import('../../lib/constant-time.js');

const API_KEY = 'qrauth_test_key_0000000000';
const state = { suspendedAt: null as Date | null };
const handled: string[] = [];

const prisma = {
  organization: { findUnique: async () => ({ suspendedAt: state.suspendedAt }) },
  apiKey: {
    findUnique: async ({ where }: { where: { keyHash: string } }) =>
      constantTimeEqualString(where.keyHash, createHash('sha256').update(API_KEY).digest('hex'))
        ? { id: 'k_1', organizationId: 'org_1', role: 'ADMIN', revokedAt: null, createdByUserId: null }
        : null,
    update: async () => ({}),
  },
};

let app: FastifyInstance;
let jwt: string;

const ROUTES: Array<[method: 'GET' | 'POST' | 'PATCH' | 'DELETE', url: string]> = [
  ['GET', '/api/v1/qrcodes'],
  ['POST', '/api/v1/qrcodes'],
  ['PATCH', '/api/v1/qrcodes/:token'],
  ['DELETE', '/api/v1/qrcodes/:token'],
  ['POST', '/api/v1/qrcodes/bulk-revoke'],
  ['POST', '/api/v1/api-keys'],
  ['PATCH', '/api/v1/organizations/:id/members/:userId'],
  ['DELETE', '/api/v1/organizations/:id/members/:userId'],
  ['POST', '/api/v1/auth/switch-org'],
  ['DELETE', '/api/v1/sessions/:id'],
  ['POST', '/api/v1/admin/organizations/:orgId/unsuspend'],
];

beforeAll(async () => {
  app = Fastify();
  app.decorate('prisma', prisma as never);
  const { authMiddleware } = await import('../auth.js');
  await app.register(authMiddleware);
  for (const [method, url] of ROUTES) {
    app.route({
      method,
      url,
      preHandler: [app.authenticate],
      handler: async () => {
        handled.push(`${method} ${url}`);
        return { ok: true };
      },
    });
  }
  await app.ready();
  jwt = app.jwt.sign({ userId: 'u_1', orgId: 'org_1', role: 'OWNER', email: 'o@example.com' });
});

afterAll(async () => {
  await app.close();
});

beforeEach(() => {
  state.suspendedAt = null;
  handled.length = 0;
});

const bearer = () => ({ authorization: `Bearer ${jwt}` });
const apiKey = () => ({ 'x-api-key': API_KEY });

describe('suspended organization', () => {
  beforeEach(() => {
    state.suspendedAt = new Date('2026-10-27T10:00:00Z');
  });

  it.each([
    ['POST', '/api/v1/qrcodes'],
    ['PATCH', '/api/v1/qrcodes/tok_1'],
    ['DELETE', '/api/v1/qrcodes/tok_1'],
    ['POST', '/api/v1/qrcodes/bulk-revoke'],
    ['POST', '/api/v1/api-keys'],
    ['PATCH', '/api/v1/organizations/org_1/members/u_2'],
    ['DELETE', '/api/v1/organizations/org_1/members/u_2'],
  ])('JWT %s %s → 403, handler not run', async (method, url) => {
    const res = await app.inject({ method: method as 'POST', url, headers: bearer() });

    expect(res.statusCode).toBe(403);
    expect(res.json().error).toBe('OrganizationSuspended');
    expect(handled).toEqual([]);
  });

  it('API key POST /qrcodes → 403', async () => {
    const res = await app.inject({ method: 'POST', url: '/api/v1/qrcodes', headers: apiKey() });

    expect(res.statusCode).toBe(403);
    expect(handled).toEqual([]);
  });

  it.each([
    ['GET', '/api/v1/qrcodes', 'read'],
    ['POST', '/api/v1/auth/switch-org', 'personal'],
    ['DELETE', '/api/v1/sessions/s_1', 'personal'],
    ['POST', '/api/v1/admin/organizations/org_1/unsuspend', 'superadmin'],
  ])('%s %s (%s) is still allowed', async (method, url) => {
    const res = await app.inject({ method: method as 'GET', url, headers: bearer() });

    expect(res.statusCode).toBe(200);
  });
});

describe('not suspended / after unsuspend', () => {
  it.each([
    ['POST', '/api/v1/qrcodes'],
    ['DELETE', '/api/v1/qrcodes/tok_1'],
    ['POST', '/api/v1/api-keys'],
  ])('%s %s → handler runs', async (method, url) => {
    const res = await app.inject({ method: method as 'POST', url, headers: bearer() });

    expect(res.statusCode).toBe(200);
    expect(handled).toHaveLength(1);
  });
});

describe('isSuspensionExempt', () => {
  it.each([
    ['GET', '/api/v1/qrcodes', true],
    ['HEAD', '/api/v1/qrcodes', true],
    ['POST', '/api/v1/qrcodes/', false],
    ['POST', '/api/v1/admin/organizations/:orgId/suspend', true],
    ['DELETE', '/api/v1/sessions/', true],
    ['POST', '/api/v1/ephemeral/', false],
    ['POST', undefined, false],
  ])('%s %s → %s', (method, url, expected) => {
    expect(isSuspensionExempt(method, url)).toBe(expected);
  });
});
