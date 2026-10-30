import { describe, it, expect, beforeAll, vi } from 'vitest';

const revokeAll = vi.hoisted(() => vi.fn(async () => 3));
vi.mock('../../services/qr-revocation.js', () => ({ revokeAllActiveForOrg: revokeAll }));
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * POST /api/v1/admin/organizations/:orgId/suspend and /unsuspend. Same
 * harness as admin-org-plan.test.ts: real admin routes, real requireAdmin
 * gate and validation, stubbed authenticate and prisma.
 */

beforeAll(() => {
  process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
  process.env.REDIS_URL = 'redis://localhost:6379';
  process.env.JWT_SECRET = 'a'.repeat(32);
  process.env.ANIMATED_QR_SECRET = 'a'.repeat(64);
  process.env.ADMIN_EMAILS = 'admin@qrauth.io';
});

const ADMIN = 'admin@qrauth.io';

type OrgRow = { id: string; suspendedAt: Date | null; suspendedReason: string | null };

async function buildApp(org: OrgRow | null) {
  const updates: Array<Record<string, unknown>> = [];
  const audits: Array<Record<string, unknown>> = [];
  const prisma = {
    user: { findUnique: async () => ({ email: ADMIN, emailVerified: true }) },
    organization: {
      findUnique: async () => org,
      update: async ({ data }: { data: Record<string, unknown> }) => {
        updates.push(data);
        return { id: org!.id, name: 'Acme', ...data };
      },
    },
    auditLog: { create: async ({ data }: { data: Record<string, unknown> }) => { audits.push(data); } },
  };
  const app = Fastify({ logger: false });
  app.decorate('prisma', prisma as never);
  app.decorate('authenticate', async (req: never) => {
    const request = req as unknown as { headers: Record<string, string>; user?: unknown };
    request.user = { id: 'u_admin', orgId: 'o_admin', role: 'OWNER', email: request.headers['x-test-email'] };
  });
  const { default: adminRoutes } = await import('../admin.js');
  await app.register(adminRoutes, { prefix: '/api/v1/admin' });
  await app.ready();
  return { app, updates, audits };
}

const post = (app: FastifyInstance, path: string, body?: unknown, email = ADMIN) =>
  app.inject({
    method: 'POST',
    url: `/api/v1/admin/organizations/org_1/${path}`,
    headers: { 'x-test-email': email, ...(body ? { 'content-type': 'application/json' } : {}) },
    ...(body ? { payload: JSON.stringify(body) } : {}),
  });

describe('POST /admin/organizations/:orgId/suspend', () => {
  it('requires a reason', async () => {
    const { app, updates } = await buildApp({ id: 'org_1', suspendedAt: null, suspendedReason: null });

    expect((await post(app, 'suspend', {})).statusCode).toBe(400);
    expect((await post(app, 'suspend', { reason: '  ' })).statusCode).toBe(400);
    expect(updates).toEqual([]);
  });

  it('refuses a non-admin', async () => {
    const { app, updates } = await buildApp({ id: 'org_1', suspendedAt: null, suspendedReason: null });

    const res = await post(app, 'suspend', { reason: 'phishing campaign' }, 'member@example.com');

    expect(res.statusCode).toBe(403);
    expect(updates).toEqual([]);
  });

  it('sets suspendedAt and the reason, and writes an audit entry', async () => {
    const { app, updates, audits } = await buildApp({ id: 'org_1', suspendedAt: null, suspendedReason: null });

    const res = await post(app, 'suspend', { reason: 'phishing campaign' });

    expect(res.statusCode).toBe(200);
    expect(res.json().suspended).toBe(true);
    expect(updates[0].suspendedAt).toBeInstanceOf(Date);
    expect(updates[0].suspendedReason).toBe('phishing campaign');
    expect(audits[0]).toMatchObject({ action: 'admin.organization.suspend', resourceId: 'org_1', userId: 'u_admin' });
  });

  it('keeps the original suspendedAt when suspended again', async () => {
    const first = new Date('2026-10-01T00:00:00Z');
    const { app, updates } = await buildApp({ id: 'org_1', suspendedAt: first, suspendedReason: 'old' });

    await post(app, 'suspend', { reason: 'updated reason' });

    expect(updates[0].suspendedAt).toEqual(first);
    expect(updates[0].suspendedReason).toBe('updated reason');
  });

  it('404 for an unknown organization', async () => {
    const { app } = await buildApp(null);

    expect((await post(app, 'suspend', { reason: 'phishing campaign' })).statusCode).toBe(404);
  });
});

describe('POST /admin/organizations/:orgId/unsuspend', () => {
  it('clears both fields and writes an audit entry', async () => {
    const { app, updates, audits } = await buildApp({
      id: 'org_1',
      suspendedAt: new Date('2026-10-01T00:00:00Z'),
      suspendedReason: 'phishing campaign',
    });

    const res = await post(app, 'unsuspend');

    expect(res.statusCode).toBe(200);
    expect(res.json().suspended).toBe(false);
    expect(updates[0]).toEqual({ suspendedAt: null, suspendedReason: null });
    expect(audits[0]).toMatchObject({ action: 'admin.organization.unsuspend' });
  });
});

describe('POST /admin/organizations/:orgId/revoke-all-codes', () => {
  it('requires a reason', async () => {
    const { app } = await buildApp({ id: 'org_1', suspendedAt: null, suspendedReason: null });
    revokeAll.mockClear();

    expect((await post(app, 'revoke-all-codes', {})).statusCode).toBe(400);
    expect(revokeAll).not.toHaveBeenCalled();
  });

  it('refuses a non-admin', async () => {
    const { app } = await buildApp({ id: 'org_1', suspendedAt: null, suspendedReason: null });
    revokeAll.mockClear();

    const res = await post(app, 'revoke-all-codes', { reason: 'phishing campaign' }, 'member@example.com');

    expect(res.statusCode).toBe(403);
    expect(revokeAll).not.toHaveBeenCalled();
  });

  it('revokes every active code of the org and audits the count', async () => {
    const { app, audits } = await buildApp({ id: 'org_1', suspendedAt: null, suspendedReason: null });
    revokeAll.mockClear();

    const res = await post(app, 'revoke-all-codes', { reason: 'phishing campaign' });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ revoked: 3 });
    expect(revokeAll).toHaveBeenCalledWith(expect.anything(), expect.anything(), 'org_1');
    expect(audits[0]).toMatchObject({
      action: 'admin.organization.revokeAllCodes',
      metadata: { reason: 'phishing campaign', revoked: 3 },
    });
  });

  it('404 for an unknown organization', async () => {
    const { app } = await buildApp(null);

    expect((await post(app, 'revoke-all-codes', { reason: 'phishing campaign' })).statusCode).toBe(404);
  });
});

describe('platform organization', () => {
  it('cannot be suspended (it owns the FIRST_PARTY OIDC clients and the OP keys)', async () => {
    const { app, updates } = await buildApp({ id: 'org_1', suspendedAt: null, suspendedReason: null, slug: 'qrauth-platform' } as never);

    const res = await post(app, 'suspend', { reason: 'testing the guard' });

    expect(res.statusCode).toBe(409);
    expect(updates).toEqual([]);
  });
});
