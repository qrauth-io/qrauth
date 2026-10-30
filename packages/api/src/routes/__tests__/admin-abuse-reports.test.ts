import { describe, it, expect, beforeAll, vi } from 'vitest';

vi.mock('../../lib/cache.js', () => ({ cacheDel: vi.fn(async () => undefined), redis: {} }));
import Fastify, { type FastifyInstance } from 'fastify';

/** Superadmin abuse-report review routes (stubbed auth and prisma). */

beforeAll(() => {
  process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
  process.env.REDIS_URL = 'redis://localhost:6379';
  process.env.JWT_SECRET = 'a'.repeat(32);
  process.env.ANIMATED_QR_SECRET = 'a'.repeat(64);
  process.env.ADMIN_EMAILS = 'admin@qrauth.io';
});

const ADMIN = 'admin@qrauth.io';

type Report = { id: string; token: string; organizationId: string; reason: string; status: string };

async function buildApp(reports: Report[], flaggedAt: Date | null = new Date('2026-10-27T10:00:00Z')) {
  const findManyCalls: Array<Record<string, unknown>> = [];
  const updates: Array<Record<string, unknown>> = [];
  const audits: Array<Record<string, unknown>> = [];
  const prisma = {
    user: { findUnique: async () => ({ email: ADMIN, emailVerified: true }) },
    abuseReport: {
      findMany: async (args: Record<string, unknown>) => {
        findManyCalls.push(args);
        const where = args.where as { status?: string };
        return reports.filter((r) => !where.status || r.status === where.status);
      },
      count: async ({ where }: { where: { status?: string } }) =>
        reports.filter((r) => !where.status || r.status === where.status).length,
      findUnique: async ({ where }: { where: { id: string } }) => reports.find((r) => r.id === where.id) ?? null,
      update: async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
        updates.push(data);
        return { ...reports.find((r) => r.id === where.id), ...data };
      },
    },
    qRCode: {
      findUnique: async ({ where }: { where: { token: string } }) =>
        where.token === 'nope'
          ? null
          : {
              token: where.token,
              status: 'ACTIVE',
              destinationUrl: 'https://x.example',
              createdAt: new Date(),
              organizationId: 'org_1',
              destinationFlaggedAt: flaggedAt,
              destinationFlagReason: flaggedAt ? 'MALWARE' : null,
              organization: { id: 'org_1', name: 'Acme', slug: 'acme', suspendedAt: null },
            },
      update: async ({ data }: { data: Record<string, unknown> }) => { updates.push(data); return {}; },
    },
    auditLog: { create: async ({ data }: { data: Record<string, unknown> }) => { audits.push(data); } },
  };
  const app = Fastify({ logger: false });
  app.decorate('prisma', prisma as never);
  app.decorate('authenticate', async (req: never) => {
    const request = req as unknown as { headers: Record<string, string>; user?: unknown };
    request.user = { id: 'u_admin', orgId: 'o_admin', role: 'OWNER', email: request.headers['x-test-email'] ?? ADMIN };
  });
  const { default: adminAbuseRoutes } = await import('../admin-abuse.js');
  await app.register(adminAbuseRoutes, { prefix: '/api/v1/admin' });
  await app.ready();
  return { app, findManyCalls, updates, audits };
}

const REPORTS: Report[] = [
  { id: 'r1', token: 'tok_1', organizationId: 'org_1', reason: 'PHISHING', status: 'OPEN' },
  { id: 'r2', token: 'tok_2', organizationId: 'org_2', reason: 'SPAM', status: 'DISMISSED' },
];

const req = (app: FastifyInstance, method: 'GET' | 'POST', url: string, body?: unknown, email = ADMIN) =>
  app.inject({
    method,
    url: `/api/v1/admin${url}`,
    headers: { 'x-test-email': email, ...(body ? { 'content-type': 'application/json' } : {}) },
    ...(body ? { payload: JSON.stringify(body) } : {}),
  });

describe('admin abuse reports', () => {
  it('lists with a status filter and pagination', async () => {
    const { app, findManyCalls } = await buildApp(REPORTS);

    const res = await req(app, 'GET', '/abuse-reports?status=OPEN&page=2&pageSize=10');

    expect(res.statusCode).toBe(200);
    expect(res.json().data.map((r: Report) => r.id)).toEqual(['r1']);
    expect(res.json().pagination).toMatchObject({ total: 1, page: 2, pageSize: 10 });
    expect(findManyCalls[0]).toMatchObject({ where: { status: 'OPEN' }, skip: 10, take: 10 });
  });

  it('rejects an unknown status filter', async () => {
    const { app } = await buildApp(REPORTS);

    expect((await req(app, 'GET', '/abuse-reports?status=WHATEVER')).statusCode).toBe(400);
  });

  it('refuses a non-admin', async () => {
    const { app } = await buildApp(REPORTS);

    expect((await req(app, 'GET', '/abuse-reports', undefined, 'member@example.com')).statusCode).toBe(403);
  });

  it('gets one report with its code and organization, 404 otherwise', async () => {
    const { app } = await buildApp(REPORTS);

    const res = await req(app, 'GET', '/abuse-reports/r1');
    expect(res.statusCode).toBe(200);
    expect(res.json().qrCode.organization.name).toBe('Acme');
    expect((await req(app, 'GET', '/abuse-reports/nope')).statusCode).toBe(404);
  });

  it.each([
    ['resolve', 'RESOLVED', 'admin.abuseReport.resolve'],
    ['dismiss', 'DISMISSED', 'admin.abuseReport.dismiss'],
  ])('%s sets the status, who and why, and writes an audit entry', async (path, status, action) => {
    const { app, updates, audits } = await buildApp(REPORTS);

    const res = await req(app, 'POST', `/abuse-reports/r1/${path}`, { note: 'checked the destination' });

    expect(res.statusCode).toBe(200);
    expect(updates[0]).toMatchObject({ status, resolvedBy: ADMIN, resolutionNote: 'checked the destination' });
    expect(updates[0].resolvedAt).toBeInstanceOf(Date);
    expect(audits[0]).toMatchObject({ action, organizationId: 'org_1', resourceId: 'r1' });
  });

  it('requires a note', async () => {
    const { app, updates } = await buildApp(REPORTS);

    expect((await req(app, 'POST', '/abuse-reports/r1/resolve', {})).statusCode).toBe(400);
    expect(updates).toEqual([]);
  });

  it('409 when the report is no longer open', async () => {
    const { app, updates } = await buildApp(REPORTS);

    expect((await req(app, 'POST', '/abuse-reports/r2/resolve', { note: 'again' })).statusCode).toBe(409);
    expect(updates).toEqual([]);
  });
});

describe('POST /admin/qrcodes/:token/clear-destination-flag', () => {
  it('clears the flag and writes an audit entry with the note and previous reason', async () => {
    const { app, updates, audits } = await buildApp(REPORTS);

    const res = await req(app, 'POST', '/qrcodes/tok_1/clear-destination-flag', { note: 'false positive, checked manually' });

    expect(res.statusCode).toBe(200);
    expect(updates[0]).toEqual({ destinationFlaggedAt: null, destinationFlagReason: null });
    expect(audits[0]).toMatchObject({
      action: 'admin.qrcode.clearDestinationFlag',
      organizationId: 'org_1',
      resourceId: 'tok_1',
      metadata: expect.objectContaining({ previousReason: 'MALWARE', note: 'false positive, checked manually' }),
    });
  });

  it('409 when the code is not flagged, 404 when it does not exist, 400 without a note', async () => {
    const notFlagged = await buildApp(REPORTS, null);
    expect((await req(notFlagged.app, 'POST', '/qrcodes/tok_1/clear-destination-flag', { note: 'x y z' })).statusCode).toBe(409);

    const { app } = await buildApp(REPORTS);
    expect((await req(app, 'POST', '/qrcodes/nope/clear-destination-flag', { note: 'x y z' })).statusCode).toBe(404);
    expect((await req(app, 'POST', '/qrcodes/tok_1/clear-destination-flag', {})).statusCode).toBe(400);
  });

  it('refuses a non-admin', async () => {
    const { app, updates } = await buildApp(REPORTS);

    const res = await req(app, 'POST', '/qrcodes/tok_1/clear-destination-flag', { note: 'x y z' }, 'member@example.com');

    expect(res.statusCode).toBe(403);
    expect(updates).toEqual([]);
  });
});
