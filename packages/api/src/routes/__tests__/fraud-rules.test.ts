import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';

const cacheDel = vi.fn(async () => undefined);
vi.mock('../../lib/cache.js', () => ({ cacheDel: (...a: unknown[]) => cacheDel(...(a as [])), redis: {} }));
import Fastify, { type FastifyInstance } from 'fastify';

/** Superadmin fraud-rule routes: list, PATCH, shadow summary, promote, demote (stubbed auth and prisma). */

beforeAll(() => {
  process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
  process.env.REDIS_URL = 'redis://localhost:6379';
  process.env.JWT_SECRET = 'a'.repeat(32);
  process.env.ANIMATED_QR_SECRET = 'a'.repeat(64);
  process.env.ADMIN_EMAILS = 'admin@qrauth.io';
});

beforeEach(() => cacheDel.mockClear());

const ADMIN = 'admin@qrauth.io';
type Rule = { id: string; name: string; status: string; enabled: boolean; source: string; version: number };

async function buildApp(rules: Rule[], opts: { platformOrg?: boolean } = {}) {
  const updates: Array<{ where: Record<string, unknown>; data: Record<string, unknown> }> = [];
  const audits: Array<Record<string, unknown>> = [];
  const incidentQueries: Array<Record<string, unknown>> = [];
  const prisma = {
    user: { findUnique: async () => ({ email: ADMIN, emailVerified: true }) },
    organization: {
      findUnique: async () => (opts.platformOrg === false ? null : { id: 'org_qrauth_platform' }),
    },
    fraudRule: {
      findMany: async () => rules,
      findUnique: async ({ where }: { where: { id: string } }) => rules.find((r) => r.id === where.id) ?? null,
      update: async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
        updates.push({ where, data });
        return { ...rules.find((r) => r.id === where.id), ...data };
      },
      updateMany: async ({ where, data }: { where: { id: string; status: string }; data: Record<string, unknown> }) => {
        updates.push({ where, data });
        const hit = rules.find((r) => r.id === where.id && r.status === where.status);
        return { count: hit ? 1 : 0 };
      },
    },
    fraudIncident: {
      count: async (args: Record<string, unknown>) => { incidentQueries.push(args); return 7; },
      aggregate: async (args: Record<string, unknown>) => {
        incidentQueries.push(args);
        return { _min: { createdAt: new Date('2026-10-20T00:00:00Z') }, _max: { createdAt: new Date('2026-10-28T00:00:00Z') } };
      },
      findMany: async (args: Record<string, unknown>) => {
        incidentQueries.push(args);
        return [{ id: 'inc_1', createdAt: new Date(), type: 'PATTERN_ANOMALY', severity: 'LOW', details: { features: { isBot: true } }, qrCode: { token: 't', organizationId: 'o' } }];
      },
    },
    auditLog: { create: async ({ data }: { data: Record<string, unknown> }) => { audits.push(data); } },
  };
  const app = Fastify({ logger: false });
  app.decorate('prisma', prisma as never);
  app.decorate('authenticate', async (req: never) => {
    const request = req as unknown as { headers: Record<string, string>; user?: unknown };
    request.user = { id: 'u_admin', orgId: 'o_admin', role: 'OWNER', email: request.headers['x-test-email'] ?? ADMIN };
  });
  const { default: fraudRuleRoutes } = await import('../fraud-rules.js');
  await app.register(fraudRuleRoutes, { prefix: '/api/v1/analytics' });
  await app.ready();
  return { app, updates, audits, incidentQueries };
}

const RULES: Rule[] = [
  { id: 'shadow1', name: 'trial', status: 'SHADOW', enabled: false, source: 'agent', version: 1 },
  { id: 'active1', name: 'live', status: 'ACTIVE', enabled: true, source: 'system', version: 3 },
  { id: 'off1', name: 'off', status: 'DISABLED', enabled: false, source: 'agent', version: 2 },
];

const req = (app: FastifyInstance, method: 'GET' | 'POST' | 'PATCH', url: string, body?: unknown, email = ADMIN) =>
  app.inject({
    method,
    url: `/api/v1/analytics${url}`,
    headers: { 'x-test-email': email, ...(body ? { 'content-type': 'application/json' } : {}) },
    ...(body ? { payload: JSON.stringify(body) } : {}),
  });

describe('superadmin guard', () => {
  it.each([
    ['GET', '/fraud-rules'],
    ['GET', '/fraud-rules/shadow1/shadow-summary'],
    ['POST', '/fraud-rules/shadow1/promote'],
    ['POST', '/fraud-rules/active1/demote'],
    ['PATCH', '/fraud-rules/active1'],
  ] as const)('%s %s refuses a non-superadmin with 403', async (method, url) => {
    const { app, updates, audits } = await buildApp(RULES);

    const res = await req(app, method, url, method === 'PATCH' ? { enabled: false } : undefined, 'member@example.com');

    expect(res.statusCode).toBe(403);
    expect(updates).toHaveLength(0);
    expect(audits).toHaveLength(0);
    expect(cacheDel).not.toHaveBeenCalled();
  });
});

describe('GET /fraud-rules/:id/shadow-summary', () => {
  it('returns count, first/last seen and up to 5 samples of shadow incidents for the rule', async () => {
    const { app, incidentQueries } = await buildApp(RULES);

    const res = await req(app, 'GET', '/fraud-rules/shadow1/shadow-summary');

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.rule).toMatchObject({ id: 'shadow1', status: 'SHADOW' });
    expect(body.shadow).toMatchObject({
      count: 7,
      firstSeen: '2026-10-20T00:00:00.000Z',
      lastSeen: '2026-10-28T00:00:00.000Z',
    });
    expect(body.shadow.samples[0]).toMatchObject({ id: 'inc_1', features: { isBot: true }, qrCodeToken: 't' });
    const where = { shadow: true, details: { path: ['ruleId'], equals: 'shadow1' } };
    for (const q of incidentQueries) expect(q.where).toEqual(where);
    expect(incidentQueries.find((q) => 'take' in q)?.take).toBe(5);
  });

  it('404s for an unknown rule', async () => {
    const { app } = await buildApp(RULES);
    expect((await req(app, 'GET', '/fraud-rules/nope/shadow-summary')).statusCode).toBe(404);
  });
});

describe('POST /fraud-rules/:id/promote', () => {
  it('moves SHADOW to ACTIVE, keeps enabled consistent, audits and busts the rule cache', async () => {
    const { app, updates, audits } = await buildApp(RULES);

    const res = await req(app, 'POST', '/fraud-rules/shadow1/promote');

    expect(res.statusCode).toBe(200);
    expect(updates).toEqual([
      {
        where: { id: 'shadow1', status: 'SHADOW' },
        data: { status: 'ACTIVE', enabled: true, version: { increment: 1 } },
      },
    ]);
    expect(audits).toEqual([
      expect.objectContaining({
        organizationId: 'org_qrauth_platform',
        userId: 'u_admin',
        action: 'admin.fraudRule.promote',
        resource: 'FraudRule',
        resourceId: 'shadow1',
        metadata: expect.objectContaining({ name: 'trial', from: 'SHADOW', to: 'ACTIVE' }),
      }),
    ]);
    expect(cacheDel).toHaveBeenCalledWith('fraud_rules:active');
  });

  it.each(['active1', 'off1'])('refuses %s (not SHADOW) with 409 and changes nothing', async (id) => {
    const { app, updates, audits } = await buildApp(RULES);

    const res = await req(app, 'POST', `/fraud-rules/${id}/promote`);

    expect(res.statusCode).toBe(409);
    expect(updates).toHaveLength(0);
    expect(audits).toHaveLength(0);
    expect(cacheDel).not.toHaveBeenCalled();
  });

  it('404s for an unknown rule', async () => {
    const { app } = await buildApp(RULES);
    expect((await req(app, 'POST', '/fraud-rules/nope/promote')).statusCode).toBe(404);
  });

  it('falls back to the acting admin org for the audit row when the platform org is absent', async () => {
    const { app, audits } = await buildApp(RULES, { platformOrg: false });

    await req(app, 'POST', '/fraud-rules/shadow1/promote');

    expect(audits[0].organizationId).toBe('o_admin');
  });
});

describe('POST /fraud-rules/:id/demote', () => {
  it('moves ACTIVE to SHADOW, audits and busts the cache', async () => {
    const { app, updates, audits } = await buildApp(RULES);

    const res = await req(app, 'POST', '/fraud-rules/active1/demote');

    expect(res.statusCode).toBe(200);
    expect(updates[0]).toEqual({
      where: { id: 'active1', status: 'ACTIVE' },
      data: { status: 'SHADOW', enabled: false, version: { increment: 1 } },
    });
    expect(audits[0]).toMatchObject({ action: 'admin.fraudRule.demote', metadata: { from: 'ACTIVE', to: 'SHADOW' } });
    expect(cacheDel).toHaveBeenCalledWith('fraud_rules:active');
  });

  it('refuses a non-ACTIVE rule with 409', async () => {
    const { app } = await buildApp(RULES);
    expect((await req(app, 'POST', '/fraud-rules/shadow1/demote')).statusCode).toBe(409);
  });
});

describe('PATCH /fraud-rules/:id', () => {
  it.each([
    [{ enabled: false }, { status: 'DISABLED', enabled: false }],
    [{ enabled: true }, { status: 'ACTIVE', enabled: true }],
    [{ status: 'SHADOW' }, { status: 'SHADOW', enabled: false }],
    [{ status: 'ACTIVE' }, { status: 'ACTIVE', enabled: true }],
  ])('maps %j to %j', async (body, expected) => {
    const { app, updates } = await buildApp(RULES);

    const res = await req(app, 'PATCH', '/fraud-rules/off1', body);

    expect(res.statusCode).toBe(200);
    expect(updates[0].data).toMatchObject({ ...expected, version: { increment: 1 } });
    expect(cacheDel).toHaveBeenCalledWith('fraud_rules:active');
  });

  it('updates priority without touching status', async () => {
    const { app, updates } = await buildApp(RULES);

    await req(app, 'PATCH', '/fraud-rules/active1', { priority: 5 });

    expect(updates[0].data).toEqual({ priority: 5, version: { increment: 1 } });
  });

  it('audits a status change', async () => {
    const { app, audits } = await buildApp(RULES);

    await req(app, 'PATCH', '/fraud-rules/active1', { enabled: false });

    expect(audits[0]).toMatchObject({
      action: 'admin.fraudRule.update',
      resourceId: 'active1',
      metadata: { from: 'ACTIVE', to: 'DISABLED' },
    });
  });

  it.each([
    [{ enabled: true, status: 'DISABLED' }],
    [{ status: 'BOGUS' }],
    [{ priority: 'high' }],
  ])('rejects %j with 400', async (body) => {
    const { app, updates } = await buildApp(RULES);

    expect((await req(app, 'PATCH', '/fraud-rules/active1', body)).statusCode).toBe(400);
    expect(updates).toHaveLength(0);
  });

  it('404s for an unknown rule', async () => {
    const { app } = await buildApp(RULES);
    expect((await req(app, 'PATCH', '/fraud-rules/nope', { enabled: false })).statusCode).toBe(404);
  });
});
