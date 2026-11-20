import { describe, it, expect, beforeAll, vi } from 'vitest';

vi.mock('../../lib/cache.js', () => ({ cacheDel: vi.fn(async () => undefined), redis: {} }));
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * Scan analytics endpoints (ADR-0006) with a mocked database: plan gating
 * (D6), organisation scoping of the code lookup, range validation, the
 * streamed CSV, and the heatmap grouped in SQL.
 */

beforeAll(() => {
  process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
  process.env.REDIS_URL = 'redis://localhost:6379';
  process.env.JWT_SECRET = 'a'.repeat(32);
  process.env.ANIMATED_QR_SECRET = 'a'.repeat(64);
});

const ORG = 'org_1';

interface Mocks {
  plan: string;
  codes: Array<{ id: string; token: string; label: string | null; organizationId: string }>;
  scanRows: Array<Record<string, unknown>>;
  qrFindFirst: Array<Record<string, unknown>>;
  scanFindMany: Array<Record<string, unknown>>;
  raw: number;
}

async function buildApp(plan = 'PRO') {
  const m: Mocks = {
    plan,
    codes: [
      { id: 'qr_own', token: 'own', label: 'Own code', organizationId: ORG },
      { id: 'qr_other', token: 'other', label: 'Other org', organizationId: 'org_2' },
    ],
    scanRows: [
      {
        id: 's1',
        createdAt: new Date('2026-06-14T10:00:00Z'),
        country: 'GR',
        region: 'Attica',
        city: 'Athens',
        deviceType: 'mobile',
        os: 'iOS',
        browser: 'Safari',
        trustScore: 100,
        qrCode: { token: 'own', label: '=cmd' },
      },
    ],
    qrFindFirst: [],
    scanFindMany: [],
    raw: 0,
  };
  const neutral = { count: async () => 0, findMany: async () => [], aggregate: async () => ({ _avg: { trustScore: null } }) };
  const prisma = new Proxy(
    {
      organization: { findUnique: async () => ({ plan: m.plan }) },
      qRCode: {
        count: async () => 0,
        findFirst: async (args: { where: { token: string; organizationId: string } }) => {
          m.qrFindFirst.push(args.where);
          return m.codes.find((c) => c.token === args.where.token && c.organizationId === args.where.organizationId) ?? null;
        },
      },
      scan: {
        count: async () => 0,
        aggregate: async () => ({ _avg: { trustScore: null } }),
        findMany: async (args: { where: Record<string, unknown>; take?: number }) => {
          m.scanFindMany.push(args.where);
          return args.take && m.scanFindMany.length === 1 ? m.scanRows : [];
        },
      },
      $queryRaw: async () => {
        m.raw++;
        return [];
      },
    } as Record<string, unknown>,
    { get: (target, prop: string) => target[prop] ?? neutral },
  );
  const app = Fastify({ logger: false });
  app.decorate('prisma', prisma as never);
  app.decorate('authenticate', async (req: never) => {
    (req as unknown as { user: unknown }).user = { id: 'u_1', orgId: ORG, role: 'VIEWER', email: 'v@example.com' };
  });
  const { default: analyticsRoutes } = await import('../analytics.js');
  await app.register(analyticsRoutes, { prefix: '/api/v1/analytics' });
  await app.ready();
  return { app: app as FastifyInstance, m };
}

const PAID = [
  '/timeseries',
  '/timeseries?granularity=week',
  '/breakdown?dimension=country',
  '/qrcodes/own',
  '/export.csv',
];

describe('plan gating (D6)', () => {
  it.each(PAID)('FREE: %s is 403 analytics-plan-required', async (url) => {
    const { app } = await buildApp('FREE');
    const res = await app.inject({ method: 'GET', url: `/api/v1/analytics${url}` });
    expect(res.statusCode).toBe(403);
    expect(res.json()).toMatchObject({ code: 'analytics-plan-required' });
  });

  it.each(['PRO', 'BUSINESS', 'ENTERPRISE'])('%s: every paid endpoint answers 200', async (plan) => {
    const { app } = await buildApp(plan);
    for (const url of PAID) {
      const res = await app.inject({ method: 'GET', url: `/api/v1/analytics${url}` });
      expect(res.statusCode, url).toBe(200);
    }
  });

  it('FREE: the summary, with the 7-day daily totals, stays available', async () => {
    const { app } = await buildApp('FREE');
    const res = await app.inject({ method: 'GET', url: '/api/v1/analytics/summary' });
    expect(res.statusCode).toBe(200);
    const days = res.json().scansDaily7d as Array<{ date: string; total: number }>;
    expect(days).toHaveLength(7);
    expect(days.every((d) => /^\d{4}-\d{2}-\d{2}$/.test(d.date) && d.total === 0)).toBe(true);
  });
});

describe('tenant isolation', () => {
  it.each(['/timeseries?token=other', '/breakdown?dimension=os&token=other', '/qrcodes/other', '/export.csv?token=other'])(
    "another organisation's code is 404: %s",
    async (url) => {
      const { app, m } = await buildApp();
      const res = await app.inject({ method: 'GET', url: `/api/v1/analytics${url}` });
      expect(res.statusCode).toBe(404);
      expect(m.qrFindFirst).toEqual([{ token: 'other', organizationId: ORG }]);
      expect(m.raw).toBe(0);
    },
  );

  it('the CSV export reads only the organisation and the code asked for', async () => {
    const { app, m } = await buildApp();
    await app.inject({ method: 'GET', url: '/api/v1/analytics/export.csv?token=own' });
    expect(m.scanFindMany[0]).toMatchObject({ qrCode: { organizationId: ORG }, qrCodeId: 'qr_own' });
  });
});

describe('validation', () => {
  it.each([
    ['/timeseries?granularity=month', 400],
    ['/timeseries?from=2020-01-01', 400],
    ['/timeseries?from=2026-13-01', 400],
    ['/breakdown', 400],
    ['/breakdown?dimension=ip', 400],
    ['/timeseries?unknown=1', 400],
  ])('%s -> %i', async (url, status) => {
    const { app } = await buildApp();
    const res = await app.inject({ method: 'GET', url: `/api/v1/analytics${url}` });
    expect(res.statusCode).toBe(status);
  });
});

describe('responses', () => {
  it('time series: one point per day of the range, totals summed', async () => {
    const { app } = await buildApp();
    const res = await app.inject({ method: 'GET', url: '/api/v1/analytics/timeseries' });
    const body = res.json();
    expect(body.points).toHaveLength(30);
    expect(body).toMatchObject({ granularity: 'day', total: 0, unique: 0 });
  });

  it('CSV: streamed attachment, header line, formula cells neutralised, no IP hash', async () => {
    const { app } = await buildApp();
    const res = await app.inject({ method: 'GET', url: '/api/v1/analytics/export.csv?from=2026-06-01&to=2026-06-14' });
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toBe('text/csv; charset=utf-8');
    expect(res.headers['content-disposition']).toBe('attachment; filename="qrauth-scans-2026-06-01-to-2026-06-14.csv"');
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.body.split('\r\n')).toEqual([
      'scanned_at,code,label,country,region,city,device_type,os,browser,trust_score',
      "2026-06-14T10:00:00.000Z,own,'=cmd,GR,Attica,Athens,mobile,iOS,Safari,100",
      '',
    ]);
  });

  it('heatmap: grouped in SQL, the scans are never loaded', async () => {
    const { app, m } = await buildApp('FREE');
    const res = await app.inject({ method: 'GET', url: '/api/v1/analytics/heatmap' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ data: [], total: 0 });
    expect(m.raw).toBe(1);
    expect(m.scanFindMany).toEqual([]);
  });
});
