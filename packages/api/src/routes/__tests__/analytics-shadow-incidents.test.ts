import { describe, it, expect, beforeAll, vi } from 'vitest';

vi.mock('../../lib/cache.js', () => ({ cacheDel: vi.fn(async () => undefined), redis: {} }));
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * Customer-facing incident routes never show shadow incidents (from fraud
 * rules still under superadmin review): every FraudIncident query they make
 * carries `shadow: false`.
 */

beforeAll(() => {
  process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
  process.env.REDIS_URL = 'redis://localhost:6379';
  process.env.JWT_SECRET = 'a'.repeat(32);
  process.env.ANIMATED_QR_SECRET = 'a'.repeat(64);
});

type Call = { method: string; args: { where?: Record<string, unknown> } };

async function buildApp() {
  const incidentCalls: Call[] = [];
  const record = (method: string, result: unknown) => async (args: Call['args']) => {
    incidentCalls.push({ method, args });
    return result;
  };
  // Every other model answers with neutral values; only incident queries matter here.
  const neutral = {
    count: async () => 0,
    findMany: async () => [],
    aggregate: async () => ({ _avg: { trustScore: null } }),
  };
  const prisma = new Proxy(
    {
      fraudIncident: {
        findMany: record('findMany', []),
        findFirst: record('findFirst', null),
        count: record('count', 0),
        groupBy: record('groupBy', []),
        update: record('update', {}),
      },
    } as Record<string, unknown>,
    { get: (target, prop: string) => target[prop] ?? neutral },
  );
  const app = Fastify({ logger: false });
  app.decorate('prisma', prisma as never);
  app.decorate('authenticate', async (req: never) => {
    (req as unknown as { user: unknown }).user = { id: 'u_1', orgId: 'org_1', role: 'OWNER', email: 'o@example.com' };
  });
  const { default: analyticsRoutes } = await import('../analytics.js');
  await app.register(analyticsRoutes, { prefix: '/api/v1/analytics' });
  await app.ready();
  return { app, incidentCalls };
}

async function callsFor(method: 'GET' | 'POST', url: string): Promise<Call[]> {
  const { app, incidentCalls } = await buildApp();
  const res = await (app as FastifyInstance).inject({ method, url: `/api/v1/analytics${url}` });
  expect(res.statusCode).toBeLessThan(500);
  return incidentCalls;
}

describe('customer incident routes exclude shadow incidents', () => {
  it.each([
    ['GET', '/fraud'],
    ['GET', '/fraud?severity=HIGH&resolved=false'],
    ['GET', '/fraud/inc_1'],
    ['POST', '/fraud/inc_1/acknowledge'],
    ['POST', '/fraud/inc_1/resolve'],
    ['GET', '/summary'],
  ] as const)('%s %s', async (method, url) => {
    const calls = await callsFor(method, url);

    expect(calls.length).toBeGreaterThan(0);
    for (const call of calls) {
      expect(call.args.where, `${call.method} ${JSON.stringify(call.args.where)}`).toMatchObject({ shadow: false });
    }
  });

  it('GET /fraud filters list, total, stat counts and type breakdown', async () => {
    const calls = await callsFor('GET', '/fraud');

    expect(calls.map((c) => c.method).sort()).toEqual(['count', 'count', 'count', 'count', 'findMany', 'groupBy']);
  });
});
