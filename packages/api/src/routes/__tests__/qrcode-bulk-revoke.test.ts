import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * POST /api/v1/qrcodes/bulk-revoke: OWNER/ADMIN only, 1–100 tokens, 207 with
 * per-token results, scoped to the caller's organization. The database is a
 * small in-memory table holding codes of two organizations.
 */

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

const cacheDel = vi.hoisted(() => vi.fn(async () => undefined));
vi.mock('../../lib/cache.js', () => ({
  cacheGet: vi.fn(async () => null),
  cacheSet: vi.fn(async () => undefined),
  cacheDel,
}));
vi.mock('../../services/hybrid-signing.js', () => ({ HybridSigningService: class {} }));
vi.mock('../../services/mac.js', () => ({ MacService: class {} }));
vi.mock('../../services/domain.js', () => ({ DomainService: class {} }));

type Row = { token: string; organizationId: string; status: string };
let table: Row[] = [];
let role = 'OWNER';

const prisma = {
  qRCode: {
    findMany: vi.fn(async ({ where }: { where: { organizationId: string; token: { in: string[] } } }) =>
      table
        .filter((r) => r.organizationId === where.organizationId && where.token.in.includes(r.token))
        .map(({ token, status }) => ({ token, status }))),
    updateMany: vi.fn(async ({ where }: { where: { organizationId: string; token: { in: string[] } } }) => {
      const hit = table.filter((r) => r.organizationId === where.organizationId && where.token.in.includes(r.token) && r.status !== 'REVOKED');
      hit.forEach((r) => { r.status = 'REVOKED'; });
      return { count: hit.length };
    }),
  },
};

let app: FastifyInstance;

const bulkRevoke = (payload: unknown) =>
  app.inject({
    method: 'POST',
    url: '/api/v1/qrcodes/bulk-revoke',
    headers: { 'content-type': 'application/json' },
    payload: JSON.stringify(payload),
  });

beforeAll(async () => {
  app = Fastify();
  app.decorate('prisma', prisma as never);
  app.decorate('signingService', {} as never);
  app.decorate('batchSigner', {} as never);
  app.decorateRequest('user', null);
  app.decorate('authenticate', async (request: { user: unknown }) => {
    request.user = { id: 'user_1', orgId: 'org_1', role, email: 'o@example.com' };
  });
  const { default: qrCodeRoutes } = await import('../qrcodes.js');
  await app.register(qrCodeRoutes, { prefix: '/api/v1/qrcodes' });
  await app.ready();
});

afterAll(async () => {
  await app.close();
});

beforeEach(() => {
  role = 'OWNER';
  cacheDel.mockClear();
  table = [
    { token: 'a1', organizationId: 'org_1', status: 'ACTIVE' },
    { token: 'a2', organizationId: 'org_1', status: 'REVOKED' },
    { token: 'b1', organizationId: 'org_2', status: 'ACTIVE' },
  ];
});

describe('POST /qrcodes/bulk-revoke', () => {
  it('207 with per-token results; another org\'s token is not_found and untouched', async () => {
    const res = await bulkRevoke({ tokens: ['a1', 'a2', 'b1', 'nope'] });

    expect(res.statusCode).toBe(207);
    expect(res.json()).toEqual({
      results: [
        { token: 'a1', status: 'revoked' },
        { token: 'a2', status: 'already_revoked' },
        { token: 'b1', status: 'not_found' },
        { token: 'nope', status: 'not_found' },
      ],
      summary: { revoked: 1, already_revoked: 1, not_found: 2 },
    });
    expect(table.find((r) => r.token === 'b1')!.status).toBe('ACTIVE');
    expect(cacheDel).toHaveBeenCalledWith('verify:a1');
    expect(cacheDel).toHaveBeenCalledTimes(1);
  });

  it('ADMIN may bulk revoke', async () => {
    role = 'ADMIN';

    expect((await bulkRevoke({ tokens: ['a1'] })).statusCode).toBe(207);
  });

  it.each(['MANAGER', 'MEMBER', 'VIEWER'])('%s is refused (403)', async (r) => {
    role = r;

    const res = await bulkRevoke({ tokens: ['a1'] });

    expect(res.statusCode).toBe(403);
    expect(table.find((row) => row.token === 'a1')!.status).toBe('ACTIVE');
  });

  it.each([
    ['no tokens', { tokens: [] }],
    ['101 tokens', { tokens: Array.from({ length: 101 }, (_, i) => `t${i}`) }],
    ['an empty token', { tokens: [''] }],
    ['unknown fields', { tokens: ['a1'], all: true }],
  ])('400 for %s', async (_label, payload) => {
    expect((await bulkRevoke(payload)).statusCode).toBe(400);
  });

  it('accepts exactly 100 tokens', async () => {
    const res = await bulkRevoke({ tokens: Array.from({ length: 100 }, (_, i) => `t${i}`) });

    expect(res.statusCode).toBe(207);
    expect(res.json().summary.not_found).toBe(100);
  });
});
