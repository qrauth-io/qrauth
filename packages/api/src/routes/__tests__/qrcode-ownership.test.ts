import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * Pins today's behaviour of GET, PATCH and DELETE /api/v1/qrcodes/:token for
 * another organization's code: 403 "You do not own this QR code." (the image
 * route answers 404 instead), and nothing is changed.
 */

process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

vi.mock('../../lib/cache.js', () => ({
  cacheGet: vi.fn(async () => null),
  cacheSet: vi.fn(async () => undefined),
  cacheDel: vi.fn(async () => undefined),
}));
vi.mock('../../services/hybrid-signing.js', () => ({ HybridSigningService: class {} }));
vi.mock('../../services/mac.js', () => ({ MacService: class {} }));
vi.mock('../../services/domain.js', () => ({ DomainService: class {} }));

const OTHER_ORG_ROW = {
  id: 'qr_b1',
  token: 'b1',
  organizationId: 'org_2',
  status: 'ACTIVE',
  destinationUrl: 'https://example.com',
  label: 'Theirs',
};

const prisma = {
  qRCode: {
    findUnique: vi.fn(async ({ where }: { where: { token: string } }) => (where.token === 'b1' ? OTHER_ORG_ROW : null)),
    update: vi.fn(async () => OTHER_ORG_ROW),
    delete: vi.fn(async () => OTHER_ORG_ROW),
  },
  user: { findUnique: vi.fn(async () => ({ emailVerified: true })) },
};

let app: FastifyInstance;

beforeAll(async () => {
  app = Fastify();
  app.decorate('prisma', prisma as never);
  app.decorate('signingService', {} as never);
  app.decorate('batchSigner', {} as never);
  app.decorateRequest('user', null);
  app.decorate('authenticate', async (request: { user: unknown }) => {
    request.user = { id: 'user_1', orgId: 'org_1', role: 'OWNER', email: 'o@example.com' };
  });
  const { default: qrCodeRoutes } = await import('../qrcodes.js');
  await app.register(qrCodeRoutes, { prefix: '/api/v1/qrcodes' });
  await app.ready();
});

afterAll(async () => {
  await app.close();
});

beforeEach(() => {
  prisma.qRCode.update.mockClear();
  prisma.qRCode.delete.mockClear();
});

describe("another organization's code", () => {
  it.each<[string, 'GET' | 'PATCH' | 'DELETE', Record<string, unknown> | undefined]>([
    ['GET /:token', 'GET', undefined],
    ['PATCH /:token', 'PATCH', { label: 'Mine now' }],
    ['DELETE /:token', 'DELETE', undefined],
  ])('%s answers 403 and changes nothing', async (_label, method, payload) => {
    const res = await app.inject({
      method,
      url: '/api/v1/qrcodes/b1',
      ...(payload ? { headers: { 'content-type': 'application/json' }, payload: JSON.stringify(payload) } : {}),
    });

    expect(res.statusCode).toBe(403);
    expect(res.json()).toEqual({ statusCode: 403, error: 'Forbidden', message: 'You do not own this QR code.' });
    expect(prisma.qRCode.update).not.toHaveBeenCalled();
    expect(prisma.qRCode.delete).not.toHaveBeenCalled();
  });

  it.each(['GET', 'PATCH', 'DELETE'] as const)('%s on a missing code answers 404', async (method) => {
    const res = await app.inject({
      method,
      url: '/api/v1/qrcodes/zz',
      ...(method === 'PATCH' ? { headers: { 'content-type': 'application/json' }, payload: '{"label":"x"}' } : {}),
    });
    expect(res.statusCode).toBe(404);
  });
});
