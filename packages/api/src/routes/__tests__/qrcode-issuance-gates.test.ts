import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * Gates in front of QR issuance and editing. Each test sets the database
 * state it needs; signing and the domain check are mocked out, so a request
 * that passes every gate fails later with a 5xx we do not assert on. The
 * assertions are about which gate answers, and with what.
 */

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

vi.mock('../../services/domain.js', () => ({
  DomainService: class {
    async checkUrlAgainstVerifiedDomains() {
      return { isSuspicious: false, warnings: [] };
    }
    extractDomain(url: string) {
      return new URL(url).hostname;
    }
  },
}));
vi.mock('../../services/hybrid-signing.js', () => ({ HybridSigningService: class {} }));
vi.mock('../../services/mac.js', () => ({ MacService: class {} }));
vi.mock('../../lib/cache.js', () => ({
  cacheGet: vi.fn(async () => null),
  cacheSet: vi.fn(async () => undefined),
  cacheDel: vi.fn(async () => undefined),
}));

const db = {
  qrCount: (): Promise<number> => Promise.resolve(0),
  userVerified: true,
  verifiedOwner: true,
  principal: { id: 'user_1', orgId: 'org_1', role: 'OWNER', email: 'owner@example.com' },
};

const QR_ROW = {
  id: 'qr_1',
  token: 'tok_1',
  organizationId: 'org_1',
  destinationUrl: 'https://example.com/a',
  contentType: 'url',
  content: null,
  label: 'Menu',
  expiresAt: null,
  latitude: null,
  longitude: null,
  radiusM: 50,
};

const membershipFindFirst = vi.fn(async () => (db.verifiedOwner ? { id: 'm_1' } : null));
const prisma = {
  organization: { findUnique: vi.fn(async () => ({ plan: 'FREE' })) },
  qRCode: {
    count: vi.fn(() => db.qrCount()),
    findUnique: vi.fn(async () => QR_ROW),
    update: vi.fn(async ({ data }: { data: Record<string, unknown> }) => ({ ...QR_ROW, ...data })),
  },
  user: { findUnique: vi.fn(async () => ({ emailVerified: db.userVerified })) },
  membership: { findFirst: membershipFindFirst },
};

let app: FastifyInstance;

const patch = (payload: unknown) =>
  app.inject({
    method: 'PATCH',
    url: '/api/v1/qrcodes/tok_1',
    headers: { 'content-type': 'application/json' },
    payload: JSON.stringify(payload),
  });

const post = (url: string, payload: unknown) =>
  app.inject({
    method: 'POST',
    url: `/api/v1/qrcodes${url}`,
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
    request.user = { ...db.principal };
  });
  const { default: qrCodeRoutes } = await import('../qrcodes.js');
  await app.register(qrCodeRoutes, { prefix: '/api/v1/qrcodes' });
  await app.ready();
});

afterAll(async () => {
  await app.close();
});

beforeEach(() => {
  db.qrCount = () => Promise.resolve(0);
  db.userVerified = true;
  db.verifiedOwner = true;
  db.principal = { id: 'user_1', orgId: 'org_1', role: 'OWNER', email: 'owner@example.com' };
  membershipFindFirst.mockClear();
});

describe('quota read failure refuses issuance (503)', () => {
  it('POST / → 503 when the QR count cannot be read', async () => {
    db.qrCount = () => Promise.reject(new Error('db down'));

    const res = await post('', { destinationUrl: 'https://example.com' });

    expect(res.statusCode).toBe(503);
    expect(res.headers['retry-after']).toBe('30');
    expect(res.json().error).toBe('Service Unavailable');
  });

  it('POST /bulk → 503 when the QR count cannot be read', async () => {
    db.qrCount = () => Promise.reject(new Error('db down'));

    const res = await post('/bulk', { items: [{ destinationUrl: 'https://example.com' }] });

    expect(res.statusCode).toBe(503);
  });

  it('POST / → 429 at the limit (count read fine)', async () => {
    db.qrCount = () => Promise.resolve(100);

    const res = await post('', { destinationUrl: 'https://example.com' });

    expect(res.statusCode).toBe(429);
  });
});

describe('verified email required to create or repoint codes', () => {
  it.each([
    ['POST /', () => post('', { destinationUrl: 'https://example.com' })],
    ['POST /bulk', () => post('/bulk', { items: [{ destinationUrl: 'https://example.com' }] })],
    ['PATCH destinationUrl', () => patch({ destinationUrl: 'https://example.org/new' })],
    ['PATCH content', () => patch({ content: { firstName: 'Ada' } })],
  ])('%s → 403 EmailNotVerified for an unverified user', async (_label, send) => {
    db.userVerified = false;

    const res = await send();

    expect(res.statusCode).toBe(403);
    expect(res.json()).toMatchObject({ error: 'EmailNotVerified' });
  });

  it('PATCH of label only is allowed for an unverified user', async () => {
    db.userVerified = false;

    const res = await patch({ label: 'Renamed' });

    expect(res.statusCode).toBe(200);
  });

  it('a verified user passes the gate (reaches the quota check)', async () => {
    db.qrCount = () => Promise.resolve(100);

    const res = await post('', { destinationUrl: 'https://example.com' });

    expect(res.statusCode).toBe(429);
  });

  it('API key: refused when no OWNER of the org has a verified email', async () => {
    db.principal = { id: 'api-key', orgId: 'org_1', role: 'ADMIN', email: '' };
    db.verifiedOwner = false;

    const res = await post('', { destinationUrl: 'https://example.com' });

    expect(res.statusCode).toBe(403);
    expect(res.json().message).toMatch(/owner of this organization/);
    expect(membershipFindFirst).toHaveBeenCalledWith(expect.objectContaining({
      where: { organizationId: 'org_1', role: 'OWNER', user: { emailVerified: true } },
    }));
  });

  it('API key: allowed when an OWNER has a verified email', async () => {
    db.principal = { id: 'api-key', orgId: 'org_1', role: 'ADMIN', email: '' };
    db.qrCount = () => Promise.resolve(100);

    const res = await post('', { destinationUrl: 'https://example.com' });

    expect(res.statusCode).toBe(429);
  });
});
