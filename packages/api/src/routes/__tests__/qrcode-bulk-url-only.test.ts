import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * POST /api/v1/qrcodes/bulk creates URL codes only. An item that carries
 * `contentType` or `content` fails validation for the whole request (400),
 * before anything is processed: nothing is stored and no quota is read.
 * Single create keeps accepting content types.
 */

process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

vi.mock('../../services/destination-screening.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../services/destination-screening.js')>()),
  screenDestination: vi.fn(async () => ({ verdict: 'clean' })),
  enqueueDestinationRecheck: vi.fn(async () => undefined),
}));
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
const signSingleQR = vi.hoisted(() => vi.fn());
vi.mock('../../services/hybrid-signing.js', () => ({
  HybridSigningService: class {
    signSingleQR = signSingleQR;
  },
}));
vi.mock('../../services/mac.js', () => ({
  MacService: class {
    async signCanonical() {
      return { mac: 'mac', keyVersion: 1 };
    }
  },
}));
vi.mock('../../lib/cache.js', () => ({
  cacheGet: vi.fn(async () => null),
  cacheSet: vi.fn(async () => undefined),
  cacheDel: vi.fn(async () => undefined),
}));

const stored: Array<Record<string, unknown>> = [];
const prisma = {
  qRCode: {
    create: vi.fn(async ({ data }: { data: Record<string, unknown> }) => {
      const row = { id: `qr_${stored.length + 1}`, createdAt: new Date(), scanMode: 'PAGE', ...data };
      stored.push(row);
      return row;
    }),
    count: vi.fn(async () => stored.length),
  },
  organization: { findUnique: vi.fn(async () => ({ plan: 'BUSINESS' })) },
  user: { findUnique: vi.fn(async () => ({ emailVerified: true })) },
  membership: { findFirst: vi.fn(async () => ({ id: 'm1' })) },
};

const logged: unknown[] = [];
let app: FastifyInstance;

const post = (url: string, payload: Record<string, unknown>) =>
  app.inject({
    method: 'POST',
    url: `/api/v1/qrcodes${url}`,
    headers: { 'content-type': 'application/json' },
    payload: JSON.stringify(payload),
  });

beforeAll(async () => {
  app = Fastify({
    logger: {
      level: 'error',
      stream: { write: (line: string) => logged.push(JSON.parse(line)) },
    },
  });
  app.decorate('prisma', prisma as never);
  app.decorate('signingService', { getActiveKey: async () => ({ id: 'sk_1', keyId: 'k1' }) } as never);
  app.decorate('batchSigner', {} as never);
  app.decorateRequest('user', null);
  app.decorate('authenticate', async (request: { user: unknown }) => {
    request.user = { id: 'user_1', orgId: 'org_1', role: 'OWNER', email: 'owner@example.com' };
  });
  const { default: qrCodeRoutes } = await import('../qrcodes.js');
  await app.register(qrCodeRoutes, { prefix: '/api/v1/qrcodes' });
  await app.ready();
});

afterAll(async () => {
  await app.close();
});

beforeEach(() => {
  stored.length = 0;
  logged.length = 0;
  prisma.qRCode.create.mockClear();
  prisma.organization.findUnique.mockClear();
  signSingleQR.mockReset();
  signSingleQR.mockResolvedValue({
    ecdsaSignature: 'sig',
    algVersion: 'hybrid-ecdsa-slhdsa-v1',
    batchId: 'b1',
    leafIndex: 0,
    leafHash: 'h',
    leafNonce: 'n',
    merklePath: [],
  });
});

const BULK_URL_ONLY = 'bulk supports URL codes only';

describe('POST /bulk: URL codes only', () => {
  it('rejects an item with contentType: 400 naming the item, nothing created, quota untouched', async () => {
    const res = await post('/bulk', {
      items: [
        { destinationUrl: 'https://example.com/a' },
        { destinationUrl: 'https://example.com/b', contentType: 'vcard', content: { firstName: 'Ada' } },
      ],
    });
    expect(res.statusCode).toBe(400);
    const body = res.json();
    expect(body.error).toBe('Validation Error');
    expect(body.message).toContain(BULK_URL_ONLY);
    expect(body.message).toContain('body.items.1.contentType');
    expect(body.details).toContainEqual(
      expect.objectContaining({ path: ['body', 'items', '1', 'contentType'], message: BULK_URL_ONLY }),
    );
    expect(prisma.qRCode.create).not.toHaveBeenCalled();
    expect(prisma.organization.findUnique).not.toHaveBeenCalled();
    expect(stored).toHaveLength(0);
  });

  it('rejects contentType "url" too: the field is not part of the bulk item', async () => {
    const res = await post('/bulk', { items: [{ destinationUrl: 'https://example.com/a', contentType: 'url' }] });
    expect(res.statusCode).toBe(400);
    expect(res.json().details).toContainEqual(
      expect.objectContaining({ path: ['body', 'items', '0', 'contentType'], message: BULK_URL_ONLY }),
    );
    expect(stored).toHaveLength(0);
  });

  it('rejects an item with content: 400 naming the item, nothing created', async () => {
    const res = await post('/bulk', { items: [{ destinationUrl: 'https://example.com/a', content: { firstName: 'Ada' } }] });
    expect(res.statusCode).toBe(400);
    expect(res.json().details).toContainEqual(
      expect.objectContaining({ path: ['body', 'items', '0', 'content'], message: BULK_URL_ONLY }),
    );
    expect(prisma.qRCode.create).not.toHaveBeenCalled();
    expect(stored).toHaveLength(0);
  });

  it('rejects an item with qrStyle: 400 naming the item, nothing created', async () => {
    const qrStyle = { version: 2, fg: '#000000', bg: '#FFFFFF', logo: { kind: 'asset', assetId: 'a1', scale: 1 } };
    const res = await post('/bulk', {
      items: [{ destinationUrl: 'https://example.com/a' }, { destinationUrl: 'https://example.com/b', qrStyle }],
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().details).toContainEqual(
      expect.objectContaining({
        path: ['body', 'items', '1', 'qrStyle'],
        message: 'bulk does not accept qrStyle; set a style per code with PATCH',
      }),
    );
    expect(prisma.qRCode.create).not.toHaveBeenCalled();
    expect(stored).toHaveLength(0);
  });

  it('plain URL items still succeed', async () => {
    const res = await post('/bulk', {
      items: [{ destinationUrl: 'https://example.com/a' }, { destinationUrl: 'https://example.com/b', label: 'B' }],
    });
    expect(res.statusCode).toBe(207);
    expect(res.json().summary).toMatchObject({ total: 2, succeeded: 2, failed: 0 });
    expect(stored).toHaveLength(2);
    expect(stored.every((row) => row.contentType === 'url')).toBe(true);
  });
});

describe('POST /: single create is unchanged', () => {
  it('still creates a content-type code', async () => {
    const res = await post('', {
      destinationUrl: 'https://example.com/card',
      contentType: 'vcard',
      content: { firstName: 'Ada' },
    });
    expect(res.statusCode).toBe(201);
    expect(stored).toHaveLength(1);
    expect(stored[0].contentType).toBe('vcard');
  });
});
