import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import sharp from 'sharp';

/**
 * Create and bulk create render qr_image_url before anything is stored: when
 * rendering fails (here sharp throws), no code is persisted, no quota is
 * used, the error is logged, and the client gets 503 (single) or a
 * RENDER_UNAVAILABLE item (bulk).
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

// The decode round trip itself is tested in test/unit/logo-decode.test.ts.
vi.mock('../../services/logo-decode.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../services/logo-decode.js')>()),
  assertLogoScans: vi.fn(async () => undefined),
}));

/** org_1's logo library holds asset_1 until a parallel delete removes it. */
let isLogoDeleted = false;
const LOGO_PNG = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.from('customer-logo')]);

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
  organization: { findUnique: vi.fn(async () => ({ plan: 'BUSINESS', domainVerified: true, kycStatus: 'PENDING' })) },
  contentAsset: { findFirst: vi.fn(async ({ where }: { where: { id: string } }) => (where.id === 'asset_1' ? { id: 'asset_1' } : null)) },
  contentAssetBlob: { findUnique: vi.fn(async () => ({ bytes: LOGO_PNG })) },
  // The logo row lock (LogoLibrary.writeWithLogo): no row once the logo is deleted.
  $queryRaw: vi.fn(async (_sql: TemplateStringsArray, assetId: string) => (assetId === 'asset_1' && !isLogoDeleted ? [{ id: assetId }] : [])),
  $transaction: vi.fn(async (work: (tx: unknown) => Promise<unknown>) => work(prisma)),
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
  isLogoDeleted = false;
  stored.length = 0;
  logged.length = 0;
  prisma.qRCode.create.mockClear();
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

/** Makes every sharp rasterisation throw, as a broken native binary would. */
function breakSharp(): () => void {
  const spy = vi.spyOn(sharp.prototype, 'toBuffer').mockRejectedValue(new Error('sharp: Input buffer has corrupt header'));
  return () => spy.mockRestore();
}

describe('customer logo write under the logo row lock', () => {
  const qrStyle = {
    version: 2, presetId: 'classic', fg: '#000000', bg: '#FFFFFF', inverted: false,
    modules: 'square', eyes: 'square', ecLevel: 'auto', quietZone: 4,
    logo: { kind: 'asset', assetId: 'asset_1', scale: 1 },
  };

  it('stores the code inside the transaction that holds the lock', async () => {
    prisma.$queryRaw.mockClear();
    const res = await post('', { destinationUrl: 'https://example.com/logo', qrStyle });
    expect(res.statusCode).toBe(201);
    expect(stored).toHaveLength(1);
    expect(prisma.$transaction).toHaveBeenCalled();
    expect(prisma.$queryRaw.mock.invocationCallOrder[0]).toBeLessThan(prisma.qRCode.create.mock.invocationCallOrder[0]);
  });

  it('a logo deleted after the checks but before the write is 422 logo-not-found and nothing is stored', async () => {
    signSingleQR.mockImplementation(async () => {
      // The delete commits while the code is being signed.
      isLogoDeleted = true;
      return { ecdsaSignature: 'sig', algVersion: 'hybrid-ecdsa-slhdsa-v1', batchId: 'b1', leafIndex: 0, leafHash: 'h', leafNonce: 'n', merklePath: [] };
    });
    const res = await post('', { destinationUrl: 'https://example.com/logo', qrStyle });
    expect(res.statusCode).toBe(422);
    expect(res.json()).toMatchObject({ code: 'logo-not-found' });
    expect(stored).toHaveLength(0);
    expect(prisma.qRCode.create).not.toHaveBeenCalled();
  });
});

describe('render before persist', () => {
  it('control: a working render stores the code and returns its image', async () => {
    const res = await post('', { destinationUrl: 'https://example.com/a' });
    expect(res.statusCode).toBe(201);
    expect(res.json().qr_image_url).toMatch(/^data:image\/png;base64,/);
    expect(stored).toHaveLength(1);
  });

  it('POST /: a render failure stores nothing, uses no quota, logs, and answers 503', async () => {
    const restore = breakSharp();
    try {
      const before = await prisma.qRCode.count();
      const res = await post('', { destinationUrl: 'https://example.com/a' });
      expect(res.statusCode).toBe(503);
      expect(res.headers['retry-after']).toBe('5');
      expect(res.json().message).toContain('No code was created');
      expect(prisma.qRCode.create).not.toHaveBeenCalled();
      expect(signSingleQR).not.toHaveBeenCalled();
      expect(await prisma.qRCode.count()).toBe(before);
      expect(logged.some((l) => (l as { msg?: string }).msg?.includes('image rendering failed; nothing stored'))).toBe(true);
    } finally {
      restore();
    }
  });

  it('POST /bulk: each item that fails to render is RENDER_UNAVAILABLE and not stored', async () => {
    const restore = breakSharp();
    try {
      const res = await post('/bulk', { items: [{ destinationUrl: 'https://example.com/a' }, { destinationUrl: 'https://example.com/b' }] });
      expect(res.statusCode).toBe(207);
      expect(res.json().results.map((r: { errorCode?: string }) => r.errorCode)).toEqual(['RENDER_UNAVAILABLE', 'RENDER_UNAVAILABLE']);
      expect(res.json().summary).toMatchObject({ succeeded: 0, failed: 2 });
      expect(prisma.qRCode.create).not.toHaveBeenCalled();
      expect(stored).toHaveLength(0);
    } finally {
      restore();
    }
  });

  it('POST /bulk: after rendering recovers, items are stored again', async () => {
    const res = await post('/bulk', { items: [{ destinationUrl: 'https://example.com/a' }] });
    expect(res.statusCode).toBe(207);
    expect(res.json().results[0].success).toBe(true);
    expect(stored).toHaveLength(1);
  });
});

describe('qr_image_url: the badge mark follows the issuer status (ADR-0005 D9, 2026-10-30)', () => {
  const qrStyle = {
    version: 2, presetId: 'classic', fg: '#000000', bg: '#FFFFFF', inverted: false,
    modules: 'square', eyes: 'square', ecLevel: 'auto', quietZone: 4, logo: null,
    frame: { template: 'badge', text: 'Scan me', color: '#003768', textColor: '#FFFFFF' },
  };

  afterAll(() => {
    prisma.organization.findUnique.mockImplementation(async () => ({ plan: 'BUSINESS', domainVerified: true, kycStatus: 'PENDING' }));
  });

  it.each([
    ['a verified issuer', { plan: 'BUSINESS', domainVerified: true, kycStatus: 'PENDING' }, true],
    ['an unverified issuer', { plan: 'BUSINESS', domainVerified: false, kycStatus: 'UNDER_REVIEW' }, false],
  ])('%s gets the image renderExport draws for that status', async (_label, org, issuerVerified) => {
    prisma.organization.findUnique.mockImplementation(async () => org);
    const res = await post('', { destinationUrl: 'https://example.com/badge', qrStyle });
    expect(res.statusCode).toBe(201);
    const { renderExport, styleForRender, QR_IMAGE_URL_PX } = await import('../../services/qr-render.js');
    const token = res.json().token as string;
    const style = styleForRender(qrStyle);
    const expected = await renderExport({ token, issuerVerified }, style, null, { format: 'png', px: QR_IMAGE_URL_PX });
    const other = await renderExport({ token, issuerVerified: !issuerVerified }, style, null, { format: 'png', px: QR_IMAGE_URL_PX });
    expect(res.json().qr_image_url).toBe(`data:image/png;base64,${expected.body.toString('base64')}`);
    expect(expected.body.equals(other.body)).toBe(false);
  });
});
