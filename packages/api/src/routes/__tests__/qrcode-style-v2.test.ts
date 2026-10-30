import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * Style v2 on write (ADR-0005 PR 3): the API accepts v2 bodies only; v1
 * bodies were accepted and upgraded until PR 6 closed that window (D2).
 * Stored v1 rows still render and compare as their upgrade. On FREE, module and eye styles are limited to square and
 * rounded, and customer logos are refused (D9), with a 403 shaped like the
 * content-type gate. A customer logo (PR 4) must be one of the
 * organization's own and read back at the checked export sizes (422 otherwise).
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
vi.mock('../../services/usage.js', () => ({
  UsageService: class {
    async checkQuota() {
      return null;
    }
  },
  QuotaUnavailableError: class extends Error {},
}));
vi.mock('../../services/destination-screening.js', () => ({
  DESTINATION_FLAGGED_ERROR: 'DestinationFlagged',
  destinationFlaggedBody: () => ({}),
  enqueueDestinationRecheck: async () => undefined,
  screenDestination: async () => ({ verdict: 'clean' }),
}));
// The decode round trip itself is tested in test/unit/logo-decode.test.ts.
const logoDecode = vi.hoisted(() => ({ assertLogoScans: vi.fn(async () => undefined) }));
vi.mock('../../services/logo-decode.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../services/logo-decode.js')>()),
  assertLogoScans: logoDecode.assertLogoScans,
}));

const { qrStyleSchema, STYLE_V1_REJECTED_MESSAGE } = await import('../qrcodes.js');
const { qrStyleGateMessage } = await import('../../config/plan-limits.js');

const V2 = {
  version: 2,
  presetId: 'classic',
  fg: '#000000',
  bg: '#FFFFFF',
  inverted: false,
  modules: 'square',
  eyes: 'square',
  ecLevel: 'auto',
  quietZone: 4,
  logo: { kind: 'qrauth' },
} as const;

const CAPTION = { template: 'caption', text: 'Scan to verify', color: '#FFFFFF', textColor: '#000000' } as const;

const V1 = {
  templateId: 'midnight',
  fgColor: '#E0E0E0',
  bgColor: '#212121',
  showLogo: true,
  captionText: 'QRAuth Verified',
};

describe('qrStyleSchema accepts v2 only', () => {
  it('a v2 style passes through unchanged', () => {
    const r = qrStyleSchema.safeParse(V2);
    expect(r.success).toBe(true);
    expect(r.data).toEqual(V2);
    const withCaption = { ...V2, frame: CAPTION };
    expect(qrStyleSchema.safeParse(withCaption).data).toEqual(withCaption);
  });

  it('a v1 style is refused with one issue that says to send version 2 (PR 6)', () => {
    const r = qrStyleSchema.safeParse(V1);
    expect(r.success).toBe(false);
    expect(r.error!.issues.map((i) => i.message)).toEqual([STYLE_V1_REJECTED_MESSAGE]);
    // A plain validation error, not a scan rule (400, not 422).
    expect(r.error!.issues.every((i) => (i as { params?: { scanRule?: string } }).params?.scanRule === undefined)).toBe(true);
  });

  it('a v2 style breaking a scan rule carries the rule code', () => {
    const r = qrStyleSchema.safeParse({ ...V2, fg: '#E0E0E0', bg: '#212121' });
    expect(r.success).toBe(false);
    const codes = r.error!.issues.map((i) => (i as { params?: { scanRule?: string } }).params?.scanRule);
    expect(codes).toContain('inverted-required');
  });

  it('an explicit EC level below the floor is refused', () => {
    const r = qrStyleSchema.safeParse({ ...V2, ecLevel: 'M' });
    expect(r.success).toBe(false);
    const codes = r.error!.issues.map((i) => (i as { params?: { scanRule?: string } }).params?.scanRule);
    expect(codes).toContain('ec-below-floor');
  });

  it('a customer logo passes the schema (ownership and decoding are checked by the routes)', () => {
    const r = qrStyleSchema.safeParse({ ...V2, logo: { kind: 'asset', assetId: 'a1', scale: 0.75 } });
    expect(r.success).toBe(true);
  });

  it('a customer logo scale outside 0.5..1 is refused', () => {
    expect(qrStyleSchema.safeParse({ ...V2, logo: { kind: 'asset', assetId: 'a1', scale: 0.4 } }).success).toBe(false);
    expect(qrStyleSchema.safeParse({ ...V2, logo: { kind: 'asset', assetId: 'a1', scale: 1.1 } }).success).toBe(false);
  });

  it.each([
    ['a v1/v2 mix', { ...V1, version: 2 }],
    ['an unknown version', { ...V2, version: 3 }],
    ['an unknown module style', { ...V2, modules: 'hearts' }],
    ['a quiet zone below 4', { ...V2, quietZone: 3 }],
  ])('%s is refused', (_label, value) => {
    expect(qrStyleSchema.safeParse(value).success).toBe(false);
  });
});

describe('qrStyleGateMessage (D9)', () => {
  it.each([
    ['square/square', 'square', 'square'],
    ['rounded/rounded', 'rounded', 'rounded'],
  ])('FREE may use %s', (_label, modules, eyes) => {
    expect(qrStyleGateMessage('FREE', { modules, eyes })).toBeNull();
  });

  it.each([
    ['dots modules', 'dots', 'square', /dots module style/],
    ['classy modules', 'classy', 'square', /classy module style/],
    ['circle eyes', 'square', 'circle', /circle eye style/],
    ['leaf eyes', 'rounded', 'leaf', /leaf eye style/],
  ])('FREE may not use %s', (_label, modules, eyes, message) => {
    expect(qrStyleGateMessage('FREE', { modules, eyes })).toMatch(message);
  });

  it.each(['PRO', 'BUSINESS', 'ENTERPRISE'])('%s may use every shape', (plan) => {
    expect(qrStyleGateMessage(plan, { modules: 'classy', eyes: 'leaf' })).toBeNull();
  });

  it('an unknown plan is treated as FREE', () => {
    expect(qrStyleGateMessage('GOLD', { modules: 'dots', eyes: 'square' })).not.toBeNull();
  });

  it('FREE may not use a customer logo; the QRAuth logo is on every plan', () => {
    const asset = { kind: 'asset' };
    expect(qrStyleGateMessage('FREE', { modules: 'square', eyes: 'square', logo: asset })).toBe(
      'Customer logos are not included in the Free plan. Upgrade at https://qrauth.io/dashboard/pricing.',
    );
    expect(qrStyleGateMessage('FREE', { modules: 'square', eyes: 'square', logo: { kind: 'qrauth' } })).toBeNull();
    expect(qrStyleGateMessage('GOLD', { modules: 'square', eyes: 'square', logo: asset })).not.toBeNull();
  });

  it.each(['PRO', 'BUSINESS', 'ENTERPRISE'])('%s may use a customer logo', (plan) => {
    expect(qrStyleGateMessage(plan, { modules: 'square', eyes: 'square', logo: { kind: 'asset' } })).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

const prisma = {
  qRCode: {
    create: vi.fn(),
    update: vi.fn(async () => ({ token: 'a1' })),
    findUnique: vi.fn(async () => ({ id: 'qr_1', token: 'a1', organizationId: 'org_1', contentType: 'url', content: null })),
  },
  organization: { findUnique: vi.fn(async () => ({ plan: 'FREE' })) },
  user: { findUnique: vi.fn(async () => ({ emailVerified: true })) },
  membership: { findFirst: vi.fn(async () => null) },
  // The logo library: org_1 owns asset_1; org_2 owns asset_2.
  contentAsset: {
    findFirst: vi.fn(async ({ where }: { where: { id: string; organizationId: string } }) =>
      LOGO_OWNERS[where.id] === where.organizationId ? { id: where.id } : null,
    ),
  },
  contentAssetBlob: {
    findUnique: vi.fn(async ({ where }: { where: { assetId: string } }) => (LOGO_OWNERS[where.assetId] ? { bytes: LOGO_PNG } : null)),
  },
  // The logo row lock a style write takes (LogoLibrary.writeWithLogo).
  $queryRaw: vi.fn(async (_sql: TemplateStringsArray, assetId: string, organizationId: string) =>
    LOGO_OWNERS[assetId] === organizationId && !deletedLogos.has(assetId) ? [{ id: assetId }] : [],
  ),
  $transaction: vi.fn(async (work: (tx: unknown) => Promise<unknown>) => work(prisma)),
};

/** Logos deleted after the request's ownership check, before its write (the delete race). */
const deletedLogos = new Set<string>();

/** A paid organization with a verified domain: the one case that may use customer logos. */
const PRO_VERIFIED = { plan: 'PRO', domainVerified: true, kycStatus: 'PENDING' };
const PRO_UNVERIFIED = { plan: 'PRO', domainVerified: false, kycStatus: 'UNDER_REVIEW' };

const LOGO_OWNERS: Record<string, string> = { asset_1: 'org_1', asset_2: 'org_2' };
const LOGO_PNG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

let app: FastifyInstance;

beforeAll(async () => {
  app = Fastify();
  app.decorate('prisma', prisma as never);
  app.decorate('signingService', {
    getActiveKey: async () => ({ id: 'key_1', keyId: 'kid_1' }),
  } as never);
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
  prisma.qRCode.create.mockClear();
  prisma.qRCode.update.mockClear();
  prisma.organization.findUnique.mockImplementation(async () => ({ plan: 'FREE' }));
  logoDecode.assertLogoScans.mockReset();
  logoDecode.assertLogoScans.mockImplementation(async () => undefined);
});

const send = (method: 'POST' | 'PATCH', url: string, payload: unknown) =>
  app.inject({ method, url: `/api/v1/qrcodes${url}`, headers: { 'content-type': 'application/json' }, payload: JSON.stringify(payload) });

describe('plan gate on routes that accept a style', () => {
  it.each<[string, 'POST' | 'PATCH', string, Record<string, unknown>]>([
    ['POST /', 'POST', '', { destinationUrl: 'https://example.com' }],
    ['PATCH /:token', 'PATCH', '/a1', {}],
  ])('%s: FREE with dots modules is 403 and nothing is written', async (_label, method, url, base) => {
    const res = await send(method, url, { ...base, qrStyle: { ...V2, modules: 'dots' } });
    expect(res.statusCode).toBe(403);
    expect(res.json()).toMatchObject({ statusCode: 403, error: 'Forbidden' });
    expect(res.json().message).toMatch(/dots module style is not included in the Free plan/);
    expect(prisma.qRCode.create).not.toHaveBeenCalled();
    expect(prisma.qRCode.update).not.toHaveBeenCalled();
  });

  it('PATCH: PRO with dots modules and leaf eyes stores the v2 style', async () => {
    prisma.organization.findUnique.mockImplementation(async () => PRO_VERIFIED);
    const qrStyle = { ...V2, modules: 'dots', eyes: 'leaf' };
    const res = await send('PATCH', '/a1', { qrStyle });
    expect(res.statusCode).toBe(200);
    expect(prisma.qRCode.update).toHaveBeenCalledWith(expect.objectContaining({ data: expect.objectContaining({ style: qrStyle }) }));
  });

  it.each<[string, 'POST' | 'PATCH', string, Record<string, unknown>]>([
    ['POST /', 'POST', '', { destinationUrl: 'https://example.com' }],
    ['PATCH /:token', 'PATCH', '/a1', {}],
  ])('%s: a v1 body is 400 and nothing is written (PR 6)', async (_label, method, url, base) => {
    prisma.organization.findUnique.mockImplementation(async () => PRO_VERIFIED);
    const res = await send(method, url, { ...base, qrStyle: V1 });
    expect(res.statusCode).toBe(400);
    expect(res.json().message).toBe(`body.qrStyle: ${STYLE_V1_REJECTED_MESSAGE}`);
    expect(prisma.qRCode.create).not.toHaveBeenCalled();
    expect(prisma.qRCode.update).not.toHaveBeenCalled();
  });

  it('PATCH without a style does not look up the plan', async () => {
    prisma.organization.findUnique.mockClear();
    const res = await send('PATCH', '/a1', { label: 'x' });
    expect(res.statusCode).toBe(200);
    expect(prisma.organization.findUnique).not.toHaveBeenCalled();
  });
});

describe('customer logos on routes that accept a style (PR 4)', () => {
  const ASSET_STYLE = { ...V2, logo: { kind: 'asset', assetId: 'asset_1', scale: 0.75 } };

  it.each<[string, 'POST' | 'PATCH', string, Record<string, unknown>]>([
    ['POST /', 'POST', '', { destinationUrl: 'https://example.com' }],
    ['PATCH /:token', 'PATCH', '/a1', {}],
  ])('%s: FREE is 403 with the gate body, before the logo is looked up', async (_label, method, url, base) => {
    prisma.contentAsset.findFirst.mockClear();
    const res = await send(method, url, { ...base, qrStyle: ASSET_STYLE });
    expect(res.statusCode).toBe(403);
    expect(res.json()).toEqual({
      statusCode: 403,
      error: 'Forbidden',
      message: 'Customer logos are not included in the Free plan. Upgrade at https://qrauth.io/dashboard/pricing.',
    });
    expect(prisma.contentAsset.findFirst).not.toHaveBeenCalled();
    expect(prisma.qRCode.create).not.toHaveBeenCalled();
    expect(prisma.qRCode.update).not.toHaveBeenCalled();
  });

  it.each<[string, 'POST' | 'PATCH', string, Record<string, unknown>]>([
    ['POST /', 'POST', '', { destinationUrl: 'https://example.com' }],
    ['PATCH /:token', 'PATCH', '/a1', {}],
  ])('%s: a paid plan without a verified issuer is 403 logo-verification-required, before the logo is looked up', async (_label, method, url, base) => {
    prisma.organization.findUnique.mockImplementation(async () => PRO_UNVERIFIED);
    prisma.contentAsset.findFirst.mockClear();
    const res = await send(method, url, { ...base, qrStyle: ASSET_STYLE });
    expect(res.statusCode).toBe(403);
    expect(res.json()).toEqual({
      statusCode: 403,
      error: 'Forbidden',
      code: 'logo-verification-required',
      message: 'Custom logos require a verified domain or completed verification',
    });
    expect(prisma.contentAsset.findFirst).not.toHaveBeenCalled();
    expect(logoDecode.assertLogoScans).not.toHaveBeenCalled();
    expect(prisma.qRCode.create).not.toHaveBeenCalled();
    expect(prisma.qRCode.update).not.toHaveBeenCalled();
  });

  it('FREE with a verified domain is refused with the plan 403, not the verification one', async () => {
    prisma.organization.findUnique.mockImplementation(async () => ({ plan: 'FREE', domainVerified: true, kycStatus: 'VERIFIED' }));
    const res = await send('PATCH', '/a1', { qrStyle: ASSET_STYLE });
    expect(res.statusCode).toBe(403);
    expect(res.json().code).toBeUndefined();
    expect(res.json().message).toMatch(/not included in the Free plan/);
  });

  it('a paid plan without a verified issuer may still save styles without a customer logo', async () => {
    prisma.organization.findUnique.mockImplementation(async () => PRO_UNVERIFIED);
    const res = await send('PATCH', '/a1', { qrStyle: { ...V2, modules: 'dots' } });
    expect(res.statusCode).toBe(200);
  });

  it('a paid plan with a completed KYC review (no verified domain) may save a customer logo', async () => {
    prisma.organization.findUnique.mockImplementation(async () => ({ plan: 'BUSINESS', domainVerified: false, kycStatus: 'VERIFIED' }));
    const res = await send('PATCH', '/a1', { qrStyle: ASSET_STYLE });
    expect(res.statusCode).toBe(200);
    expect(prisma.qRCode.update).toHaveBeenCalledWith(expect.objectContaining({ data: expect.objectContaining({ style: ASSET_STYLE }) }));
  });

  it('after a loss of verification, a save that leaves the stored style out succeeds; a changed style is refused', async () => {
    prisma.organization.findUnique.mockImplementation(async () => PRO_UNVERIFIED);
    // The dashboard omits an unchanged style, so other edits still save.
    const unchanged = await send('PATCH', '/a1', { label: 'renamed' });
    expect(unchanged.statusCode).toBe(200);
    const { data } = prisma.qRCode.update.mock.calls[0][0] as { data: Record<string, unknown> };
    expect(data).not.toHaveProperty('style');
    prisma.qRCode.update.mockClear();
    const changed = await send('PATCH', '/a1', { qrStyle: { ...ASSET_STYLE, logo: { ...ASSET_STYLE.logo, scale: 0.5 } } });
    expect(changed.statusCode).toBe(403);
    expect(changed.json().code).toBe('logo-verification-required');
    expect(prisma.qRCode.update).not.toHaveBeenCalled();
  });

  it.each<[string, 'POST' | 'PATCH', string, Record<string, unknown>, string]>([
    ['POST / with a missing logo', 'POST', '', { destinationUrl: 'https://example.com' }, 'asset_404'],
    ['POST / with another organization’s logo', 'POST', '', { destinationUrl: 'https://example.com' }, 'asset_2'],
    ['PATCH /:token with a missing logo', 'PATCH', '/a1', {}, 'asset_404'],
    ['PATCH /:token with another organization’s logo', 'PATCH', '/a1', {}, 'asset_2'],
  ])('%s is 422 logo-not-found and nothing is written', async (_label, method, url, base, assetId) => {
    prisma.organization.findUnique.mockImplementation(async () => PRO_VERIFIED);
    const res = await send(method, url, { ...base, qrStyle: { ...ASSET_STYLE, logo: { ...ASSET_STYLE.logo, assetId } } });
    expect(res.statusCode).toBe(422);
    expect(res.json()).toMatchObject({ statusCode: 422, code: 'logo-not-found', details: [{ path: ['body', 'qrStyle', 'logo'] }] });
    expect(logoDecode.assertLogoScans).not.toHaveBeenCalled();
    expect(prisma.qRCode.create).not.toHaveBeenCalled();
    expect(prisma.qRCode.update).not.toHaveBeenCalled();
  });

  it('PATCH: PRO with its own logo runs the decode check on the code’s URL, then stores the style', async () => {
    const { buildVerificationUrl } = await import('../../lib/qrcode-access.js');
    prisma.organization.findUnique.mockImplementation(async () => PRO_VERIFIED);
    const res = await send('PATCH', '/a1', { qrStyle: ASSET_STYLE });
    expect(res.statusCode).toBe(200);
    expect(logoDecode.assertLogoScans).toHaveBeenCalledWith(buildVerificationUrl('a1'), ASSET_STYLE, new Uint8Array(LOGO_PNG));
    expect(prisma.qRCode.update).toHaveBeenCalledWith(expect.objectContaining({ data: expect.objectContaining({ style: ASSET_STYLE }) }));
  });

  it('PATCH: the style write runs under the logo row lock, in a transaction', async () => {
    prisma.organization.findUnique.mockImplementation(async () => PRO_VERIFIED);
    prisma.$queryRaw.mockClear();
    prisma.$transaction.mockClear();
    const res = await send('PATCH', '/a1', { qrStyle: ASSET_STYLE });
    expect(res.statusCode).toBe(200);
    expect(prisma.$transaction).toHaveBeenCalledTimes(1);
    expect(prisma.$queryRaw.mock.calls[0].slice(1)).toEqual(['asset_1', 'org_1']);
    expect(prisma.$queryRaw.mock.invocationCallOrder[0]).toBeLessThan(prisma.qRCode.update.mock.invocationCallOrder[0]);
  });

  // The create path's lock is tested in qrcode-create-render.test.ts, which signs.
  it('PATCH: a logo deleted after the checks but before the write is 422 logo-not-found and nothing is written', async () => {
    const [method, url, base] = ['PATCH', '/a1', {}] as const;
    prisma.organization.findUnique.mockImplementation(async () => PRO_VERIFIED);
    // The decode check passes, then the logo is deleted in parallel.
    logoDecode.assertLogoScans.mockImplementation(async () => {
      deletedLogos.add('asset_1');
    });
    try {
      const res = await send(method, url, { ...base, qrStyle: ASSET_STYLE });
      expect(res.statusCode).toBe(422);
      expect(res.json()).toMatchObject({ code: 'logo-not-found' });
      expect(prisma.qRCode.create).not.toHaveBeenCalled();
      expect(prisma.qRCode.update).not.toHaveBeenCalled();
    } finally {
      deletedLogos.clear();
    }
  });

  it('PATCH: a logo that does not read back is 422 logo-unreadable and the style is not saved', async () => {
    const { LogoUnreadableError } = await import('../../services/logo-decode.js');
    prisma.organization.findUnique.mockImplementation(async () => PRO_VERIFIED);
    logoDecode.assertLogoScans.mockImplementation(async () => {
      throw new LogoUnreadableError('300 px wide');
    });
    const res = await send('PATCH', '/a1', { qrStyle: ASSET_STYLE });
    expect(res.statusCode).toBe(422);
    expect(res.json()).toMatchObject({ statusCode: 422, error: 'Unprocessable Entity', code: 'logo-unreadable' });
    // The message names the size that failed.
    expect(res.json().message).toBe(
      'The code could not be read back with this logo at 300 px wide. Use a smaller logo, a simpler logo or higher contrast.',
    );
    expect(prisma.qRCode.update).not.toHaveBeenCalled();
  });

  it('PATCH: the decode check failing to render is 503 and nothing is changed', async () => {
    prisma.organization.findUnique.mockImplementation(async () => PRO_VERIFIED);
    logoDecode.assertLogoScans.mockImplementation(async () => {
      throw new Error('queue full');
    });
    const res = await send('PATCH', '/a1', { qrStyle: ASSET_STYLE });
    expect(res.statusCode).toBe(503);
    expect(res.headers['retry-after']).toBeDefined();
    expect(prisma.qRCode.update).not.toHaveBeenCalled();
  });

  it('POST: a logo that does not read back is 422 logo-unreadable and nothing is created', async () => {
    const { LogoUnreadableError } = await import('../../services/logo-decode.js');
    const { buildVerificationUrl } = await import('../../lib/qrcode-access.js');
    prisma.organization.findUnique.mockImplementation(async () => PRO_VERIFIED);
    logoDecode.assertLogoScans.mockImplementation(async () => {
      throw new LogoUnreadableError('8 px per module');
    });
    const res = await send('POST', '', { destinationUrl: 'https://example.com', qrStyle: ASSET_STYLE });
    expect(res.statusCode).toBe(422);
    expect(res.json()).toMatchObject({ code: 'logo-unreadable' });
    // Checked against the new code's own URL, before anything is signed or stored.
    const [url, style, logo] = logoDecode.assertLogoScans.mock.calls[0] as unknown as [string, unknown, Uint8Array];
    expect(url.startsWith(buildVerificationUrl(''))).toBe(true);
    expect(url.length).toBeGreaterThan(buildVerificationUrl('').length);
    expect(style).toEqual(ASSET_STYLE);
    expect(Array.from(logo)).toEqual(Array.from(LOGO_PNG));
    expect(prisma.qRCode.create).not.toHaveBeenCalled();
  });

  it('PATCH without a style change does not look up a logo', async () => {
    prisma.contentAsset.findFirst.mockClear();
    const res = await send('PATCH', '/a1', { label: 'x' });
    expect(res.statusCode).toBe(200);
    expect(prisma.contentAsset.findFirst).not.toHaveBeenCalled();
    expect(logoDecode.assertLogoScans).not.toHaveBeenCalled();
  });
});

describe('frames on routes that accept a style (PR 5)', () => {
  const BANNER = { ...V2, frame: { template: 'banner-bottom', text: 'Σαρώστε με', color: '#000000', textColor: '#FFFFFF' } };

  it.each<[string, 'POST' | 'PATCH', string, Record<string, unknown>]>([
    ['POST /', 'POST', '', { destinationUrl: 'https://example.com' }],
    ['PATCH /:token', 'PATCH', '/a1', {}],
  ])('%s: FREE with a frame is 403 with the gate body, and nothing is written', async (_label, method, url, base) => {
    const res = await send(method, url, { ...base, qrStyle: BANNER });
    expect(res.statusCode).toBe(403);
    expect(res.json()).toEqual({
      statusCode: 403,
      error: 'Forbidden',
      message: 'Frames and call-to-action templates are not included in the Free plan. Upgrade at https://qrauth.io/dashboard/pricing.',
    });
    expect(prisma.qRCode.create).not.toHaveBeenCalled();
    expect(prisma.qRCode.update).not.toHaveBeenCalled();
  });

  it('FREE may save a style whose frame is none', async () => {
    const res = await send('PATCH', '/a1', { qrStyle: { ...BANNER, frame: { ...BANNER.frame, template: 'none' } } });
    expect(res.statusCode).toBe(200);
  });

  it('PRO stores a frame with Greek text', async () => {
    prisma.organization.findUnique.mockImplementation(async () => ({ plan: 'PRO' }));
    const res = await send('PATCH', '/a1', { qrStyle: BANNER });
    expect(res.statusCode).toBe(200);
    expect(prisma.qRCode.update).toHaveBeenCalledWith(expect.objectContaining({ data: expect.objectContaining({ style: BANNER }) }));
  });

  it('a character the font cannot draw is 422 in the scan-rule envelope', async () => {
    prisma.organization.findUnique.mockImplementation(async () => ({ plan: 'PRO' }));
    const res = await send('PATCH', '/a1', { qrStyle: { ...BANNER, frame: { ...BANNER.frame, text: 'Menu 日本' } } });
    expect(res.statusCode).toBe(422);
    expect(res.json()).toMatchObject({
      statusCode: 422,
      error: 'Unprocessable Entity',
      code: 'frame-glyph-unsupported',
      message: expect.stringContaining('This character is not supported in frame text yet'),
      details: [{ path: ['body', 'qrStyle'], code: 'frame-glyph-unsupported', message: 'This character is not supported in frame text yet' }],
    });
    expect(prisma.qRCode.update).not.toHaveBeenCalled();
  });

  it('frame text below 4.5:1 against the frame is 422 frame-contrast-too-low', async () => {
    prisma.organization.findUnique.mockImplementation(async () => ({ plan: 'PRO' }));
    // On a black frame, #747474 is 4.49:1 and #757575 is 4.56:1.
    const res = await send('PATCH', '/a1', { qrStyle: { ...BANNER, frame: { ...BANNER.frame, textColor: '#747474' } } });
    expect(res.statusCode).toBe(422);
    expect(res.json()).toMatchObject({ code: 'frame-contrast-too-low', message: expect.stringMatching(/Frame text contrast .* below 4.5:1/) });
    const ok = await send('PATCH', '/a1', { qrStyle: { ...BANNER, frame: { ...BANNER.frame, textColor: '#757575' } } });
    expect(ok.statusCode).toBe(200);
  });

  it('the frame text rules are unchanged: a line break is 400', async () => {
    prisma.organization.findUnique.mockImplementation(async () => ({ plan: 'PRO' }));
    const res = await send('PATCH', '/a1', { qrStyle: { ...BANNER, frame: { ...BANNER.frame, text: 'a\nb' } } });
    expect(res.statusCode).toBe(400);
    const long = await send('PATCH', '/a1', { qrStyle: { ...BANNER, frame: { ...BANNER.frame, text: 'x'.repeat(41) } } });
    expect(long.statusCode).toBe(400);
  });
});

describe('PATCH with the stored style unchanged (D9: only a changed style must comply)', () => {
  const STORED = { ...V2, modules: 'dots', logo: { kind: 'asset', assetId: 'asset_1', scale: 0.75 } };
  const stored = (style: unknown) =>
    prisma.qRCode.findUnique.mockImplementation(async () => ({
      id: 'qr_1',
      token: 'a1',
      organizationId: 'org_1',
      contentType: 'url',
      content: null,
      style,
    }) as never);

  afterAll(() => {
    stored(undefined);
  });

  it('a verified PRO org saves a customer-logo style; after losing verification, resending it unchanged is 200', async () => {
    prisma.organization.findUnique.mockImplementation(async () => PRO_VERIFIED);
    stored(null);
    expect((await send('PATCH', '/a1', { qrStyle: STORED })).statusCode).toBe(200);
    expect(logoDecode.assertLogoScans).toHaveBeenCalledTimes(1);

    // The org loses verification; the stored style is the one just saved.
    stored(STORED);
    prisma.organization.findUnique.mockImplementation(async () => PRO_UNVERIFIED);
    prisma.organization.findUnique.mockClear();
    prisma.qRCode.update.mockClear();
    logoDecode.assertLogoScans.mockClear();
    // Key order and colour case do not matter: the comparison is canonical.
    const reordered = { ...Object.fromEntries(Object.entries(STORED).reverse()), fg: '#000000', bg: '#ffffff' };
    const res = await send('PATCH', '/a1', { qrStyle: reordered, label: 'renamed' });
    expect(res.statusCode).toBe(200);
    expect(prisma.organization.findUnique).not.toHaveBeenCalled();
    expect(logoDecode.assertLogoScans).not.toHaveBeenCalled();
    const { data } = prisma.qRCode.update.mock.calls[0][0] as { data: Record<string, unknown> };
    expect(data).not.toHaveProperty('style');
    expect(data.label).toBe('renamed');
  });

  it('after losing verification, a changed customer-logo style is 403 logo-verification-required', async () => {
    stored(STORED);
    prisma.organization.findUnique.mockImplementation(async () => PRO_UNVERIFIED);
    const res = await send('PATCH', '/a1', { qrStyle: { ...STORED, logo: { ...STORED.logo, scale: 0.5 } } });
    expect(res.statusCode).toBe(403);
    expect(res.json().code).toBe('logo-verification-required');
    expect(prisma.qRCode.update).not.toHaveBeenCalled();
  });

  it('after a downgrade to FREE, resending a stored frame unchanged is 200 and changing it is 403', async () => {
    const frameStyle = { ...V2, frame: { template: 'badge', text: 'Καφέ', color: '#000000', textColor: '#FFFFFF' } };
    stored(frameStyle);
    expect((await send('PATCH', '/a1', { qrStyle: frameStyle })).statusCode).toBe(200);
    const changed = await send('PATCH', '/a1', { qrStyle: { ...frameStyle, frame: { ...frameStyle.frame, text: 'Καφέ Ωμέγα' } } });
    expect(changed.statusCode).toBe(403);
  });

  it('a stored v1 style equals its v2 upgrade', async () => {
    const { upgradeStyle } = await import('@qrauth/shared/qr-render');
    const v1 = { ...V1, captionText: '' };
    stored(v1);
    prisma.organization.findUnique.mockClear();
    const res = await send('PATCH', '/a1', { qrStyle: upgradeStyle(v1) });
    expect(res.statusCode).toBe(200);
    expect(prisma.organization.findUnique).not.toHaveBeenCalled();
  });
});

describe('caption grandfathering on FREE (ADR-0005 D9, 2026-10-30)', () => {
  // A v1 row with a caption: it reads as a caption frame in the code colours.
  const STORED_V1 = { templateId: 'classic', fgColor: '#000000', bgColor: '#FFFFFF', showLogo: true, captionText: 'QRAuth Verified' };
  const STORED_FRAME = { template: 'caption', text: 'QRAuth Verified', color: '#FFFFFF', textColor: '#000000' };
  const UPGRADED = { ...V2, frame: STORED_FRAME };
  const stored = (style: unknown) =>
    prisma.qRCode.findUnique.mockImplementation(async () => ({
      id: 'qr_1',
      token: 'a1',
      organizationId: 'org_1',
      contentType: 'url',
      content: null,
      style,
    }) as never);
  const writtenStyle = () => (prisma.qRCode.update.mock.calls[0][0] as { data: { style?: unknown } }).data.style;

  beforeEach(() => {
    stored(STORED_V1);
  });

  afterAll(() => {
    stored(undefined);
  });

  it('PATCH editing the caption text of a stored v1 caption is 200, and the new text is stored', async () => {
    const qrStyle = { ...UPGRADED, frame: { ...STORED_FRAME, text: 'Σαρώστε με' } };
    const res = await send('PATCH', '/a1', { qrStyle });
    expect(res.statusCode).toBe(200);
    expect(writtenStyle()).toEqual(qrStyle);
  });

  it('PATCH editing the text of a stored v2 caption frame is 200', async () => {
    stored({ ...V2, presetId: 'custom', frame: { ...STORED_FRAME, text: 'Menu' } });
    const res = await send('PATCH', '/a1', { qrStyle: { ...V2, presetId: 'custom', frame: { ...STORED_FRAME, text: 'Menu today' } } });
    expect(res.statusCode).toBe(200);
  });

  it('colour case does not matter: the stored colours compare canonically', async () => {
    const res = await send('PATCH', '/a1', { qrStyle: { ...UPGRADED, frame: { ...STORED_FRAME, color: '#ffffff', text: 'Scan' } } });
    expect(res.statusCode).toBe(200);
  });

  it('PATCH keeping the caption while changing a field FREE includes (rounded modules) is 200', async () => {
    // A verified issuer: the stored text references QRAuth (claim rule below).
    prisma.organization.findUnique.mockImplementation(async () => ({ plan: 'FREE', domainVerified: true, kycStatus: 'PENDING' }));
    const res = await send('PATCH', '/a1', { qrStyle: { ...UPGRADED, modules: 'rounded' } });
    expect(res.statusCode).toBe(200);
  });

  it.each([
    ['changing the template to banner-bottom', { ...STORED_FRAME, template: 'banner-bottom', color: '#000000', textColor: '#FFFFFF' }],
    ['changing the caption text colour', { ...STORED_FRAME, textColor: '#1B2A4A' }],
    ['changing the caption frame colour', { ...STORED_FRAME, color: '#FFF8E1' }],
  ])('PATCH %s is 403 and nothing is written', async (_label, frame) => {
    const res = await send('PATCH', '/a1', { qrStyle: { ...UPGRADED, frame } });
    expect(res.statusCode).toBe(403);
    expect(res.json()).toEqual({
      statusCode: 403,
      error: 'Forbidden',
      message:
        "On the Free plan, this code's caption can have its text edited or be removed; its template and colours cannot change. Upgrade at https://qrauth.io/dashboard/pricing.",
    });
    expect(prisma.qRCode.update).not.toHaveBeenCalled();
  });

  it('PATCH removing the frame is 200, with template none or without a frame', async () => {
    const none = await send('PATCH', '/a1', { qrStyle: { ...UPGRADED, frame: { ...STORED_FRAME, template: 'none' } } });
    expect(none.statusCode).toBe(200);
    prisma.qRCode.update.mockClear();
    const without = await send('PATCH', '/a1', { qrStyle: V2 });
    expect(without.statusCode).toBe(200);
    expect(writtenStyle()).toEqual(V2);
  });

  it('the save-time scan rules still apply to edited caption text: an unsupported character is 422', async () => {
    const res = await send('PATCH', '/a1', { qrStyle: { ...UPGRADED, frame: { ...STORED_FRAME, text: 'Menu 日本' } } });
    expect(res.statusCode).toBe(422);
    expect(res.json().code).toBe('frame-glyph-unsupported');
    expect(prisma.qRCode.update).not.toHaveBeenCalled();
  });

  it('the save-time scan rules still apply to edited caption text: a stored caption below 4.5:1 is 422 when its text changes', async () => {
    // #767676 on white is 4.54:1; #777777 is 4.48:1, below the text floor.
    const low = { ...STORED_FRAME, textColor: '#777777' };
    stored({ ...V2, frame: low });
    const res = await send('PATCH', '/a1', { qrStyle: { ...V2, frame: { ...low, text: 'Scan' } } });
    expect(res.statusCode).toBe(422);
    expect(res.json().code).toBe('frame-contrast-too-low');
  });

  it('a stored frame other than a caption is not grandfathered: editing its text is 403', async () => {
    const banner = { template: 'banner-bottom', text: 'Scan', color: '#000000', textColor: '#FFFFFF' };
    stored({ ...V2, frame: banner });
    const res = await send('PATCH', '/a1', { qrStyle: { ...V2, frame: { ...banner, text: 'Scan me' } } });
    expect(res.statusCode).toBe(403);
    expect(res.json().message).toMatch(/^Frames and call-to-action templates are not included in the Free plan/);
  });

  it('FREE without a stored frame may not add a caption', async () => {
    stored({ ...V2 });
    const res = await send('PATCH', '/a1', { qrStyle: UPGRADED });
    expect(res.statusCode).toBe(403);
    expect(res.json().message).toMatch(/^Frames and call-to-action templates/);
  });

  it('FREE create with a caption frame is 403', async () => {
    const res = await send('POST', '', { destinationUrl: 'https://example.com', qrStyle: UPGRADED });
    expect(res.statusCode).toBe(403);
    expect(res.json().message).toMatch(/^Frames and call-to-action templates/);
    expect(prisma.qRCode.create).not.toHaveBeenCalled();
  });

  it('a paid plan may change a stored caption freely', async () => {
    prisma.organization.findUnique.mockImplementation(async () => PRO_VERIFIED);
    const res = await send('PATCH', '/a1', { qrStyle: { ...UPGRADED, frame: { ...STORED_FRAME, template: 'banner-bottom', color: '#000000', textColor: '#FFFFFF' } } });
    expect(res.statusCode).toBe(200);
  });
});

describe('frame text that references QRAuth needs a verified issuer (ADR-0005 D9, 2026-10-30)', () => {
  const MESSAGE = 'Only verified organisations can reference QRAuth in frame text.';
  const FREE_UNVERIFIED = { plan: 'FREE', domainVerified: false, kycStatus: 'PENDING' };
  const STORED_V1 = { templateId: 'classic', fgColor: '#000000', bgColor: '#FFFFFF', showLogo: true, captionText: 'QRAuth Verified' };
  const CAPTION = { template: 'caption', text: 'QRAuth Verified', color: '#FFFFFF', textColor: '#000000' };
  const banner = (text: string) => ({ ...V2, frame: { template: 'banner-bottom', text, color: '#000000', textColor: '#FFFFFF' } });
  const stored = (style: unknown) =>
    prisma.qRCode.findUnique.mockImplementation(async () => ({
      id: 'qr_1',
      token: 'a1',
      organizationId: 'org_1',
      contentType: 'url',
      content: null,
      style,
    }) as never);
  const expectRefused = (res: { statusCode: number; json: () => unknown }) => {
    expect(res.statusCode).toBe(403);
    expect(res.json()).toEqual({ statusCode: 403, error: 'Forbidden', code: 'frame-claim-verification-required', message: MESSAGE });
  };

  afterAll(() => {
    stored(undefined);
  });

  it.each([
    'QRAuth',
    'Verified by QRAuth',
    'qrauth.io',
    'Q R A u t h',
    'Q.R.A.U.T.H',
    'Q-R-Auth',
    'q r . a - u t h',
  ])('POST by a paid unverified issuer with frame text %j is 403 and nothing is created', async (text) => {
    // Zero-width, full-width and Unicode-dash variants are caught by the same
    // rule (frame-claim.test.ts) but are 422 first here: the frame font does
    // not draw them (frame-glyph-unsupported).
    prisma.organization.findUnique.mockImplementation(async () => PRO_UNVERIFIED);
    const res = await send('POST', '', { destinationUrl: 'https://example.com', qrStyle: banner(text) });
    expectRefused(res);
    expect(prisma.qRCode.create).not.toHaveBeenCalled();
  });

  it('applies to every template that draws text, the badge included', async () => {
    prisma.organization.findUnique.mockImplementation(async () => PRO_UNVERIFIED);
    for (const template of ['caption', 'banner-top', 'rounded-label', 'badge']) {
      const res = await send('POST', '', {
        destinationUrl: 'https://example.com',
        qrStyle: { ...V2, frame: template === 'caption' ? { ...CAPTION, text: 'QRAuth' } : { template, text: 'QRAuth', color: '#000000', textColor: '#FFFFFF' } },
      });
      expectRefused(res);
    }
  });

  it('a verified issuer may reference QRAuth (domain verified or KYC verified)', async () => {
    stored(banner('Scan'));
    for (const org of [PRO_VERIFIED, { plan: 'BUSINESS', domainVerified: false, kycStatus: 'VERIFIED' }]) {
      prisma.organization.findUnique.mockImplementation(async () => org);
      const res = await send('PATCH', '/a1', { qrStyle: banner('Verified by QRAuth') });
      expect(res.statusCode).toBe(200);
    }
  });

  it('other text is allowed for an unverified issuer', async () => {
    prisma.organization.findUnique.mockImplementation(async () => PRO_UNVERIFIED);
    stored(banner('Scan'));
    for (const text of ['Scan to verify', 'QR menu', 'Q R code', 'Auth required']) {
      const res = await send('PATCH', '/a1', { qrStyle: banner(text) });
      expect(res.statusCode).toBe(200);
    }
  });

  it('PATCH by an unverified issuer adding QRAuth to frame text is 403 and nothing is written', async () => {
    prisma.organization.findUnique.mockImplementation(async () => PRO_UNVERIFIED);
    stored(banner('Scan'));
    const res = await send('PATCH', '/a1', { qrStyle: banner('Scan with Q R Auth') });
    expectRefused(res);
    expect(prisma.qRCode.update).not.toHaveBeenCalled();
  });

  it('a FREE unverified prod-like row (v1 "QRAuth Verified") resent unchanged is exempt', async () => {
    prisma.organization.findUnique.mockImplementation(async () => FREE_UNVERIFIED);
    stored(STORED_V1);
    const res = await send('PATCH', '/a1', { qrStyle: { ...V2, frame: CAPTION } });
    expect(res.statusCode).toBe(200);
    expect(prisma.qRCode.update.mock.calls[0][0]).not.toHaveProperty('data.style');
  });

  it('the same row with another change keeps the QRAuth text, so it is 403', async () => {
    prisma.organization.findUnique.mockImplementation(async () => FREE_UNVERIFIED);
    stored(STORED_V1);
    const res = await send('PATCH', '/a1', { qrStyle: { ...V2, modules: 'rounded', frame: CAPTION } });
    expectRefused(res);
  });

  it('the same row may replace the caption text, or remove it', async () => {
    prisma.organization.findUnique.mockImplementation(async () => FREE_UNVERIFIED);
    stored(STORED_V1);
    expect((await send('PATCH', '/a1', { qrStyle: { ...V2, frame: { ...CAPTION, text: 'Scan me' } } })).statusCode).toBe(200);
    expect((await send('PATCH', '/a1', { qrStyle: V2 })).statusCode).toBe(200);
  });
});

describe('GET /:token', () => {
  it('carries the verification URL the server encodes, so the dashboard previews the same code', async () => {
    const { buildVerificationUrl } = await import('../../lib/qrcode-access.js');
    const res = await app.inject({ method: 'GET', url: '/api/v1/qrcodes/a1' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ token: 'a1', verification_url: buildVerificationUrl('a1') });
  });
});
