import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import { request as httpRequest } from 'node:http';
import type { AddressInfo } from 'node:net';
import Fastify, { type FastifyInstance } from 'fastify';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import sharp from 'sharp';

/**
 * GET /api/v1/qrcodes/:token/image (ADR-0005 D7): roles, organization
 * scoping, query validation, caching headers, the SVG sandbox CSP and the
 * render rate limit. The database is a small in-memory table.
 */

process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

const { SVG_EXPORT_CSP } = await import('../qrcode-image.js');
const { HELMET_OPTIONS } = await import('../../lib/security-headers.js');
const { pngLimiter, PNG_CONCURRENCY, QRAUTH_LOGO_PNG, RENDER_RETRY_AFTER_SECONDS } = await import('../../services/qr-render.js');
const { SemaphoreFullError, SemaphoreTimeoutError } = await import('../../lib/semaphore.js');

type Row = { token: string; organizationId: string; style: unknown; status: string; destinationFlaggedAt: Date | null };
let table: Row[] = [];
let role = 'OWNER';
let orgId = 'org_1';
/** The organization's plan: FREE by default; print PNG and PDF need a paid plan (D9). */
let orgPlan = 'FREE';

const DEFAULT_CSP = "default-src 'self'";

/** org_1's logo library: one normalised PNG (bytes stand in for it; the renderer checks only the signature). */
const LOGO_PNG = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.from('customer-logo')]);
let logoBytes = LOGO_PNG;
const ASSET_STYLE = {
  version: 2, presetId: 'classic', fg: '#000000', bg: '#FFFFFF', inverted: false,
  modules: 'square', eyes: 'square', ecLevel: 'auto', quietZone: 4,
  logo: { kind: 'asset', assetId: 'logo_1', scale: 1 },
};

const prisma = {
  // Organizations are FREE (unless a test sets orgPlan) and unverified: the
  // image endpoint gates only print PNG and PDF on the plan, never the stored
  // style, so a downgraded or no-longer-verified issuer's codes keep
  // rendering (ADR-0005 D9).
  organization: { findUnique: vi.fn(async () => ({ plan: orgPlan, domainVerified: false, kycStatus: 'PENDING' })) },
  contentAsset: {
    findFirst: async ({ where }: { where: { id: string; organizationId: string } }) =>
      where.id === 'logo_1' && where.organizationId === 'org_1' ? { id: 'logo_1' } : null,
  },
  contentAssetBlob: {
    findUnique: async ({ where }: { where: { assetId: string } }) => (where.assetId === 'logo_1' ? { bytes: logoBytes } : null),
  },
  qRCode: {
    findUnique: async ({ where, select }: { where: { token: string }; select: Record<string, boolean> }) => {
      const row = table.find((r) => r.token === where.token);
      if (!row) return null;
      return Object.fromEntries(Object.keys(select).map((k) => [k, row[k as keyof Row]]));
    },
  },
};

let app: FastifyInstance;

const get = (url: string, headers: Record<string, string> = {}, target: FastifyInstance = app) =>
  target.inject({ method: 'GET', url: `/api/v1/qrcodes${url}`, headers });

/** The routes as server.ts mounts them; `limited` adds the rate-limit plugin. */
async function buildApp(limited: boolean): Promise<FastifyInstance> {
  const instance = Fastify();
  instance.decorate('prisma', prisma as never);
  instance.decorateRequest('user', null);
  instance.decorate('authenticate', async (request: { user: unknown }) => {
    request.user = { id: 'user_1', orgId, role, email: 'o@example.com' };
  });
  // The server's security headers (lib/security-headers.ts) and CSP hook.
  await instance.register(helmet, HELMET_OPTIONS);
  if (limited) await instance.register(rateLimit, { global: false });
  // Same CSP mapping as server.ts: a route may override the default per response.
  instance.addHook('onSend', async (request, reply) => {
    const override = (request as unknown as { cspOverride?: string }).cspOverride;
    reply.header('Content-Security-Policy', override ?? DEFAULT_CSP);
  });
  const { default: qrCodeImageRoutes } = await import('../qrcode-image.js');
  await instance.register(qrCodeImageRoutes, { prefix: '/api/v1/qrcodes' });
  await instance.ready();
  return instance;
}

beforeAll(async () => {
  app = await buildApp(false);
});

afterAll(async () => {
  await app.close();
});

beforeEach(() => {
  role = 'OWNER';
  orgId = 'org_1';
  orgPlan = 'FREE';
  table = [
    { token: 'a1', organizationId: 'org_1', style: null, status: 'ACTIVE', destinationFlaggedAt: null },
    {
      token: 'a2',
      organizationId: 'org_1',
      style: { templateId: 'midnight', fgColor: '#E0E0E0', bgColor: '#212121', showLogo: true, captionText: 'Hi' },
      status: 'ACTIVE',
      destinationFlaggedAt: null,
    },
    { token: 'b1', organizationId: 'org_2', style: null, status: 'ACTIVE', destinationFlaggedAt: null },
  ];
});

describe('access', () => {
  it.each(['OWNER', 'ADMIN', 'MANAGER', 'MEMBER', 'VIEWER'])('%s may export', async (r) => {
    role = r;
    expect((await get('/a1/image')).statusCode).toBe(200);
  });

  it('another organization\'s code is 404, with the same body as a missing code', async () => {
    const other = await get('/b1/image');
    const missing = await get('/zz/image');
    expect(other.statusCode).toBe(404);
    expect(missing.statusCode).toBe(404);
    expect(other.json().message).toBe('QR code "b1" not found.');
    expect(Object.keys(other.json()).sort()).toEqual(Object.keys(missing.json()).sort());
    expect(other.headers.etag).toBeUndefined();
  });

  it('the owning organization sees it', async () => {
    orgId = 'org_2';
    expect((await get('/b1/image')).statusCode).toBe(200);
  });
});

describe('query validation', () => {
  it.each([
    '?px=63', '?px=1025', '?px=300.5', '?px=abc', '?download=yes', '?format=jpeg', '?foo=1',
    // Print sizes (PR 6): ranges, and combinations that mean nothing.
    '?size_mm=9.9', '?size_mm=1000.1', '?size_mm=abc', '?size_mm=Infinity', '?size_mm=', '?size_in=0.39', '?size_in=39.4',
    '?dpi=71', '?dpi=1201', '?dpi=300.5', '?format=pdf&margin_mm=51', '?format=pdf&margin_mm=-1',
    '?px=300&size_mm=50', '?px=300&dpi=300', '?size_mm=50&size_in=2', '?format=svg&dpi=300', '?format=pdf&dpi=300',
    '?format=pdf&px=300', '?format=png&size_mm=50&margin_mm=5', '?format=svg&margin_mm=5',
  ])(
    '400 for %s',
    async (query) => {
      expect((await get(`/a1/image${query}`)).statusCode).toBe(400);
    },
  );

  it('400 for a token longer than 64 characters', async () => {
    expect((await get(`/${'x'.repeat(65)}/image`)).statusCode).toBe(400);
  });

  it.each([300, 1024])('PNG at px=%i is exactly that size', async (px) => {
    const res = await get(`/a1/image?format=png&px=${px}`);
    expect(res.statusCode).toBe(200);
    expect(res.headers['x-qrauth-image-px']).toBe(String(px));
    const meta = await sharp(res.rawPayload).metadata();
    expect([meta.format, meta.width, meta.height]).toEqual(['png', px, px]);
  });

  it('px below 3 px/module is raised; the header, filename and ETag give the actual size', async () => {
    const res = await get('/a1/image?format=png&px=64');
    expect(res.statusCode).toBe(200);
    const actual = Number(res.headers['x-qrauth-image-px']);
    expect(actual).toBeGreaterThan(64);
    expect(actual % 3).toBe(0);
    expect((await sharp(res.rawPayload).metadata()).width).toBe(actual);
    expect(res.headers['content-disposition']).toBe(`inline; filename="qrauth-a1-${actual}px.png"`);
    // Asking for 64 or for the minimum itself is the same image.
    expect((await get(`/a1/image?format=png&px=${actual}`)).headers.etag).toBe(res.headers.etag);
  });

  it('defaults to a 300 px PNG', async () => {
    const res = await get('/a1/image');
    expect(res.headers['content-type']).toBe('image/png');
    expect((await sharp(res.rawPayload).metadata()).width).toBe(300);
  });
});

describe('formats and headers', () => {
  it('PNG: private no-cache, inline filename, default CSP', async () => {
    const res = await get('/a1/image?px=512');
    expect(res.headers['cache-control']).toBe('private, no-cache');
    expect(res.headers['content-disposition']).toBe('inline; filename="qrauth-a1-512px.png"');
    expect(res.headers['content-security-policy']).toBe(DEFAULT_CSP);
    expect(res.headers.etag).toMatch(/^"[0-9a-f]{64}"$/);
  });

  it('SVG: sandbox CSP, scalable by default, attachment with download=1', async () => {
    const res = await get('/a1/image?format=svg&download=1');
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toBe('image/svg+xml; charset=utf-8');
    expect(res.headers['content-security-policy']).toBe(SVG_EXPORT_CSP);
    expect(SVG_EXPORT_CSP).toBe("default-src 'none'; img-src data:; style-src 'unsafe-inline'; sandbox; frame-ancestors 'none'");
    expect(res.headers['content-disposition']).toBe('attachment; filename="qrauth-a1.svg"');
    expect(res.body.startsWith('<svg')).toBe(true);
    expect(res.body).not.toContain('width=');
  });

  it('SVG with px names the size', async () => {
    const res = await get('/a1/image?format=svg&px=256');
    expect(res.headers['content-disposition']).toBe('inline; filename="qrauth-a1-256px.svg"');
    expect(res.body).toContain('width="256" height="256"');
  });

  it('applies the stored style: a v1 midnight row with the QRAuth logo', async () => {
    const res = await get('/a2/image?format=svg');
    expect(res.body).toContain('fill="#212121"');
    expect(res.body).toContain('fill="#E0E0E0"');
    expect(res.body).toContain('xlink:href="data:image/png;base64,');
  });
});

describe('security headers (helmet, as in server.ts)', () => {
  it('SVG: nosniff, and exactly the sandbox CSP with frame-ancestors', async () => {
    const res = await get('/a1/image?format=svg');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['content-security-policy']).toBe(
      "default-src 'none'; img-src data:; style-src 'unsafe-inline'; sandbox; frame-ancestors 'none'",
    );
    expect(res.headers['x-frame-options']).toBe('SAMEORIGIN');
  });

  it('PNG: nosniff, and the default CSP', async () => {
    const res = await get('/a1/image?format=png');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['content-security-policy']).toBe(DEFAULT_CSP);
  });
});

describe('ETag', () => {
  it('304 without a body when If-None-Match matches', async () => {
    const first = await get('/a1/image?px=300');
    const etag = first.headers.etag as string;
    for (const header of [etag, `W/${etag}`, `"other", ${etag}`, '*']) {
      const again = await get('/a1/image?px=300', { 'if-none-match': header });
      expect(again.statusCode).toBe(304);
      expect(again.rawPayload.length).toBe(0);
      expect(again.headers.etag).toBe(etag);
      expect(again.headers['cache-control']).toBe('private, no-cache');
    }
  });

  it('200 when the tag no longer matches: another size, format or style', async () => {
    const etag = (await get('/a1/image?px=300')).headers.etag as string;
    expect((await get('/a1/image?px=301', { 'if-none-match': etag })).statusCode).toBe(200);
    expect((await get('/a1/image?format=svg&px=300', { 'if-none-match': etag })).statusCode).toBe(200);
    table[0].style = { templateId: 'classic', fgColor: '#1A2B3C', bgColor: '#FFFFFF', showLogo: false, captionText: '' };
    expect((await get('/a1/image?px=300', { 'if-none-match': etag })).statusCode).toBe(200);
  });

  it('another organization\'s code is 404 even with a matching If-None-Match', async () => {
    orgId = 'org_2';
    const etag = (await get('/b1/image')).headers.etag as string;
    orgId = 'org_1';
    expect((await get('/b1/image', { 'if-none-match': etag })).statusCode).toBe(404);
  });
});

describe('code state', () => {
  // The image encodes only the verification URL; revocation, expiry,
  // flagging and suspension are all decided when the code is scanned.
  it.each<[string, Partial<Row>]>([
    ['revoked', { status: 'REVOKED' }],
    ['expired', { status: 'EXPIRED' }],
    ['destination flagged', { destinationFlaggedAt: new Date() }],
  ])('a %s code still renders, identical to the active one', async (_label, patch) => {
    const active = await get('/a1/image?format=svg');
    Object.assign(table[0], patch);
    const changed = await get('/a1/image?format=svg');
    expect(changed.statusCode).toBe(200);
    expect(changed.body).toBe(active.body);
    expect(changed.headers.etag).toBe(active.headers.etag);
  });
});

describe('customer logos (ADR-0005 PR 4)', () => {
  it('draws the organization’s logo bytes into the export', async () => {
    table.push({ token: 'a3', organizationId: 'org_1', style: ASSET_STYLE, status: 'ACTIVE', destinationFlaggedAt: null });
    const res = await get('/a3/image?format=svg');
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain(`data:image/png;base64,${LOGO_PNG.toString('base64')}`);
  });

  it('a downgraded (FREE), unverified organization’s stored customer logo still renders, as SVG and PNG', async () => {
    table.push({ token: 'a3', organizationId: 'org_1', style: ASSET_STYLE, status: 'ACTIVE', destinationFlaggedAt: null });
    const svg = await get('/a3/image?format=svg');
    expect(svg.statusCode).toBe(200);
    expect(svg.body).toContain(`data:image/png;base64,${LOGO_PNG.toString('base64')}`);
    const png = await get('/a3/image?format=png&px=512');
    expect(png.statusCode).toBe(200);
    expect(png.headers['content-type']).toBe('image/png');
    // The organization is read for its issuer status (the badge mark) and its
    // plan, which gates print PNG and PDF only, never the stored style.
    for (const [arg] of prisma.organization.findUnique.mock.calls as unknown as [{ select: Record<string, boolean> }][]) {
      expect(arg.select).toEqual({ domainVerified: true, kycStatus: true, plan: true });
    }
  });

  it('a code naming a logo its organization does not own renders with the logo area empty', async () => {
    table.push({ token: 'b3', organizationId: 'org_2', style: ASSET_STYLE, status: 'ACTIVE', destinationFlaggedAt: null });
    orgId = 'org_2';
    const res = await get('/b3/image?format=svg');
    expect(res.statusCode).toBe(200);
    expect(res.body).not.toContain(LOGO_PNG.toString('base64'));
  });

  it('the ETag follows the logo bytes, not only the style', async () => {
    table.push({ token: 'a3', organizationId: 'org_1', style: ASSET_STYLE, status: 'ACTIVE', destinationFlaggedAt: null });
    const before = await get('/a3/image?format=svg');
    logoBytes = Buffer.concat([LOGO_PNG, Buffer.from('v2')]);
    try {
      const after = await get('/a3/image?format=svg');
      expect(after.headers.etag).not.toBe(before.headers.etag);
    } finally {
      logoBytes = LOGO_PNG;
    }
  });
});

describe('grandfathered captions (ADR-0005 D9, 2026-10-30)', () => {
  it('a FREE organization’s stored v1 captionText renders as the caption frame', async () => {
    // a2 is a v1 row with captionText "Hi"; every organization here is FREE.
    const { renderStyled, styleForRender } = await import('../../services/qr-render.js');
    const { buildVerificationUrl } = await import('../../lib/qrcode-access.js');
    const style = styleForRender(table.find((r) => r.token === 'a2')!.style);
    expect(style.frame).toMatchObject({ template: 'caption', text: 'Hi' });

    const res = await get('/a2/image?format=svg');
    expect(res.statusCode).toBe(200);
    const framed = renderStyled({ data: buildVerificationUrl('a2'), style, logoPng: QRAUTH_LOGO_PNG, issuerVerified: false });
    expect(res.body).toBe(framed.svg);
    // The caption adds a text band under the code, drawn as outlined glyphs.
    expect(framed.meta.height).toBeGreaterThan(framed.meta.width);
    expect(framed.meta.notDrawn).toEqual([]);
    const { frame: _frame, ...unframed } = style;
    expect(res.body).not.toBe(renderStyled({ data: buildVerificationUrl('a2'), style: unframed, logoPng: QRAUTH_LOGO_PNG }).svg);
  });
});

describe('old default caption by issuer status (ADR-0005 D9, 2026-10-30)', () => {
  // The two prod rows: FREE, unverified issuer, v1 style with the old default caption.
  const PROD_LIKE = [
    { token: 'p1', style: { templateId: 'classic', fgColor: '#000000', bgColor: '#FFFFFF', showLogo: true, captionText: 'QRAuth Verified' } },
    { token: 'p2', style: { templateId: 'dark', fgColor: '#FFFFFF', bgColor: '#1B2A4A', showLogo: true, captionText: 'QRAuth Verified' } },
  ];
  const FREE_UNVERIFIED = { plan: 'FREE', domainVerified: false, kycStatus: 'PENDING' };
  const VERIFIED = { plan: 'PRO', domainVerified: true, kycStatus: 'PENDING' };

  /** The shared renderer's SVG of `token`'s stored style with its frame text set to `text`, drawn as is. */
  async function svgWithText(token: string, text: string): Promise<string> {
    const { renderStyled, styleForRender } = await import('../../services/qr-render.js');
    const { buildVerificationUrl } = await import('../../lib/qrcode-access.js');
    const style = styleForRender(PROD_LIKE.find((r) => r.token === token)!.style);
    const withText = { ...style, frame: { ...style.frame!, text } };
    return renderStyled({ data: buildVerificationUrl(token), style: withText, logoPng: QRAUTH_LOGO_PNG, issuerVerified: true }).svg;
  }

  beforeEach(() => {
    for (const row of PROD_LIKE) table.push({ ...row, organizationId: 'org_1', status: 'ACTIVE', destinationFlaggedAt: null });
  });

  afterAll(() => {
    prisma.organization.findUnique.mockImplementation(async () => FREE_UNVERIFIED);
  });

  it.each(PROD_LIKE.map((r) => r.token))('FREE unverified row %s exports "Signed with QRAuth"', async (token) => {
    prisma.organization.findUnique.mockImplementation(async () => FREE_UNVERIFIED);
    const res = await get(`/${token}/image?format=svg`);
    expect(res.statusCode).toBe(200);
    expect(res.body).toBe(await svgWithText(token, 'Signed with QRAuth'));
    expect(res.body).not.toBe(await svgWithText(token, 'QRAuth Verified'));
  });

  it.each(PROD_LIKE.map((r) => r.token))('a verified organization’s row %s still exports "QRAuth Verified"', async (token) => {
    prisma.organization.findUnique.mockImplementation(async () => VERIFIED);
    const res = await get(`/${token}/image?format=svg`);
    expect(res.statusCode).toBe(200);
    expect(res.body).toBe(await svgWithText(token, 'QRAuth Verified'));
  });

  it('the PNG export changes with verification, and so does its ETag', async () => {
    prisma.organization.findUnique.mockImplementation(async () => FREE_UNVERIFIED);
    const signed = await get('/p1/image?format=png&px=512');
    prisma.organization.findUnique.mockImplementation(async () => VERIFIED);
    const verified = await get('/p1/image?format=png&px=512', { 'if-none-match': signed.headers.etag as string });
    expect(verified.statusCode).toBe(200);
    expect(verified.headers.etag).not.toBe(signed.headers.etag);
    expect(verified.rawPayload.equals(signed.rawPayload)).toBe(false);
  });

  it('a caption with other text keeps its ETag when verification changes', async () => {
    prisma.organization.findUnique.mockImplementation(async () => FREE_UNVERIFIED);
    const before = await get('/a2/image');
    prisma.organization.findUnique.mockImplementation(async () => VERIFIED);
    expect((await get('/a2/image', { 'if-none-match': before.headers.etag as string })).statusCode).toBe(304);
  });
});

describe('badge mark by issuer status (ADR-0005 D9, 2026-10-30)', () => {
  const BADGE_STYLE = {
    version: 2, presetId: 'classic', fg: '#000000', bg: '#FFFFFF', inverted: false,
    modules: 'square', eyes: 'square', ecLevel: 'auto', quietZone: 4, logo: null,
    frame: { template: 'badge', text: 'Καφέ Ωμέγα', color: '#003768', textColor: '#FFFFFF' },
  };
  const UNVERIFIED = { plan: 'PRO', domainVerified: false, kycStatus: 'UNDER_REVIEW' };

  /** The shared renderer's SVG for the badge code, with the issuer status passed explicitly. */
  async function expectedSvg(issuerVerified: boolean): Promise<string> {
    const { renderStyled, styleForRender } = await import('../../services/qr-render.js');
    const { buildVerificationUrl } = await import('../../lib/qrcode-access.js');
    return renderStyled({ data: buildVerificationUrl('a4'), style: styleForRender(BADGE_STYLE), logoPng: null, issuerVerified }).svg;
  }

  beforeEach(() => {
    table.push({ token: 'a4', organizationId: 'org_1', style: BADGE_STYLE, status: 'ACTIVE', destinationFlaggedAt: null });
  });

  afterAll(() => {
    prisma.organization.findUnique.mockImplementation(async () => ({ plan: orgPlan, domainVerified: false, kycStatus: 'PENDING' }));
  });

  it.each([
    ['a verified domain', { plan: 'PRO', domainVerified: true, kycStatus: 'PENDING' }],
    ['an approved KYC review', { plan: 'FREE', domainVerified: false, kycStatus: 'VERIFIED' }],
  ])('an organization with %s prints "Verified by QRAuth"', async (_label, org) => {
    prisma.organization.findUnique.mockImplementation(async () => org);
    const res = await get('/a4/image?format=svg');
    expect(res.statusCode).toBe(200);
    expect(res.body).toBe(await expectedSvg(true));
    expect(res.body).not.toBe(await expectedSvg(false));
  });

  it('an unverified organization prints "Signed with QRAuth"', async () => {
    prisma.organization.findUnique.mockImplementation(async () => UNVERIFIED);
    const res = await get('/a4/image?format=svg');
    expect(res.statusCode).toBe(200);
    expect(res.body).toBe(await expectedSvg(false));
    expect(res.body).not.toBe(await expectedSvg(true));
  });

  it('a change in verification changes the image and its ETag, so a cached copy is not reused', async () => {
    prisma.organization.findUnique.mockImplementation(async () => UNVERIFIED);
    const before = await get('/a4/image?format=png&px=512');
    prisma.organization.findUnique.mockImplementation(async () => ({ ...UNVERIFIED, domainVerified: true }));
    const revalidated = await get('/a4/image?format=png&px=512', { 'if-none-match': before.headers.etag as string });
    expect(revalidated.statusCode).toBe(200);
    expect(revalidated.headers.etag).not.toBe(before.headers.etag);
    expect(revalidated.rawPayload.equals(before.rawPayload)).toBe(false);
  });

  it('a code without a badge keeps its ETag when verification changes', async () => {
    prisma.organization.findUnique.mockImplementation(async () => UNVERIFIED);
    const before = await get('/a1/image');
    prisma.organization.findUnique.mockImplementation(async () => ({ ...UNVERIFIED, domainVerified: true }));
    const after = await get('/a1/image', { 'if-none-match': before.headers.etag as string });
    expect(after.statusCode).toBe(304);
  });
});

describe('rate limit', () => {
  it('the render tier allows 60 requests a minute, then 429', async () => {
    const limited = await buildApp(true);
    try {
      const statuses: number[] = [];
      for (let i = 0; i < 61; i++) statuses.push((await get('/a1/image?format=svg', {}, limited)).statusCode);
      expect(statuses.slice(0, 60)).toEqual(new Array<number>(60).fill(200));
      expect(statuses[60]).toBe(429);
      const last = await get('/a1/image?format=svg', {}, limited);
      expect(last.headers['x-ratelimit-limit']).toBe('60');
    } finally {
      await limited.close();
    }
  });
});

describe('PNG queue', () => {
  it.each([
    ['full', () => new SemaphoreFullError('export')],
    ['timed out', () => new SemaphoreTimeoutError('export', 10_000)],
  ])('queue %s: 503 with Retry-After and no image headers', async (_label, error) => {
    const spy = vi.spyOn(pngLimiter, 'run').mockRejectedValueOnce(error());
    try {
      const res = await get('/a1/image?format=png');
      expect(res.statusCode).toBe(503);
      expect(res.headers['retry-after']).toBe(String(RENDER_RETRY_AFTER_SECONDS));
      expect(res.headers['cache-control']).toBe('no-store');
      expect(res.headers.etag).toBeUndefined();
      expect(res.headers['content-disposition']).toBeUndefined();
      expect(res.headers['x-qrauth-image-px']).toBeUndefined();
      expect(spy.mock.calls[0][1]).toMatchObject({ lane: 'export' });
    } finally {
      spy.mockRestore();
    }
  });

  it('SVG does not use the PNG queue', async () => {
    const spy = vi.spyOn(pngLimiter, 'run');
    try {
      expect((await get('/a1/image?format=svg')).statusCode).toBe(200);
      expect(spy).not.toHaveBeenCalled();
    } finally {
      spy.mockRestore();
    }
  });

  it('a client that disconnects while queued leaves the queue without a render', async () => {
    const server = await buildApp(false);
    await server.listen({ port: 0, host: '127.0.0.1' });
    const { port } = server.server.address() as AddressInfo;
    // Hold every slot so the request has to wait.
    const releases: Array<() => void> = [];
    const holders = Array.from({ length: PNG_CONCURRENCY }, () =>
      pngLimiter.run(() => new Promise<void>((r) => releases.push(r))),
    );
    try {
      await vi.waitFor(() => expect(pngLimiter.inUse).toBe(PNG_CONCURRENCY));
      const req = httpRequest({ host: '127.0.0.1', port, path: '/api/v1/qrcodes/a1/image?format=png' });
      req.on('error', () => undefined);
      req.end();
      await vi.waitFor(() => expect(pngLimiter.queued('export')).toBe(1));
      req.destroy();
      await vi.waitFor(() => expect(pngLimiter.queued('export')).toBe(0));
      // Still no free slot: the request left the queue without rendering.
      expect(pngLimiter.inUse).toBe(PNG_CONCURRENCY);
    } finally {
      releases.forEach((r) => r());
      await Promise.all(holders);
      await server.close();
    }
  });
});


describe('print export plan gate (ADR-0005 D9)', () => {
  it.each(['?format=pdf', '?format=pdf&size_mm=50', '?format=png&size_mm=30', '?format=png&dpi=300', '?size_in=2'])(
    'FREE: 403 for %s, with the content-type gate’s body shape',
    async (query) => {
      const res = await get(`/a1/image${query}`);
      expect(res.statusCode).toBe(403);
      const body = res.json();
      expect(Object.keys(body).sort()).toEqual(['error', 'message', 'statusCode']);
      expect(body.error).toBe('Forbidden');
      expect(body.message).toMatch(/not included in the Free plan.* Upgrade at https:\/\/qrauth\.io\/dashboard\/pricing\.$/);
      expect(res.headers.etag).toBeUndefined();
    },
  );

  it('FREE: the PDF and print PNG messages say what is refused', async () => {
    expect((await get('/a1/image?format=pdf')).json().message).toMatch(/^PDF export is not included in the Free plan/);
    expect((await get('/a1/image?size_mm=30')).json().message).toMatch(/^Print-size PNG export .* PNG up to 1024 px/);
  });

  it('FREE keeps SVG (also at a physical size) and PNG up to 1024 px', async () => {
    expect((await get('/a1/image?format=png&px=1024')).statusCode).toBe(200);
    expect((await get('/a1/image?format=svg')).statusCode).toBe(200);
    const mm = await get('/a1/image?format=svg&size_mm=30');
    expect(mm.statusCode).toBe(200);
    expect(mm.body).toContain('width="30mm" height="30mm"');
    expect(mm.headers['content-disposition']).toBe('inline; filename="qrauth-a1-30mm.svg"');
  });

  it('a validation error is 400 before the plan gate', async () => {
    expect((await get('/a1/image?format=pdf&size_mm=5000')).statusCode).toBe(400);
  });

  it.each(['PRO', 'BUSINESS', 'ENTERPRISE'])('%s may export print PNG and PDF', async (plan) => {
    orgPlan = plan;
    expect((await get('/a1/image?size_mm=30')).statusCode).toBe(200);
    expect((await get('/a1/image?format=pdf')).statusCode).toBe(200);
  });
});

describe('print PNG (PR 6)', () => {
  beforeEach(() => {
    orgPlan = 'PRO';
  });

  it('30 mm at 300 dpi is 354 px with 300 dpi in pHYs, named with size and dpi', async () => {
    const res = await get('/a1/image?format=png&size_mm=30&dpi=300&download=1');
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toBe('image/png');
    expect(res.headers['x-qrauth-image-px']).toBe('354');
    expect(res.headers['content-disposition']).toBe('attachment; filename="qrauth-a1-30mm-300dpi.png"');
    const meta = await sharp(res.rawPayload).metadata();
    expect([meta.width, meta.height, meta.density]).toEqual([354, 354, 300]);
  });

  it('size alone defaults to 300 dpi, dpi alone to 50 mm', async () => {
    expect((await get('/a1/image?size_mm=30')).headers['x-qrauth-image-px']).toBe('354');
    expect((await get('/a1/image?dpi=600')).headers['x-qrauth-image-px']).toBe('1181');
  });

  it('size_in is converted to mm (2 in = 50.8 mm, 600 px at 300 dpi)', async () => {
    const res = await get('/a1/image?size_in=2&dpi=300');
    expect(res.headers['x-qrauth-image-px']).toBe('600');
    expect(res.headers['content-disposition']).toBe('inline; filename="qrauth-a1-50.8mm-300dpi.png"');
    expect(res.headers.etag).toBe((await get('/a1/image?size_mm=50.8&dpi=300')).headers.etag);
  });

  it('a screen PNG keeps sharp’s default density, and its ETag differs from a print PNG of the same width', async () => {
    const res = await get('/a1/image?px=354');
    // sharp's default 72 dpi, as before PR 6.
    expect((await sharp(res.rawPayload).metadata()).density).toBe(72);
    expect(res.headers.etag).not.toBe((await get('/a1/image?size_mm=30&dpi=300')).headers.etag);
  });

  it('the ETag follows size and dpi, and a match is 304', async () => {
    const a = (await get('/a1/image?size_mm=30&dpi=300')).headers.etag as string;
    expect((await get('/a1/image?size_mm=30&dpi=600')).headers.etag).not.toBe(a);
    expect((await get('/a1/image?size_mm=31&dpi=300')).headers.etag).not.toBe(a);
    expect((await get('/a1/image?size_mm=30&dpi=300', { 'if-none-match': a })).statusCode).toBe(304);
  });

  it('modules under 0.4 mm are 422 print-size-too-small, naming the minimum size', async () => {
    const res = await get('/a1/image?size_mm=10');
    expect(res.statusCode).toBe(422);
    expect(res.json()).toMatchObject({ code: 'print-size-too-small' });
    expect(res.json().message).toMatch(/the minimum is 0\.4 mm, so this code needs at least \d+(\.\d)? mm\.$/);
  });

  it('under 3 px per module is 422, naming the dpi needed', async () => {
    const res = await get('/a1/image?size_mm=20&dpi=72');
    expect(res.statusCode).toBe(422);
    expect(res.json().message).toMatch(/use at least \d+ dpi or a larger size/);
  });

  it('a raster above the caps is 400 print-raster-too-large, stating the maximum', async () => {
    const res = await get('/a1/image?size_mm=1000&dpi=1200');
    expect(res.statusCode).toBe(400);
    const body = res.json();
    expect(body.code).toBe('print-raster-too-large');
    expect(body.message).toMatch(/the maximum is 12,000 px per side and 100 megapixels\. At 1200 dpi this code can be at most 211\.\d mm wide\.$/);
  });

  it('print renders use the PNG queue on the export lane', async () => {
    const spy = vi.spyOn(pngLimiter, 'run');
    try {
      expect((await get('/a1/image?size_mm=30')).statusCode).toBe(200);
      expect(spy.mock.calls[0][1]).toMatchObject({ lane: 'export' });
    } finally {
      spy.mockRestore();
    }
  });
});

describe('PDF (PR 6)', () => {
  beforeEach(() => {
    orgPlan = 'PRO';
  });

  it('a vector PDF: application/pdf, nosniff, named by size, page = artwork in points', async () => {
    const res = await get('/a1/image?format=pdf&size_mm=50&download=1');
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toBe('application/pdf');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['content-disposition']).toBe('attachment; filename="qrauth-a1-50mm.pdf"');
    expect(res.headers['x-qrauth-image-px']).toBeUndefined();
    const pdf = res.rawPayload.toString('latin1');
    expect(pdf.startsWith('%PDF-1.4')).toBe(true);
    const side = (50 * 72) / 25.4;
    const box = /\/MediaBox \[0 0 ([\d.]+) ([\d.]+)\]/.exec(pdf);
    expect(Number(box?.[1])).toBeCloseTo(side, 2);
    expect(Number(box?.[2])).toBeCloseTo(side, 2);
  });

  it('defaults to 50 mm; margin_mm adds to every side and to the ETag', async () => {
    const plain = await get('/a1/image?format=pdf');
    const margin = await get('/a1/image?format=pdf&margin_mm=5');
    expect(plain.headers['content-disposition']).toBe('inline; filename="qrauth-a1-50mm.pdf"');
    expect(margin.headers.etag).not.toBe(plain.headers.etag);
    const box = /\/MediaBox \[0 0 ([\d.]+)/.exec(margin.rawPayload.toString('latin1'));
    expect(Number(box?.[1])).toBeCloseTo((60 * 72) / 25.4, 2);
  });

  it('two renders are byte-identical with the same ETag, and a match is 304', async () => {
    const a = await get('/a1/image?format=pdf&size_mm=40');
    const b = await get('/a1/image?format=pdf&size_mm=40');
    expect(a.rawPayload.equals(b.rawPayload)).toBe(true);
    expect(a.headers.etag).toBe(b.headers.etag);
    expect((await get('/a1/image?format=pdf&size_mm=40', { 'if-none-match': a.headers.etag as string })).statusCode).toBe(304);
  });

  it('metadata names QRAuth and the token only, never internal ids', async () => {
    const pdf = (await get('/a1/image?format=pdf')).rawPayload.toString('latin1');
    // pdfkit writes Info values as indirect string objects.
    const strings = [...pdf.matchAll(/\d+ 0 obj\n\((.*)\)\nendobj/g)].map((m) => m[1]);
    expect(strings).toEqual(['QRAuth', 'QRAuth qrauth-qr/2', 'D:20261030000000Z', 'QR code a1']);
    expect(pdf).not.toContain('/ModDate');
    expect(pdf).not.toContain('org_1');
    expect(pdf).not.toContain('user_1');
    expect(pdf).not.toContain('PDFKit');
  });

  it('modules under 0.4 mm are 422 for PDF too', async () => {
    expect((await get('/a1/image?format=pdf&size_mm=10')).statusCode).toBe(422);
  });

  it('PDFs use the PNG queue on the export lane; a busy queue is 503', async () => {
    const spy = vi.spyOn(pngLimiter, 'run').mockRejectedValueOnce(new SemaphoreFullError('export'));
    try {
      const res = await get('/a1/image?format=pdf');
      expect(res.statusCode).toBe(503);
      expect(spy.mock.calls[0][1]).toMatchObject({ lane: 'export' });
    } finally {
      spy.mockRestore();
    }
  });
});
