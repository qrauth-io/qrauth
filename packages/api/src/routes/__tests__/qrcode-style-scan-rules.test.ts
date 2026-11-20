import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * Scannability rules on write (ADR-0005 D4): a style that breaks one is
 * refused with 422 and the rule's code, on POST / and PATCH /:token, the
 * only routes that accept a style. Nothing is written. Stored styles are not
 * re-checked when read or rendered.
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

const { qrStyleSchema } = await import('../qrcodes.js');
const { upgradeStyle } = await import('@qrauth/shared/qr-render');

/** The v1 shape (stored rows; request bodies must be v2 since PR 6). */
const v1 = (fgColor: string, bgColor: string, showLogo: boolean, templateId = 'custom', captionText = '') => ({
  templateId,
  fgColor,
  bgColor,
  showLogo,
  captionText,
});

/** A v2 request body: the v1 shape's upgrade (inverted follows the colours). */
const style = (fgColor: string, bgColor: string, showLogo: boolean, templateId = 'custom') =>
  upgradeStyle(v1(fgColor, bgColor, showLogo, templateId));

/** The scan-rule codes a style is refused with, or [] when it is accepted. */
function refusedWith(value: unknown): string[] {
  const r = qrStyleSchema.safeParse(value);
  if (r.success) return [];
  return r.error.issues.map((i) => String((i as { params?: { scanRule?: string } }).params?.scanRule ?? i.code));
}

describe('contrast floors on the write schema', () => {
  // On white: #959595 is 2.995:1, #949494 3.03:1; #0089FE 3.4945:1, #008BF4 3.5004:1.
  it('without a logo: 2.99:1 refused, 3.0:1 accepted', () => {
    expect(refusedWith(style('#959595', '#FFFFFF', false))).toContain('contrast-too-low');
    expect(refusedWith(style('#949494', '#FFFFFF', false))).toEqual([]);
  });

  it('with a logo: 3.49:1 refused, 3.5:1 accepted', () => {
    expect(refusedWith(style('#0089FE', '#FFFFFF', true))).toContain('contrast-too-low-with-logo');
    expect(refusedWith(style('#008BF4', '#FFFFFF', true))).toEqual([]);
  });

  // On black: #595959 is 2.998:1, #5A5A5A 3.04:1; #949494 6.92:1, #959595 7.01:1.
  it('light-on-dark without a logo: 3:1 floor', () => {
    expect(refusedWith(style('#595959', '#000000', false))).toContain('contrast-too-low');
    expect(refusedWith(style('#5A5A5A', '#000000', false))).toEqual([]);
  });

  it('light-on-dark with a logo: 7:1 floor', () => {
    expect(refusedWith(style('#949494', '#000000', true))).toContain('contrast-too-low-inverted-with-logo');
    expect(refusedWith(style('#959595', '#000000', true))).toEqual([]);
  });

  it('identical colours are refused', () => {
    expect(refusedWith(style('#FFFFFF', '#FFFFFF', false))).toContain('contrast-too-low');
  });

  // The four v1 shapes stored in production (2026-10-28), caption text
  // neutral: their v2 upgrade, as the dashboard sends it back, validates.
  it.each([
    ['classic, no logo', v1('#000000', '#FFFFFF', false, 'classic', 'Scan to verify!')],
    ['classic, logo', v1('#000000', '#FFFFFF', true, 'classic', 'Scan to verify!')],
    ['custom, no logo', v1('#000000', '#FFFFFF', false, 'custom', 'Scan to verify!')],
    ['midnight, logo', v1('#E0E0E0', '#212121', true, 'midnight', 'Scan to verify!')],
  ])('production style %s still validates as its v2 upgrade', (_label, value) => {
    expect(refusedWith(upgradeStyle(value))).toEqual([]);
  });

  // Every dashboard preset (qr-style-picker.tsx), with and without the logo.
  it.each([
    ['classic', '#000000', '#FFFFFF'],
    ['dark', '#FFFFFF', '#1B2A4A'],
    ['ocean', '#003768', '#E3F2FD'],
    ['forest', '#1B5E20', '#E8F5E9'],
    ['sunset', '#BF360C', '#FFF3E0'],
    ['royal', '#4A148C', '#F3E5F5'],
    ['slate', '#37474F', '#ECEFF1'],
    ['midnight', '#E0E0E0', '#212121'],
  ])('dashboard preset %s validates with and without the logo', (id, fg, bg) => {
    expect(refusedWith(style(fg, bg, false, id))).toEqual([]);
    expect(refusedWith(style(fg, bg, true, id))).toEqual([]);
  });
});

const prisma = {
  qRCode: {
    create: vi.fn(),
    update: vi.fn(),
    findUnique: vi.fn(async () => ({ id: 'qr_1', token: 'a1', organizationId: 'org_1' })),
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

const send = (method: 'POST' | 'PATCH', url: string, payload: unknown) =>
  app.inject({ method, url: `/api/v1/qrcodes${url}`, headers: { 'content-type': 'application/json' }, payload: JSON.stringify(payload) });

describe('routes that accept a style', () => {
  it.each<[string, 'POST' | 'PATCH', string, Record<string, unknown>]>([
    ['POST /', 'POST', '', { destinationUrl: 'https://example.com' }],
    ['PATCH /:token', 'PATCH', '/a1', {}],
  ])('%s: a style below its floor is 422 with the rule code, and nothing is written', async (_label, method, url, base) => {
    const res = await send(method, url, { ...base, qrStyle: style('#FFFFFF', '#FFFFFF', false) });
    expect(res.statusCode).toBe(422);
    expect(res.json()).toMatchObject({ statusCode: 422, error: 'Unprocessable Entity', code: 'contrast-too-low' });
    expect(res.json().details[0].path).toEqual(['body', 'qrStyle']);
    expect(prisma.qRCode.create).not.toHaveBeenCalled();
    expect(prisma.qRCode.update).not.toHaveBeenCalled();
  });

  it('with a logo the code names the logo floor', async () => {
    const res = await send('POST', '', { destinationUrl: 'https://example.com', qrStyle: style('#0089FE', '#FFFFFF', true) });
    expect(res.statusCode).toBe(422);
    expect(res.json().code).toBe('contrast-too-low-with-logo');
  });

  it('a malformed field alongside stays 400', async () => {
    const res = await send('POST', '', { destinationUrl: 'not a url', qrStyle: style('#FFFFFF', '#FFFFFF', false) });
    expect(res.statusCode).toBe(400);
  });
});

describe('malformed styles stay validation errors', () => {
  it.each([
    ['numeric presetId', { presetId: 5 }],
    ['string inverted', { inverted: 'yes' }],
    ['empty presetId', { presetId: '' }],
    ['short hex', { fg: '#FFF' }],
    ['unknown key', { extra: 1 }],
  ])('%s: a field error, no crash and no scan rule', (_label, patch) => {
    const r = qrStyleSchema.safeParse({ ...style('#000000', '#FFFFFF', false), ...patch });
    expect(r.success).toBe(false);
    expect(refusedWith({ ...style('#000000', '#FFFFFF', false), ...patch }).some((c) => c.startsWith('contrast'))).toBe(false);
  });
});
