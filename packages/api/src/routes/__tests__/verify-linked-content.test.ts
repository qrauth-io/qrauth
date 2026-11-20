import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * GET /v/:token for smart link (app-link) and link list codes: platform
 * detection, the FLASH continue target, Web Risk flags that hide an entry,
 * the lookalike check on every link, and trust rules (neutral and UNTRUSTED
 * never continue). Collaborators are mocked as in verify-trust-state.test.ts.
 */

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

const state = vi.hoisted(() => ({
  signatureValid: true,
  trustScore: 100,
  domainCheck: (_url: string): { isSuspicious: boolean; warnings: Array<Record<string, unknown>> } => ({
    isSuspicious: false,
    warnings: [],
  }),
}));

vi.mock('../verify-signatures.js', () => ({
  verifyRowSignatures: vi.fn(async () => ({
    macRejected: false,
    signatureValid: state.signatureValid,
    merkleProofValid: state.signatureValid,
    merkleBatchId: null,
  })),
}));
vi.mock('../../services/hybrid-signing.js', () => ({ HybridSigningService: class {} }));
vi.mock('../../services/mac.js', () => ({ MacService: class {} }));
vi.mock('../../lib/qr-canonical.js', () => ({ buildQrCanonicalCore: vi.fn(async () => 'canonical') }));
vi.mock('../../services/transparency.js', () => ({ TransparencyLogService: class {} }));
vi.mock('../../services/fraud.js', () => ({
  FraudDetectionService: class {
    async getQuickTrustScore() {
      return state.trustScore;
    }
  },
}));
vi.mock('../../services/domain.js', () => ({
  DomainService: class {
    async checkUrlAgainstVerifiedDomains(url: string) {
      return state.domainCheck(url);
    }
    async checkUrlsAgainstVerifiedDomains(urls: string[]) {
      return new Map(urls.map((u) => [u, state.domainCheck(u)]));
    }
  },
}));
vi.mock('../../lib/cache.js', () => ({
  cacheGet: vi.fn(async () => null),
  cacheSet: vi.fn(async () => undefined),
  cacheDel: vi.fn(async () => undefined),
}));
vi.mock('../../lib/queue.js', () => ({ scanQueue: { add: vi.fn(async () => undefined) } }));
vi.mock('../../lib/metadata.js', () => ({
  collectRequestMetadata: vi.fn(async () => ({ ipCity: 'Athens', browser: 'Test', os: 'Test OS' })),
}));
vi.mock('../../services/usage.js', () => ({
  UsageService: class {
    async increment() {
      return 0;
    }
  },
}));
vi.mock('../../services/usage-alerts.js', () => ({ notifyVerificationThreshold: vi.fn(async () => undefined) }));
vi.mock('../verify-quota-headers.js', () => ({
  attachQuotaHeaders: vi.fn(async () => undefined),
  shouldMeterVerification: () => false,
}));

import { linkUrlHash } from '../../services/link-screening.js';

const IOS = 'https://apps.apple.com/app/id123';
const ANDROID = 'https://play.google.com/store/apps/details?id=com.acme';
const WEB = 'https://acme.example/app';
const APP = { iosUrl: IOS, androidUrl: ANDROID, fallbackUrl: WEB };
const LIST = {
  title: 'Acme links',
  description: 'Menu and booking',
  links: [
    { label: 'Menu', url: 'https://acme.example/menu' },
    { label: 'Book a table', url: 'https://book.example/acme' },
  ],
};

const UA = {
  iphone: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
  android: 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36',
  desktop: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
};

const VERIFIED_ORG = {
  id: 'org_1',
  name: 'Acme',
  slug: 'acme',
  trustLevel: 'BUSINESS',
  kycStatus: 'PENDING',
  domain: 'https://acme.example',
  domainVerified: true,
  plan: 'PRO',
  suspendedAt: null,
};
const UNVERIFIED_ORG = { ...VERIFIED_ORG, domain: null, domainVerified: false };

let qrRow: Record<string, unknown>;
let flaggedUrls: string[] = [];

function row(contentType: 'app-link' | 'link-list', overrides: Record<string, unknown> = {}, org = VERIFIED_ORG) {
  return {
    id: 'qr_1',
    token: 'tok_1',
    organizationId: org.id,
    organization: org,
    destinationUrl: 'http://localhost:3000/v/tok_1',
    contentType,
    content: contentType === 'app-link' ? APP : LIST,
    label: 'Get the Acme app',
    status: 'ACTIVE',
    expiresAt: null,
    maxScans: null,
    maxScansPerDevice: null,
    algVersion: 'hybrid-ecdsa-slhdsa-v1',
    transparencyLogEntry: null,
    latitude: null,
    longitude: null,
    radiusM: 50,
    geoHash: null,
    requireProximity: false,
    scanMode: 'FLASH',
    source: 'runtime',
    createdAt: new Date('2026-10-01T00:00:00Z'),
    ...overrides,
  };
}

const prisma = {
  qRCode: { findUnique: vi.fn(async () => qrRow) },
  scan: { count: vi.fn(async () => 0) },
  qRCodeLinkFlag: { findMany: vi.fn(async () => flaggedUrls.map((u) => ({ urlHash: linkUrlHash(u) }))) },
};

let app: FastifyInstance;

const html = (ua: string) =>
  app.inject({ method: 'GET', url: '/v/tok_1', headers: { accept: 'text/html', 'user-agent': ua } });
const json = (ua = UA.iphone) =>
  app.inject({ method: 'GET', url: '/v/tok_1', headers: { accept: 'application/json', 'user-agent': ua } });

beforeAll(async () => {
  app = Fastify();
  app.decorate('prisma', prisma as never);
  app.decorate('signingService', {} as never);
  app.decorate('batchSigner', {} as never);
  const { default: verifyRoutes } = await import('../verify.js');
  await app.register(verifyRoutes, { prefix: '/v' });
  await app.ready();
});

afterAll(async () => {
  await app.close();
});

beforeEach(() => {
  state.signatureValid = true;
  state.trustScore = 100;
  state.domainCheck = () => ({ isSuspicious: false, warnings: [] });
  flaggedUrls = [];
});

const FLASH_SCRIPT = /<script src="\/sdk\/verify-flash\.[0-9a-f]{16}\.js" defer><\/script>/;
const flashHref = (body: string) => /data-flash-href="([^"]*)"/.exec(body)?.[1] ?? null;

describe('smart link: platform and FLASH', () => {
  it.each([
    ['iPhone', UA.iphone, IOS],
    ['Android', UA.android, ANDROID],
    ['desktop', UA.desktop, WEB],
  ])('VERIFIED + FLASH on %s continues to that platform URL', async (_label, ua, expected) => {
    qrRow = row('app-link');

    const res = await html(ua);

    expect(res.statusCode).toBe(200);
    expect(flashHref(res.body)).toBe(expected.replace(/&/g, '&amp;'));
    expect(res.body).toMatch(FLASH_SCRIPT);
    expect(res.headers.vary).toContain('User-Agent');
  });

  it('lists the scanner\'s platform first, then the other two choices', async () => {
    qrRow = row('app-link', { scanMode: 'PAGE' });

    const body = (await html(UA.android)).body;

    expect(flashHref(body)).toBeNull();
    const order = ['Google Play', 'App Store', 'Website'].map((name) => body.indexOf(`<span class="ql-label">${name}`));
    expect(order.every((i) => i > 0)).toBe(true);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
    expect(body).toContain('For your device');
  });

  it('scan mode PAGE shows the three choices and does not continue', async () => {
    qrRow = row('app-link', { scanMode: 'PAGE' });

    const body = (await html(UA.iphone)).body;

    expect(body).not.toMatch(FLASH_SCRIPT);
    for (const url of [IOS, ANDROID, WEB]) expect(body).toContain(`href="${url.replace(/&/g, '&amp;')}"`);
  });

  it('a neutral issuer shows the choices and never continues', async () => {
    qrRow = row('app-link', {}, UNVERIFIED_ORG);

    const body = (await html(UA.iphone)).body;

    expect(flashHref(body)).toBeNull();
    expect(body).not.toMatch(FLASH_SCRIPT);
    expect(body).toContain(`href="${IOS}"`);
    expect(body).not.toContain('class="ql-link ql-primary"');
  });

  it('an UNTRUSTED code shows the choices with a warning and never continues', async () => {
    state.trustScore = 5;
    qrRow = row('app-link');

    const body = (await html(UA.iphone)).body;

    expect(flashHref(body)).toBeNull();
    expect(body).toContain('Do not proceed - this QR code is not verified');
    expect(body).toContain(`href="${IOS}"`);
  });

  it('a location-bound code never continues', async () => {
    qrRow = row('app-link', { latitude: 37.98, longitude: 23.72, requireProximity: false });

    expect(flashHref((await html(UA.iphone)).body)).toBeNull();
  });

  it('a flagged platform link is hidden with a warning, and the scan does not continue', async () => {
    flaggedUrls = [IOS];
    qrRow = row('app-link');

    const body = (await html(UA.iphone)).body;

    expect(flashHref(body)).toBeNull();
    expect(body).not.toContain(IOS);
    expect(body).toContain('The App Store link was removed: Google Web Risk lists it as dangerous.');
    expect(body).toContain(`href="${WEB}"`);
  });

  it('a flagged link of another platform is hidden; this platform still continues', async () => {
    flaggedUrls = [ANDROID];
    qrRow = row('app-link');

    const body = (await html(UA.iphone)).body;

    expect(flashHref(body)).toBe(IOS);
    expect(body).not.toContain('play.google.com');
  });

  it('a lookalike link makes the code UNTRUSTED and is marked', async () => {
    state.domainCheck = (url) => url === WEB
      ? { isSuspicious: true, warnings: [{ domain: 'acme.com', verifiedOrgName: 'Acme Corp', similarity: 90, reason: 'typosquatting', source: 'curated' }] }
      : { isSuspicious: false, warnings: [] };
    qrRow = row('app-link');

    const res = await html(UA.desktop);

    expect(flashHref(res.body)).toBeNull();
    expect(res.body).toContain('Do not proceed - this QR code is not verified');
    expect(res.body).toContain('Looks like acme.com (Acme Corp)');
    const j = (await json()).json();
    expect(j.trust_state).toBe('UNTRUSTED');
    expect(j.domain_warning.similar_to).toBe('acme.com');
  });

  it('JSON keeps the verify page as destination and reports PAGE', async () => {
    qrRow = row('app-link');

    const body = (await json()).json();

    expect(body.trust_state).toBe('VERIFIED');
    expect(body.scan_mode).toBe('PAGE');
    expect(body.destination_url).toBe('http://localhost:3000/v/tok_1');
  });
});

describe('link list', () => {
  it('shows the title, description and links after the reveal, and never continues', async () => {
    qrRow = row('link-list');

    const res = await html(UA.iphone);

    expect(flashHref(res.body)).toBeNull();
    expect(res.body).not.toMatch(FLASH_SCRIPT);
    expect(res.body).toContain('<div class="ql-title">Acme links</div>');
    expect(res.body).toContain('Menu and booking');
    expect(res.body).toContain('href="https://book.example/acme" rel="noopener noreferrer nofollow"');
    expect(res.body.indexOf('id="trust-reveal"')).toBeLessThan(res.body.indexOf('ql-title">Acme links'));
    expect(res.headers.vary ?? '').not.toContain('User-Agent');
  });

  it('a flagged link is hidden with a warning; the rest stay', async () => {
    flaggedUrls = ['https://book.example/acme'];
    qrRow = row('link-list');

    const body = (await html(UA.desktop)).body;

    expect(body).not.toContain('book.example');
    expect(body).toContain('1 link was removed: Google Web Risk lists it as dangerous.');
    expect(body).toContain('href="https://acme.example/menu"');
  });

  it('a lookalike link makes the code UNTRUSTED', async () => {
    state.domainCheck = (url) => url.includes('book.example')
      ? { isSuspicious: true, warnings: [{ domain: 'booking.example', verifiedOrgName: 'Booking', similarity: 85, reason: 'typosquatting' }] }
      : { isSuspicious: false, warnings: [] };
    qrRow = row('link-list');

    expect((await json()).json().trust_state).toBe('UNTRUSTED');
  });

  it('checks every link, not the verify page itself', async () => {
    const seen: string[] = [];
    state.domainCheck = (url) => {
      seen.push(url);
      return { isSuspicious: false, warnings: [] };
    };
    qrRow = row('link-list');

    await json();

    expect(seen).toEqual(['https://acme.example/menu', 'https://book.example/acme']);
  });
});

describe('rendering safety on the full page', () => {
  const XSS = '<img src=x onerror=alert(1)>"\'<script>alert(1)</script>';

  it('escapes user text in every field, and adds no script or event handler', async () => {
    qrRow = row('link-list', {
      label: XSS,
      content: { title: XSS.slice(0, 60), description: XSS, links: [{ label: XSS.slice(0, 40), url: 'https://x.example/?q="><script>alert(1)</script>' }] },
    });

    const body = (await html(UA.desktop)).body;

    expect(body).not.toContain('<script>alert(1)');
    expect(body).not.toContain('<img src=x');
    // User '<' is escaped, so every literal '<' opens a real tag: none may carry an event handler.
    expect(body.match(/<[a-z][^>]*\son[a-z]+\s*=/gi)).toBeNull();
    for (const tag of body.match(/<script\b[^>]*>/g) ?? []) {
      expect(tag).toMatch(/nonce="[^"]+"|src="\/sdk\//);
    }
    expect(body).toContain('href="https://x.example/?q=%22%3E%3Cscript%3Ealert(1)%3C/script%3E"');
  });
});
