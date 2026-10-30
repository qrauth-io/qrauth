import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * GET /v/:token — response shape for the verify page and the JSON API.
 *
 * Every collaborator that touches crypto, Redis or the queue is mocked, so
 * these tests drive only the route's decision and rendering logic. Each test
 * sets the QR row, the organization, the signature outcome, the quick trust
 * score and the domain-similarity result it needs.
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

const ORG_NAME = 'Acme Payments Ltd';
const DESTINATION = 'https://pay.example.com/checkout';

type OrgFixture = {
  id: string;
  name: string;
  slug: string;
  trustLevel: string;
  kycStatus: string;
  domain: string | null;
  domainVerified: boolean;
  plan: string;
  suspendedAt: Date | null;
};

const UNVERIFIED_ORG: OrgFixture = {
  id: 'org_1',
  name: ORG_NAME,
  slug: 'acme',
  trustLevel: 'INDIVIDUAL',
  kycStatus: 'PENDING',
  domain: null,
  domainVerified: false,
  plan: 'FREE',
  suspendedAt: null,
};

let qrRow: Record<string, unknown>;

function makeQrRow(overrides: Record<string, unknown> = {}, org: OrgFixture = UNVERIFIED_ORG) {
  return {
    id: 'qr_1',
    token: 'tok_1',
    organizationId: org.id,
    organization: org,
    destinationUrl: DESTINATION,
    contentType: 'url',
    content: null,
    label: 'Parking',
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
};

let app: FastifyInstance;

const getJson = (token = 'tok_1') =>
  app.inject({ method: 'GET', url: `/v/${token}`, headers: { accept: 'application/json' } });
const getHtml = (token = 'tok_1') =>
  app.inject({ method: 'GET', url: `/v/${token}`, headers: { accept: 'text/html' } });

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
  qrRow = makeQrRow();
});

describe('failure responses carry no destination', () => {
  it.each([
    ['revoked', { status: 'REVOKED' }],
    ['expired by status', { status: 'EXPIRED' }],
    ['expired by date', { expiresAt: new Date('2020-01-01T00:00:00Z') }],
  ])('JSON: %s', async (_label, overrides) => {
    qrRow = makeQrRow(overrides);

    const res = await getJson();
    const body = res.json();

    expect(body.verified).toBe(false);
    expect(body).not.toHaveProperty('destination_url');
    expect(res.body).not.toContain('pay.example.com');
  });

  it.each([
    ['revoked', { status: 'REVOKED' }],
    ['expired', { status: 'EXPIRED' }],
  ])('HTML: %s', async (_label, overrides) => {
    qrRow = makeQrRow(overrides);

    const res = await getHtml();

    expect(res.headers['content-type']).toContain('text/html');
    expect(res.body).not.toContain('pay.example.com');
    expect(res.body).not.toContain('Continue to');
  });
});

// ---------------------------------------------------------------------------
// Trust state
// ---------------------------------------------------------------------------

const DOMAIN_VERIFIED_ORG: OrgFixture = {
  ...UNVERIFIED_ORG,
  domain: 'https://acme.example',
  domainVerified: true,
};
const KYC_VERIFIED_ORG: OrgFixture = { ...UNVERIFIED_ORG, kycStatus: 'VERIFIED' };
const UNDER_REVIEW_ORG: OrgFixture = { ...UNVERIFIED_ORG, kycStatus: 'UNDER_REVIEW' };

const LOOKALIKE = 'https://acrne.example/pay';
const lookalikeCheck = (url: string) =>
  url === LOOKALIKE
    ? {
        isSuspicious: true,
        warnings: [{ domain: 'acme.example', verifiedOrgName: 'Acme', similarity: 0.9, reason: 'typosquat' }],
      }
    : { isSuspicious: false, warnings: [] };

const GREEN_CHECK_PATH = 'M62 104 L88 134 L144 64';

function headSection(html: string): string {
  return html.slice(0, html.indexOf('</head>'));
}

function metaContent(html: string, attr: string, name: string): string | undefined {
  const re = new RegExp(`<meta ${attr}="${name}" content="([^"]*)"`);
  return re.exec(html)?.[1];
}

describe('SIGNED_UNVERIFIED_ISSUER — free, unverified org', () => {
  it('JSON: trust_state and verified=false', async () => {
    const body = (await getJson()).json();

    expect(body.trust_state).toBe('SIGNED_UNVERIFIED_ISSUER');
    expect(body.verified).toBe(false);
    expect(body.destination_url).toBe(DESTINATION);
  });

  it('HTML: neutral copy, no org name in body, title or meta', async () => {
    const html = (await getHtml()).body;

    expect(html).not.toContain(ORG_NAME);
    expect(html).toContain('Authentic signed code');
    expect(html).toContain('Issuer not verified by QRAuth');
    expect(html).toContain('<title>Authentic signed code — issuer not verified by QRAuth | QRAuth</title>');
    // No "Verified" word, no green check shield, no fraud alarm.
    expect(html).not.toMatch(/\bVerified\b/);
    expect(html).not.toContain(GREEN_CHECK_PATH);
    expect(html).not.toContain('Fraudulent Code Detected');
    expect(html).toContain('trust-reveal trust-neutral');
    for (const [attr, name] of [
      ['property', 'og:title'],
      ['property', 'og:description'],
      ['name', 'twitter:title'],
      ['name', 'twitter:description'],
    ]) {
      const content = metaContent(html, attr, name) ?? '';
      expect(content).not.toContain(ORG_NAME);
      expect(content.toLowerCase()).not.toContain('cryptographically verified');
    }
  });

  it('HTML: destination host shown above the Continue button', async () => {
    const html = (await getHtml()).body;

    const hostIdx = html.indexOf('data-destination-host');
    expect(hostIdx).toBeGreaterThan(-1);
    expect(html.indexOf('Continue to pay.example.com')).toBeGreaterThan(hostIdx);
  });

  it('UNDER_REVIEW (after POST /organizations/:id/verify) is still SIGNED_UNVERIFIED_ISSUER', async () => {
    qrRow = makeQrRow({}, UNDER_REVIEW_ORG);

    const body = (await getJson()).json();
    const html = (await getHtml()).body;

    expect(body.trust_state).toBe('SIGNED_UNVERIFIED_ISSUER');
    expect(body.verified).toBe(false);
    expect(html).not.toContain('Verification Pending');
    expect(html).not.toContain(ORG_NAME);
  });
});

describe('VERIFIED — verified issuer', () => {
  it('domain-verified org: green reveal, org name and verified domain host', async () => {
    qrRow = makeQrRow({}, DOMAIN_VERIFIED_ORG);

    const body = (await getJson()).json();
    const html = (await getHtml()).body;

    expect(body.trust_state).toBe('VERIFIED');
    expect(body.verified).toBe(true);
    expect(body.organization).not.toHaveProperty('domain');
    expect(html).toContain(GREEN_CHECK_PATH);
    expect(html).toContain(`Issued by <strong>${ORG_NAME}</strong>`);
    expect(html).toContain('<div class="status-domain">acme.example</div>');
    expect(headSection(html)).toContain(`Cryptographically verified QR code issued by ${ORG_NAME}`);
  });

  it('KYC-verified org without a domain is VERIFIED', async () => {
    qrRow = makeQrRow({}, KYC_VERIFIED_ORG);

    expect((await getJson()).json().trust_state).toBe('VERIFIED');
  });

  it('the fraud-score floor alone does not block a verified issuer', async () => {
    qrRow = makeQrRow({}, DOMAIN_VERIFIED_ORG);
    state.trustScore = 30;

    expect((await getJson()).json().trust_state).toBe('VERIFIED');
  });
});

describe('UNTRUSTED', () => {
  it('verified org + lookalike destination: not green, phishing warning, no Continue', async () => {
    qrRow = makeQrRow({ destinationUrl: LOOKALIKE }, DOMAIN_VERIFIED_ORG);
    state.domainCheck = lookalikeCheck;

    const body = (await getJson()).json();
    const html = (await getHtml()).body;

    expect(body.trust_state).toBe('UNTRUSTED');
    expect(body.verified).toBe(false);
    expect(body.domain_warning).toBeDefined();
    expect(html).not.toContain(GREEN_CHECK_PATH);
    expect(html).toContain('Phishing Warning');
    expect(html).toContain('trust-reveal trust-failed');
    expect(html).not.toContain('Continue to');
  });

  it('after an edit to a lookalike destination, the same code is no longer green', async () => {
    qrRow = makeQrRow({}, DOMAIN_VERIFIED_ORG);
    state.domainCheck = lookalikeCheck;
    expect((await getJson()).json().trust_state).toBe('VERIFIED');

    // PATCH stores the new destination on the same token (see
    // qrcode-update-domain-check.test.ts); verify reads the current row.
    qrRow = makeQrRow({ destinationUrl: LOOKALIKE }, DOMAIN_VERIFIED_ORG);
    const html = (await getHtml()).body;

    expect((await getJson()).json().trust_state).toBe('UNTRUSTED');
    expect(html).not.toContain(GREEN_CHECK_PATH);
  });

  it('unverified org + lookalike: UNTRUSTED and still no org name', async () => {
    qrRow = makeQrRow({ destinationUrl: LOOKALIKE });
    state.domainCheck = lookalikeCheck;

    const html = (await getHtml()).body;

    expect((await getJson()).json().trust_state).toBe('UNTRUSTED');
    expect(html).not.toContain(ORG_NAME);
  });

  it('invalid signature', async () => {
    qrRow = makeQrRow({}, DOMAIN_VERIFIED_ORG);
    state.signatureValid = false;

    const body = (await getJson()).json();

    expect(body.trust_state).toBe('UNTRUSTED');
    expect(body.verified).toBe(false);
  });

  it('trust score at the threshold', async () => {
    qrRow = makeQrRow({}, DOMAIN_VERIFIED_ORG);
    state.trustScore = 20;

    expect((await getJson()).json().trust_state).toBe('UNTRUSTED');
  });

  it('revoked: UNTRUSTED, no destination', async () => {
    qrRow = makeQrRow({ status: 'REVOKED' }, DOMAIN_VERIFIED_ORG);

    const body = (await getJson()).json();

    expect(body.trust_state).toBe('UNTRUSTED');
    expect(body.verified).toBe(false);
    expect(body).not.toHaveProperty('destination_url');
  });

  it('revoked page names a verified issuer but not an unverified one', async () => {
    qrRow = makeQrRow({ status: 'REVOKED' }, DOMAIN_VERIFIED_ORG);
    expect((await getHtml()).body).toContain(`Issued by ${ORG_NAME}`);

    qrRow = makeQrRow({ status: 'REVOKED' });
    expect((await getHtml()).body).not.toContain(ORG_NAME);
  });

  it('geo interstitial does not name an unverified issuer', async () => {
    qrRow = makeQrRow({ latitude: 37.98, longitude: 23.72, requireProximity: true });

    const res = await getHtml();

    expect(res.statusCode).toBe(200);
    expect(res.body).not.toContain(ORG_NAME);
  });
});

describe('JSON: verified mirrors trust_state', () => {
  it.each<[string, () => void]>([
    ['unverified issuer', () => {}],
    ['verified issuer', () => { qrRow = makeQrRow({}, DOMAIN_VERIFIED_ORG); }],
    ['lookalike', () => { qrRow = makeQrRow({ destinationUrl: LOOKALIKE }, DOMAIN_VERIFIED_ORG); state.domainCheck = lookalikeCheck; }],
    ['bad signature', () => { state.signatureValid = false; }],
    ['expired', () => { qrRow = makeQrRow({ status: 'EXPIRED' }, DOMAIN_VERIFIED_ORG); }],
  ])('%s', async (_label, arrange) => {
    arrange();

    const body = (await getJson()).json();

    expect(['VERIFIED', 'SIGNED_UNVERIFIED_ISSUER', 'UNTRUSTED']).toContain(body.trust_state);
    expect(body.verified).toBe(body.trust_state === 'VERIFIED');
  });
});

// ---------------------------------------------------------------------------
// JSON: issuer identity
// ---------------------------------------------------------------------------

describe('JSON organization is named only when VERIFIED', () => {
  it.each<[string, () => void]>([
    ['SIGNED_UNVERIFIED_ISSUER', () => {}],
    ['SIGNED_UNVERIFIED_ISSUER (UNDER_REVIEW)', () => { qrRow = makeQrRow({}, UNDER_REVIEW_ORG); }],
    ['UNTRUSTED: verified org + lookalike', () => { qrRow = makeQrRow({ destinationUrl: LOOKALIKE }, DOMAIN_VERIFIED_ORG); state.domainCheck = lookalikeCheck; }],
    ['UNTRUSTED: bad signature, verified org', () => { qrRow = makeQrRow({}, DOMAIN_VERIFIED_ORG); state.signatureValid = false; }],
    ['UNTRUSTED: revoked, verified org', () => { qrRow = makeQrRow({ status: 'REVOKED' }, DOMAIN_VERIFIED_ORG); }],
    ['UNTRUSTED: expired, unverified org', () => { qrRow = makeQrRow({ status: 'EXPIRED' }); }],
    ['UNTRUSTED: geo-blocked, verified org', () => { qrRow = makeQrRow({ latitude: 37.98, longitude: 23.72, requireProximity: true }, DOMAIN_VERIFIED_ORG); }],
  ])('%s: { verified: false } and no org name anywhere in the body', async (_label, arrange) => {
    arrange();

    const res = await getJson();
    const body = res.json();

    expect(body.trust_state).not.toBe('VERIFIED');
    expect(body.organization).toEqual({ verified: false });
    expect(res.body).not.toContain(ORG_NAME);
    expect(res.body).not.toContain('org_1');
    expect(res.body).not.toContain('"slug"');
  });

  it('VERIFIED (domain): name and verified_domain', async () => {
    qrRow = makeQrRow({}, DOMAIN_VERIFIED_ORG);

    const res = await getJson();

    expect(res.json().organization).toEqual({ verified: true, name: ORG_NAME, verified_domain: 'acme.example' });
    expect(res.body).toContain(ORG_NAME);
  });

  it('VERIFIED (KYC only): name, no verified_domain', async () => {
    qrRow = makeQrRow({}, KYC_VERIFIED_ORG);

    expect((await getJson()).json().organization).toEqual({ verified: true, name: ORG_NAME });
  });
});

// ---------------------------------------------------------------------------
// Suspended organization
// ---------------------------------------------------------------------------

describe('suspended organization', () => {
  const SUSPENDED_VERIFIED_ORG: OrgFixture = { ...DOMAIN_VERIFIED_ORG, suspendedAt: new Date('2026-10-27T10:00:00Z') };
  const SUSPENDED_UNVERIFIED_ORG: OrgFixture = { ...UNVERIFIED_ORG, suspendedAt: new Date('2026-10-27T10:00:00Z') };

  it.each([
    ['verified issuer', SUSPENDED_VERIFIED_ORG],
    ['unverified issuer', SUSPENDED_UNVERIFIED_ORG],
  ])('JSON (%s): UNTRUSTED, "disabled", no destination, no org identity', async (_label, org) => {
    qrRow = makeQrRow({}, org);

    const res = await getJson();
    const body = res.json();

    expect(body.trust_state).toBe('UNTRUSTED');
    expect(body.verified).toBe(false);
    expect(body.reason).toBe('This code has been disabled.');
    expect(body.organization).toEqual({ verified: false });
    expect(body).not.toHaveProperty('destination_url');
    expect(res.body).not.toContain(ORG_NAME);
    expect(res.body).not.toContain('pay.example.com');
  });

  it('HTML: "QR Code Disabled", no destination, no org name, no Continue', async () => {
    qrRow = makeQrRow({}, SUSPENDED_VERIFIED_ORG);

    const html = (await getHtml()).body;

    expect(html).toContain('QR Code Disabled');
    expect(html).toContain('This code has been disabled.');
    expect(html).not.toContain(ORG_NAME);
    expect(html).not.toContain('pay.example.com');
    expect(html).not.toContain('Continue to');
    expect(html).not.toContain(GREEN_CHECK_PATH);
  });

  it('wins over every other state (a revoked code still says disabled)', async () => {
    qrRow = makeQrRow({ status: 'REVOKED' }, SUSPENDED_VERIFIED_ORG);

    expect((await getJson()).json().reason).toBe('This code has been disabled.');
  });

  it('unsuspending restores the prior behavior with the same row', async () => {
    qrRow = makeQrRow({}, SUSPENDED_VERIFIED_ORG);
    expect((await getJson()).json().trust_state).toBe('UNTRUSTED');

    qrRow = makeQrRow({}, { ...SUSPENDED_VERIFIED_ORG, suspendedAt: null });
    const body = (await getJson()).json();

    expect(body.trust_state).toBe('VERIFIED');
    expect(body.destination_url).toBe(DESTINATION);
  });
});

// ---------------------------------------------------------------------------
// Demo codes
// ---------------------------------------------------------------------------

describe('demo codes (QRCode.source = demo)', () => {
  it('a demo code of a verified org is never VERIFIED (JSON)', async () => {
    qrRow = makeQrRow({ source: 'demo' }, DOMAIN_VERIFIED_ORG);

    const res = await getJson();
    const body = res.json();

    expect(body.trust_state).toBe('SIGNED_UNVERIFIED_ISSUER');
    expect(body.verified).toBe(false);
    expect(body.organization).toEqual({ verified: false });
    expect(res.body).not.toContain(ORG_NAME);
  });

  it('a demo code of a verified org renders the neutral state without the org name (HTML)', async () => {
    qrRow = makeQrRow({ source: 'demo' }, DOMAIN_VERIFIED_ORG);

    const html = (await getHtml()).body;

    expect(html).toContain('trust-reveal trust-neutral');
    expect(html).not.toContain(GREEN_CHECK_PATH);
    expect(html).not.toMatch(/\bVerified\b/);
    expect(html).not.toContain(ORG_NAME);
    expect(html).not.toContain('acme.example');
  });

  it('the same org\'s non-demo code stays VERIFIED', async () => {
    qrRow = makeQrRow({ source: 'runtime' }, DOMAIN_VERIFIED_ORG);

    expect((await getJson()).json().trust_state).toBe('VERIFIED');
  });

  it('an expired demo code is UNTRUSTED with no org name', async () => {
    qrRow = makeQrRow({ source: 'demo', expiresAt: new Date('2020-01-01T00:00:00Z') }, DOMAIN_VERIFIED_ORG);

    const html = (await getHtml()).body;

    expect((await getJson()).json().trust_state).toBe('UNTRUSTED');
    expect(html).not.toContain(ORG_NAME);
  });
});

describe('"Report this code" link', () => {
  it.each<[string, () => void]>([
    ['VERIFIED', () => { qrRow = makeQrRow({}, DOMAIN_VERIFIED_ORG); }],
    ['SIGNED_UNVERIFIED_ISSUER', () => {}],
    ['UNTRUSTED (lookalike)', () => { qrRow = makeQrRow({ destinationUrl: LOOKALIKE }, DOMAIN_VERIFIED_ORG); state.domainCheck = lookalikeCheck; }],
    ['UNTRUSTED (revoked page)', () => { qrRow = makeQrRow({ status: 'REVOKED' }); }],
    ['UNTRUSTED (suspended page)', () => { qrRow = makeQrRow({}, { ...UNVERIFIED_ORG, suspendedAt: new Date() }); }],
  ])('%s page links to the report form', async (_label, arrange) => {
    arrange();

    const html = (await getHtml()).body;

    expect(html).toContain('href="/v/tok_1/report"');
    expect(html).toContain('Report this code');
  });
});

// ---------------------------------------------------------------------------
// Destination flagged by screening
// ---------------------------------------------------------------------------

describe('flagged destination', () => {
  const FLAGGED = { destinationFlaggedAt: new Date('2026-10-27T10:00:00Z'), destinationFlagReason: 'SOCIAL_ENGINEERING' };

  it('JSON: UNTRUSTED with the flag reason, no destination, no org identity (even a verified org)', async () => {
    qrRow = makeQrRow(FLAGGED, DOMAIN_VERIFIED_ORG);

    const res = await getJson();
    const body = res.json();

    expect(body.trust_state).toBe('UNTRUSTED');
    expect(body.verified).toBe(false);
    expect(body.reason).toBe('This code points to a site flagged as dangerous.');
    expect(body.organization).toEqual({ verified: false });
    expect(body).not.toHaveProperty('destination_url');
    expect(res.body).not.toContain('pay.example.com');
    expect(res.body).not.toContain(ORG_NAME);
  });

  it('HTML: "Dangerous Site Blocked", no destination, no Continue link', async () => {
    qrRow = makeQrRow(FLAGGED, DOMAIN_VERIFIED_ORG);

    const html = (await getHtml()).body;

    expect(html).toContain('Dangerous Site Blocked');
    expect(html).toContain('This code points to a site flagged as dangerous.');
    expect(html).not.toContain('pay.example.com');
    expect(html).not.toContain('Continue to');
    expect(html).not.toContain(GREEN_CHECK_PATH);
    expect(html).toContain('href="/v/tok_1/report"');
  });

  it('clearing the flag restores the prior state', async () => {
    qrRow = makeQrRow({ destinationFlaggedAt: null }, DOMAIN_VERIFIED_ORG);

    expect((await getJson()).json().trust_state).toBe('VERIFIED');
  });
});

// ---------------------------------------------------------------------------
// Scan mode (trust flash)
// ---------------------------------------------------------------------------

const FLASH_SCRIPT = /<script src="\/sdk\/verify-flash\.[0-9a-f]{16}\.js" defer><\/script>/;

describe('scan mode', () => {
  it('VERIFIED https URL code with FLASH: flash hooks on the full page', async () => {
    qrRow = makeQrRow({}, DOMAIN_VERIFIED_ORG);

    expect((await getJson()).json().scan_mode).toBe('FLASH');

    const res = await getHtml();
    expect(res.body).toMatch(FLASH_SCRIPT);
    expect(res.body).toContain(`data-flash-href="${DESTINATION}"`);
    expect(res.body).toContain('Continuing to pay.example.com');
    // The full page is still there for no-JS scanners.
    expect(res.body).toContain('Continue to pay.example.com');
    // The flash script is same-origin (script-src 'self'); every inline
    // script still carries the nonce.
    const inlineScripts = res.body.match(/<script(?![^>]*\bsrc=)[^>]*>/g) ?? [];
    expect(inlineScripts.length).toBeGreaterThan(0);
    for (const tag of inlineScripts) expect(tag).toMatch(/nonce="/);
  });

  it.each<[string, () => void]>([
    ['http destination', () => { qrRow = makeQrRow({ destinationUrl: 'http://pay.example.com/checkout' }, DOMAIN_VERIFIED_ORG); }],
    ['SIGNED_UNVERIFIED_ISSUER', () => { qrRow = makeQrRow(); }],
    ['UNTRUSTED (lookalike)', () => { qrRow = makeQrRow({ destinationUrl: LOOKALIKE }, DOMAIN_VERIFIED_ORG); state.domainCheck = lookalikeCheck; }],
    ['UNTRUSTED (low trust score)', () => { qrRow = makeQrRow({}, DOMAIN_VERIFIED_ORG); state.trustScore = 10; }],
    ['location-bound (advisory)', () => { qrRow = makeQrRow({ latitude: 37.98, longitude: 23.72, requireProximity: false }, DOMAIN_VERIFIED_ORG); }],
    ['scan mode PAGE', () => { qrRow = makeQrRow({ scanMode: 'PAGE' }, DOMAIN_VERIFIED_ORG); }],
    ['non-URL content type', () => { qrRow = makeQrRow({ contentType: 'coupon', content: { title: 'Ten off', code: 'TEN' } }, DOMAIN_VERIFIED_ORG); }],
  ])('%s: full page, no flash', async (_label, arrange) => {
    arrange();

    expect((await getJson()).json().scan_mode).toBe('PAGE');

    const html = (await getHtml()).body;
    expect(html).not.toContain('verify-flash.js');
    expect(html).not.toContain('data-flash-href');
  });

  it('failure responses report PAGE', async () => {
    qrRow = makeQrRow({ status: 'REVOKED' }, DOMAIN_VERIFIED_ORG);

    expect((await getJson()).json().scan_mode).toBe('PAGE');
    expect((await getHtml()).body).not.toContain('verify-flash.js');
  });

  it('scan recording is the same in both modes', async () => {
    const { scanQueue } = await import('../../lib/queue.js');
    const add = vi.mocked(scanQueue.add);

    add.mockClear();
    qrRow = makeQrRow({}, DOMAIN_VERIFIED_ORG);
    await getHtml();
    const flashJob = add.mock.calls[0];

    add.mockClear();
    qrRow = makeQrRow({ scanMode: 'PAGE' }, DOMAIN_VERIFIED_ORG);
    await getHtml();
    const pageJob = add.mock.calls[0];

    expect(flashJob).toEqual(pageJob);
  });
});
