/**
 * Smart link (app-link) and link list content types against a real
 * Postgres, through the real create, update and bulk routes and the real
 * Web Risk worker: paid-plan gating on create and on a content change,
 * schema refusals (javascript:, data:, intent:, http:), Web Risk on every
 * link (refused, or queued for a re-check), the lookalike check on every
 * link, per-link flags from the daily scan, and flags dropped by an edit.
 * Signing, MAC, Redis, the queue, email and the Web Risk API are stubbed.
 * Run by scripts/ci-verify.sh `db`.
 */
import { PrismaClient } from '@prisma/client';
import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

const url = process.env.TEST_DATABASE_URL;
if (!url) throw new Error('TEST_DATABASE_URL is not set');
if (!/test/i.test(new URL(url).pathname)) throw new Error('TEST_DATABASE_URL must name a test database (the suite truncates tables)');

process.env.DATABASE_URL ??= url;
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'db-test-only-throwaway-secret-0000000000';
// The "unscreened" stub verdict stands for a server without Web Risk.
process.env.WEB_RISK_ALLOW_UNSCREENED_LINKS = 'true';

const stubs = vi.hoisted(() => ({
  noQueue: { add: async () => undefined },
  recheck: [] as string[],
  emails: [] as Array<{ to: string; url: string }>,
  // Web Risk: "malware" is listed, "down" cannot be screened, "unscreened"
  // gets no verdict (as without an API key), the rest are clean.
  screen(u: string) {
    if (u.includes('malware')) return { verdict: 'flagged' as const, threatTypes: ['MALWARE'] };
    if (u.includes('down')) return { verdict: 'unavailable' as const, detail: 'timeout' };
    if (u.includes('unscreened')) return { verdict: 'skipped' as const };
    return { verdict: 'clean' as const };
  },
}));

vi.mock('../../src/lib/queue.js', () => ({
  scanQueue: stubs.noQueue, fraudQueue: stubs.noQueue, alertQueue: stubs.noQueue, webhookQueue: stubs.noQueue,
  cleanupQueue: stubs.noQueue, analyticsQueue: stubs.noQueue, webRiskQueue: stubs.noQueue,
  createQueueConnection: vi.fn(), closeQueues: vi.fn(async () => undefined),
}));
vi.mock('../../src/lib/cache.js', () => ({
  redis: {},
  cacheGet: vi.fn(async () => null),
  cacheSet: vi.fn(async () => undefined),
  cacheDel: vi.fn(async () => undefined),
}));
vi.mock('../../src/lib/email.js', async (importOriginal) => ({
  ...(await importOriginal<object>()),
  sendLinkFlaggedEmail: vi.fn(async (to: string, flag: { url: string }) => {
    stubs.emails.push({ to, url: flag.url });
  }),
}));
vi.mock('../../src/services/hybrid-signing.js', () => ({
  HybridSigningService: class {
    async signSingleQR() {
      return { ecdsaSignature: `sig-${Math.random()}`, algVersion: 'test', batchId: null, leafIndex: null, leafHash: null, leafNonce: null, merklePath: null, merkleRoot: null };
    }
  },
}));
vi.mock('../../src/services/mac.js', () => ({
  MacService: class {
    async signCanonical() {
      return { mac: 'mac', keyVersion: 1 };
    }
  },
}));
vi.mock('../../src/services/transparency.js', () => ({
  TransparencyLogService: class {
    async appendEntry() {
      return { logIndex: 1 };
    }
    static computeBatchRootRef() {
      return 'ref';
    }
  },
}));
vi.mock('../../src/services/destination-screening.js', async (importOriginal) => ({
  ...(await importOriginal<object>()),
  screenDestination: async (u: string) => stubs.screen(u),
  enqueueDestinationRecheck: vi.fn(async (token: string) => {
    stubs.recheck.push(token);
  }),
}));

const db = new PrismaClient({ datasources: { db: { url } } });
let app: FastifyInstance;
const orgs: Record<'PRO' | 'FREE', { id: string; userId: string }> = {} as never;

const APP = {
  iosUrl: 'https://apps.apple.com/app/id123',
  androidUrl: 'https://play.google.com/store/apps/details?id=com.acme',
  fallbackUrl: 'https://acme.example/app',
};
const LIST = {
  title: 'Acme links',
  description: 'Menu and booking',
  links: [
    { label: 'Menu', url: 'https://acme.example/menu' },
    { label: 'Book', url: 'https://book.example/acme' },
  ],
};

function call(org: 'PRO' | 'FREE', method: 'POST' | 'PATCH' | 'GET', path: string, body?: unknown) {
  const user = { id: orgs[org].userId, orgId: orgs[org].id, role: 'OWNER', email: 'o@ct.test' };
  return app.inject({
    method,
    url: `/api/v1/qrcodes${path}`,
    headers: { 'x-test-user': JSON.stringify(user), ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
    ...(body === undefined ? {} : { payload: JSON.stringify(body) }),
  });
}

const create = (org: 'PRO' | 'FREE', contentType: string, content: unknown) =>
  call(org, 'POST', '', { contentType, content, label: 'Test' });

async function reset(): Promise<void> {
  await db.$executeRawUnsafe('TRUNCATE "organizations", "users" CASCADE');
  for (const plan of ['PRO', 'FREE'] as const) {
    const o = await db.organization.create({ data: { name: `Org ${plan}`, slug: `org-${plan.toLowerCase()}-ct-test`, email: `${plan}@ct.test`, plan } });
    await db.signingKey.create({ data: { organizationId: o.id, publicKey: 'pk', keyId: `key-${plan}-${o.id}` } });
    const user = await db.user.create({ data: { name: `Owner ${plan}`, email: `owner-${plan.toLowerCase()}@ct.test`, passwordHash: 'x', emailVerified: true } });
    await db.membership.create({ data: { userId: user.id, organizationId: o.id, role: 'OWNER' } });
    orgs[plan] = { id: o.id, userId: user.id };
  }
  // A verified organization whose domain the lookalike check compares with.
  await db.organization.create({ data: { name: 'PayPal', slug: 'paypal-ct-test', email: 'pp@ct.test', domain: 'paypal.com', domainVerified: true } });
}

beforeAll(async () => {
  app = Fastify();
  app.decorate('prisma', db as never);
  app.decorate('signingService', { getActiveKey: async (orgId: string) => {
    const k = await db.signingKey.findFirstOrThrow({ where: { organizationId: orgId } });
    return { id: k.id, keyId: k.keyId };
  } } as never);
  app.decorate('batchSigner', {} as never);
  app.decorateRequest('user', null);
  app.decorate('authenticate', async (request: { headers: Record<string, string | undefined>; user: unknown }) => {
    request.user = JSON.parse(request.headers['x-test-user'] ?? '{}');
  });
  const { default: qrcodeRoutes } = await import('../../src/routes/qrcodes.js');
  await app.register(qrcodeRoutes, { prefix: '/api/v1/qrcodes' });
  await app.ready();
});

afterAll(async () => {
  await app.close();
  await db.$disconnect();
});

beforeEach(async () => {
  // The lookalike check caches the protected set per Prisma client (ADR-0007).
  const { DomainService } = await import('../../src/services/domain.js');
  DomainService.clearCaches(db);
  stubs.recheck.length = 0;
  stubs.emails.length = 0;
  await reset();
});

describe('create', () => {
  it.each([['app-link', APP], ['link-list', LIST]])('a paid plan creates a %s code that points to its verify page', async (type, content) => {
    const res = await create('PRO', type, content);

    expect(res.statusCode).toBe(201);
    const row = await db.qRCode.findUniqueOrThrow({ where: { token: res.json().token } });
    expect(row.contentType).toBe(type);
    expect(row.content).toEqual(content);
    expect(row.destinationUrl).toMatch(new RegExp(`/v/${row.token}$`));
  });

  it.each([['app-link', APP], ['link-list', LIST]])('the Free plan cannot create a %s code (403)', async (type, content) => {
    const res = await create('FREE', type, content);

    expect(res.statusCode).toBe(403);
    expect(res.json().message).toMatch(/not included in the Free plan/);
    expect(await db.qRCode.count()).toBe(0);
  });

  it.each(['javascript:alert(1)', 'data:text/html,<script>alert(1)</script>', 'intent://x#Intent;scheme=https;end', 'http://acme.example/', 'https://a@evil.example/', 'https://10.0.0.1/', 'https://2130706433/', 'https://[::1]/', 'https://localhost/', 'https://nas.local/'])(
    'refuses %j in any link (400), storing nothing',
    async (bad) => {
      for (const content of [
        { ...APP, iosUrl: bad },
        { ...APP, androidUrl: bad },
        { ...APP, fallbackUrl: bad },
      ]) {
        expect((await create('PRO', 'app-link', content)).statusCode).toBe(400);
      }
      expect((await create('PRO', 'link-list', { ...LIST, links: [{ label: 'x', url: bad }] })).statusCode).toBe(400);
      expect(await db.qRCode.count()).toBe(0);
    },
  );

  it('refuses a link list over the limits (400)', async () => {
    const links = Array.from({ length: 21 }, (_, i) => ({ label: `L${i}`, url: `https://acme.example/${i}` }));
    expect((await create('PRO', 'link-list', { ...LIST, links })).statusCode).toBe(400);
    expect((await create('PRO', 'link-list', { ...LIST, title: 'x'.repeat(61) })).statusCode).toBe(400);
    expect((await create('PRO', 'link-list', { ...LIST, description: 'x'.repeat(201) })).statusCode).toBe(400);
    expect((await create('PRO', 'link-list', { ...LIST, links: [{ label: 'x'.repeat(41), url: 'https://a.example/' }] })).statusCode).toBe(400);
    expect((await create('PRO', 'app-link', undefined)).statusCode).toBe(400);
  });

  it('refuses a listed link (422 naming it), storing nothing', async () => {
    const res = await create('PRO', 'link-list', { ...LIST, links: [...LIST.links, { label: 'Bad', url: 'https://malware.example/x' }] });

    expect(res.statusCode).toBe(422);
    expect(res.json()).toMatchObject({ error: 'DestinationFlagged', url: 'https://malware.example/x', threatType: 'MALWARE' });
    expect((await create('PRO', 'app-link', { ...APP, androidUrl: 'https://malware.example/apk' })).statusCode).toBe(422);
    expect(await db.qRCode.count()).toBe(0);
  });

  it('refuses with 503 and Retry-After when a link cannot be screened, storing nothing', async () => {
    const res = await create('PRO', 'app-link', { ...APP, fallbackUrl: 'https://down.example/app' });

    expect(res.statusCode).toBe(503);
    expect(res.headers['retry-after']).toBe('30');
    expect(await db.qRCode.count()).toBe(0);
  });

  it('refuses an unknown content type (400)', async () => {
    expect((await create('PRO', 'hologram', { a: 1 })).statusCode).toBe(400);
  });

  it('runs the lookalike check on every link and records the incident', async () => {
    const res = await create('PRO', 'link-list', { ...LIST, links: [...LIST.links, { label: 'Pay', url: 'https://paypa1.com/login' }] });

    expect(res.statusCode).toBe(201);
    expect(res.json().domain_warnings[0]).toMatchObject({ url: 'https://paypa1.com/login', similar_to: 'paypal.com' });
    const incident = await db.fraudIncident.findFirstOrThrow();
    expect(incident.details).toMatchObject({ reason: 'suspicious_domain', url: 'https://paypa1.com/login', source: 'create' });
  });

  it('a create warning and the first daily re-scan record one incident (destinations and links)', async () => {
    const url = await call('PRO', 'POST', '', { destinationUrl: 'https://paypa1.com/pay' });
    const list = await create('PRO', 'link-list', { ...LIST, links: [...LIST.links, { label: 'Pay', url: 'https://paypa1.com/login' }] });
    expect(url.statusCode).toBe(201);
    expect(list.statusCode).toBe(201);
    expect(await db.fraudIncident.count()).toBe(2);

    const { runDailyScan } = await import('../../src/workers/web-risk.js');
    const { DomainService } = await import('../../src/services/domain.js');
    const domains = new DomainService(db);
    const summary = await runDailyScan(db, { info: vi.fn(), warn: vi.fn() } as never, {
      lookup: async () => ({ verdict: 'clean' as const }),
      sleep: async () => undefined,
      now: () => new Date(),
      lookalike: (u, org) => domains.checkUrlAgainstVerifiedDomains(u, org),
    });

    expect(summary.lookalikes).toBe(0);
    expect(await db.fraudIncident.count()).toBe(2);
  });

  it('incidents written before the shared path (no url in details) are not duplicated by the re-scan', async () => {
    const created = await call('PRO', 'POST', '', { destinationUrl: 'https://acme.example/menu' });
    const code = await db.qRCode.update({ where: { token: created.json().token }, data: { destinationUrl: 'https://paypa1.com/' } });
    await db.fraudIncident.create({
      data: { qrCodeId: code.id, type: 'MANUAL_REPORT', severity: 'HIGH', details: { reason: 'suspicious_domain', destinationDomain: 'paypa1.com', similarTo: 'paypal.com' } },
    });

    const { runDailyScan } = await import('../../src/workers/web-risk.js');
    const { DomainService } = await import('../../src/services/domain.js');
    const domains = new DomainService(db);
    await runDailyScan(db, { info: vi.fn(), warn: vi.fn() } as never, {
      lookup: async () => ({ verdict: 'clean' as const }),
      sleep: async () => undefined,
      now: () => new Date(),
      lookalike: (u, org) => domains.checkUrlAgainstVerifiedDomains(u, org),
    });

    expect(await db.fraudIncident.count({ where: { qrCodeId: code.id } })).toBe(1);
  });

  it('bulk stays URL-only: a smart link or link list item is refused (400)', async () => {
    for (const [contentType, content] of [['app-link', APP], ['link-list', LIST]] as const) {
      const res = await call('PRO', 'POST', '/bulk', { items: [{ destinationUrl: 'https://acme.example/', contentType, content }] });
      expect(res.statusCode).toBe(400);
      expect(res.body).toContain('bulk supports URL codes only');
    }
    expect(await db.qRCode.count()).toBe(0);
  });
});

describe('content edits', () => {
  async function made(type: 'app-link' | 'link-list', content: unknown) {
    const res = await create('PRO', type, content);
    expect(res.statusCode).toBe(201);
    return db.qRCode.findUniqueOrThrow({ where: { token: res.json().token } });
  }

  it('re-signs a clean edit', async () => {
    const before = await made('app-link', APP);
    const res = await call('PRO', 'PATCH', `/${before.token}`, { content: { ...APP, fallbackUrl: 'https://acme.example/new' } });

    expect(res.statusCode).toBe(200);
    const after = await db.qRCode.findUniqueOrThrow({ where: { token: before.token } });
    expect((after.content as typeof APP).fallbackUrl).toBe('https://acme.example/new');
    expect(after.signature).not.toBe(before.signature);
  });

  it('refuses a listed or unsafe link and leaves the content as it was', async () => {
    const before = await made('link-list', LIST);

    const flagged = await call('PRO', 'PATCH', `/${before.token}`, { content: { ...LIST, links: [{ label: 'x', url: 'https://malware.example/' }] } });
    const unsafe = await call('PRO', 'PATCH', `/${before.token}`, { content: { ...LIST, links: [{ label: 'x', url: 'javascript:alert(1)' }] } });

    expect(flagged.statusCode).toBe(422);
    expect(unsafe.statusCode).toBe(400);
    expect((await db.qRCode.findUniqueOrThrow({ where: { token: before.token } })).content).toEqual(LIST);
  });

  it('a plan without the type (after a downgrade) cannot change the content; unchanged content and the label still save', async () => {
    const code = await made('link-list', LIST);
    await db.organization.update({ where: { id: orgs.PRO.id }, data: { plan: 'FREE' } });

    const changed = await call('PRO', 'PATCH', `/${code.token}`, { content: { ...LIST, title: 'New' } });
    // Same content, keys in another order.
    const resent = await call('PRO', 'PATCH', `/${code.token}`, { content: { links: LIST.links, description: LIST.description, title: LIST.title } });
    const label = await call('PRO', 'PATCH', `/${code.token}`, { label: 'Renamed' });

    expect(changed.statusCode).toBe(403);
    expect(resent.statusCode).toBe(200);
    expect(label.statusCode).toBe(200);
    expect((await db.qRCode.findUniqueOrThrow({ where: { token: code.token } })).content).toEqual(LIST);
  });

  it('drops the flags of removed links and of links screened clean; keeps a kept link that was not screened', async () => {
    const code = await made('link-list', {
      ...LIST,
      links: [
        { label: 'a', url: 'https://acme.example/a' },
        { label: 'b', url: 'https://unscreened.example/b' },
        { label: 'c', url: 'https://gone.example/c' },
      ],
    });
    const { linkUrlHash } = await import('../../src/services/link-screening.js');
    for (const u of ['https://acme.example/a', 'https://unscreened.example/b', 'https://gone.example/c']) {
      await db.qRCodeLinkFlag.create({ data: { qrCodeId: code.id, url: u, urlHash: linkUrlHash(u), threatTypes: 'MALWARE' } });
    }

    const res = await call('PRO', 'PATCH', `/${code.token}`, {
      content: { ...LIST, links: [{ label: 'a', url: 'https://acme.example/a' }, { label: 'b', url: 'https://unscreened.example/b' }] },
    });

    expect(res.statusCode).toBe(200);
    expect((await db.qRCodeLinkFlag.findMany()).map((f) => f.url)).toEqual(['https://unscreened.example/b']);
  });

  it('an edit is refused with 503 when a link cannot be screened', async () => {
    const code = await made('app-link', APP);
    const res = await call('PRO', 'PATCH', `/${code.token}`, { content: { ...APP, iosUrl: 'https://down.example/ios' } });

    expect(res.statusCode).toBe(503);
    expect((await db.qRCode.findUniqueOrThrow({ where: { id: code.id } })).content).toEqual(APP);
  });

  it('an unchanged resend (the dashboard sends content on every save) is not screened again and records no new incident', async () => {
    const content = { ...LIST, links: [...LIST.links, { label: 'Pay', url: 'https://paypa1.com/login' }] };
    const code = await made('link-list', content);
    expect(await db.fraudIncident.count()).toBe(1);
    // A link becomes listed after creation: saving the label must still work.
    const original = stubs.screen;
    stubs.screen = (u: string) => (u.includes('book.example') ? { verdict: 'flagged' as const, threatTypes: ['MALWARE'] } : original(u)) as never;
    try {
      const res = await call('PRO', 'PATCH', `/${code.token}`, { label: 'Renamed', content });
      expect(res.statusCode).toBe(200);
      expect(res.json().domain_warnings).toBeUndefined();
      expect(await db.fraudIncident.count()).toBe(1);
      expect((await db.qRCode.findUniqueOrThrow({ where: { id: code.id } })).label).toBe('Renamed');
    } finally {
      stubs.screen = original;
    }
  });

  it('refuses destinationUrl on a smart link or link list code (400)', async () => {
    const code = await made('app-link', APP);
    const res = await call('PRO', 'PATCH', `/${code.token}`, { destinationUrl: 'https://elsewhere.example/' });

    expect(res.statusCode).toBe(400);
    expect((await db.qRCode.findUniqueOrThrow({ where: { id: code.id } })).destinationUrl).toBe(code.destinationUrl);
  });
});

describe('destination host rules (URL codes)', () => {
  it('create refuses a private destination (400)', async () => {
    for (const destinationUrl of ['https://192.168.1.10/', 'https://0x7f000001/', 'https://[::ffff:127.0.0.1]/', 'https://intranet/', 'https://svc.internal/']) {
      expect((await call('PRO', 'POST', '', { destinationUrl })).statusCode).toBe(400);
    }
    expect((await call('PRO', 'POST', '/bulk', { items: [{ destinationUrl: 'https://localhost/' }] })).statusCode).toBe(400);
    expect(await db.qRCode.count()).toBe(0);
  });

  it('PATCH refuses a new private destination but still edits a code that already has one', async () => {
    const res = await call('PRO', 'POST', '', { destinationUrl: 'https://acme.example/menu' });
    expect(res.statusCode).toBe(201);
    const token = res.json().token as string;
    expect((await call('PRO', 'PATCH', `/${token}`, { destinationUrl: 'https://10.1.2.3/' })).statusCode).toBe(400);

    // An existing code whose destination predates the rule.
    await db.qRCode.update({ where: { token }, data: { destinationUrl: 'https://192.168.1.10/' } });
    const edit = await call('PRO', 'PATCH', `/${token}`, { destinationUrl: 'https://192.168.1.10/', label: 'Renamed' });
    expect(edit.statusCode).toBe(200);
    expect((await db.qRCode.findUniqueOrThrow({ where: { token } })).label).toBe('Renamed');
  });
});

describe('normalized URLs', () => {
  it('stores destinations and links in normalized form', async () => {
    const url = await call('PRO', 'POST', '', { destinationUrl: 'HTTPS://Acme.EXAMPLE:443/Menu' });
    expect(url.statusCode).toBe(201);
    expect((await db.qRCode.findUniqueOrThrow({ where: { token: url.json().token } })).destinationUrl).toBe('https://acme.example/Menu');

    const list = await create('PRO', 'link-list', { title: 'T', links: [{ label: 'a', url: 'HTTPS://Book.Example/x?q="y"' }] });
    expect(list.statusCode).toBe(201);
    const stored = await db.qRCode.findUniqueOrThrow({ where: { token: list.json().token } });
    expect(stored.content).toEqual({ title: 'T', links: [{ label: 'a', url: 'https://book.example/x?q=%22y%22' }] });
  });

  it('refuses spaces and control characters in any URL (400)', async () => {
    expect((await call('PRO', 'POST', '', { destinationUrl: ' https://acme.example/' })).statusCode).toBe(400);
    expect((await create('PRO', 'app-link', { ...APP, iosUrl: 'ht\ttps://apps.apple.com/x' })).statusCode).toBe(400);
    expect((await create('PRO', 'link-list', { ...LIST, links: [{ label: 'a', url: 'https://acme.example/a\nb' }] })).statusCode).toBe(400);
    expect(await db.qRCode.count()).toBe(0);
  });

  it('PATCH: the current destination in another spelling is not a change; a new one is stored normalized', async () => {
    const res = await call('PRO', 'POST', '', { destinationUrl: 'https://acme.example/menu' });
    const token = res.json().token as string;
    const before = await db.qRCode.findUniqueOrThrow({ where: { token } });

    await call('PRO', 'PATCH', `/${token}`, { destinationUrl: 'HTTPS://ACME.example:443/menu' });
    const same = await db.qRCode.findUniqueOrThrow({ where: { token } });
    expect(same.destinationUrl).toBe('https://acme.example/menu');
    expect(same.signature).toBe(before.signature);

    expect((await call('PRO', 'PATCH', `/${token}`, { destinationUrl: 'HTTPS://Acme.example/New' })).statusCode).toBe(200);
    expect((await db.qRCode.findUniqueOrThrow({ where: { token } })).destinationUrl).toBe('https://acme.example/New');
  });
});

describe('daily scan and flags', () => {
  it('flags a listed link once, emails the owner once, and never flags the code', async () => {
    const created = await create('PRO', 'link-list', LIST);
    const code = await db.qRCode.findUniqueOrThrow({ where: { token: created.json().token } });
    const { runDailyScan } = await import('../../src/workers/web-risk.js');
    const log = { info: vi.fn(), warn: vi.fn() } as never;
    const lookup = async (u: string) => (u.includes('book.example') ? { verdict: 'flagged' as const, threatTypes: ['SOCIAL_ENGINEERING'] } : { verdict: 'clean' as const });

    const first = await runDailyScan(db, log, { lookup, sleep: async () => undefined, now: () => new Date() });
    const second = await runDailyScan(db, log, { lookup, sleep: async () => undefined, now: () => new Date() });

    expect(first.flagged).toBe(1);
    expect(second.flagged).toBe(0);
    const flags = await db.qRCodeLinkFlag.findMany();
    expect(flags).toHaveLength(1);
    expect(flags[0]).toMatchObject({ qrCodeId: code.id, url: 'https://book.example/acme', threatTypes: 'SOCIAL_ENGINEERING' });
    expect(stubs.emails).toEqual([{ to: 'owner-pro@ct.test', url: 'https://book.example/acme' }]);
    expect((await db.qRCode.findUniqueOrThrow({ where: { id: code.id } })).destinationFlaggedAt).toBeNull();
  });

  it('flags go with the code (cascade)', async () => {
    const created = await create('PRO', 'app-link', APP);
    const code = await db.qRCode.findUniqueOrThrow({ where: { token: created.json().token } });
    await db.qRCodeLinkFlag.create({ data: { qrCodeId: code.id, url: APP.iosUrl, urlHash: 'x'.repeat(64), threatTypes: 'MALWARE' } });

    await db.qRCode.delete({ where: { id: code.id } });

    expect(await db.qRCodeLinkFlag.count()).toBe(0);
  });
});
