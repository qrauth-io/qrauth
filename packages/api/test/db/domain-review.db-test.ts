/**
 * Lookalike review of organization domains (ADR-0007 D9) through the real
 * organization and admin routes against Postgres: a domain that resembles a
 * protected domain is held (PENDING_REVIEW, not verified) when it is set,
 * when DNS verification succeeds and on a superadmin override; a superadmin
 * approves or rejects it, audit-logged. The DNS lookup is stubbed.
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
process.env.ADMIN_EMAILS = 'admin@review.test';

vi.mock('../../src/lib/queue.js', () => ({ webRiskQueue: { add: vi.fn() }, scanQueue: { add: vi.fn() }, createQueueConnection: vi.fn() }));
vi.mock('../../src/lib/cache.js', () => ({ redis: {}, cacheGet: vi.fn(async () => null), cacheSet: vi.fn(), cacheDel: vi.fn(async () => undefined) }));
vi.mock('../../src/lib/email.js', async (importOriginal) => ({
  ...(await importOriginal<object>()),
  sendDomainVerifiedEmail: vi.fn(async () => undefined),
}));

const db = new PrismaClient({ datasources: { db: { url } } });
let app: FastifyInstance;
let admin: { id: string; email: string };
const owners: Record<string, { userId: string; orgId: string }> = {};

function as(user: { id: string; orgId: string; role: string; email: string }, method: 'PATCH' | 'POST', path: string, body?: unknown) {
  return app.inject({
    method,
    url: path,
    headers: { 'x-test-user': JSON.stringify(user), 'content-type': 'application/json' },
    payload: JSON.stringify(body ?? {}),
  });
}
const owner = (key: string) => ({ id: owners[key].userId, orgId: owners[key].orgId, role: 'OWNER', email: `${key}@review.test` });
const asAdmin = (method: 'PATCH' | 'POST', path: string, body?: unknown) =>
  as({ id: admin.id, orgId: owners.a.orgId, role: 'OWNER', email: admin.email }, method, path, body);

/** DNS-over-HTTPS answers with the org's current token. */
function dnsAnswers(token: string | null) {
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ Answer: token ? [{ type: 16, data: `"qrauth-verify=${token}"` }] : [] }))));
}

async function setDomain(key: string, domain: string) {
  return as(owner(key), 'PATCH', `/api/v1/organizations/${owners[key].orgId}`, { domain });
}
async function verifyByDns(key: string) {
  await db.organization.update({ where: { id: owners[key].orgId }, data: { domainVerifyToken: `tok-${key}` } });
  dnsAnswers(`tok-${key}`);
  return as(owner(key), 'POST', `/api/v1/organizations/${owners[key].orgId}/verify-domain`);
}
const org = (key: string) => db.organization.findUniqueOrThrow({ where: { id: owners[key].orgId } });

beforeAll(async () => {
  app = Fastify();
  app.decorate('prisma', db as never);
  app.decorate('signingService', {} as never);
  app.decorateRequest('user', null);
  app.decorate('authenticate', async (request: { headers: Record<string, string | undefined>; user: unknown }) => {
    request.user = JSON.parse(request.headers['x-test-user'] ?? '{}');
  });
  const { default: organizationRoutes } = await import('../../src/routes/organizations.js');
  const { default: adminRoutes } = await import('../../src/routes/admin.js');
  await app.register(organizationRoutes, { prefix: '/api/v1/organizations' });
  await app.register(adminRoutes, { prefix: '/api/v1/admin' });
  await app.ready();
});

afterAll(async () => {
  vi.unstubAllGlobals();
  await app.close();
  await db.$disconnect();
});

beforeEach(async () => {
  const { DomainService } = await import('../../src/services/domain.js');
  DomainService.clearCaches(db);
  await db.$executeRawUnsafe('TRUNCATE "organizations", "users" CASCADE');
  for (const key of ['a', 'b', 'c']) {
    const o = await db.organization.create({ data: { name: `Org ${key.toUpperCase()}`, slug: `org-${key}-review-test`, email: `${key}-org@review.test` } });
    const u = await db.user.create({ data: { name: `Owner ${key}`, email: `${key}@review.test`, passwordHash: 'x', emailVerified: true } });
    await db.membership.create({ data: { userId: u.id, organizationId: o.id, role: 'OWNER' } });
    owners[key] = { userId: u.id, orgId: o.id };
  }
  const a = await db.user.create({ data: { name: 'Admin', email: 'admin@review.test', passwordHash: 'x', emailVerified: true } });
  admin = { id: a.id, email: a.email };
});

describe('a lookalike domain is held, not verified', () => {
  it('on set, on DNS verification, and approval verifies it (audit-logged)', async () => {
    // раураl.com: Cyrillic letters, a lookalike of the protected paypal.com.
    expect((await setDomain('a', 'xn--l-7sba6dbr.com')).statusCode).toBe(200);
    let row = await org('a');
    expect(row).toMatchObject({ domainVerified: false, domainReviewStatus: 'PENDING_REVIEW' });
    expect(row.domainReview).toMatchObject({ domain: 'xn--l-7sba6dbr.com', source: 'domain_set', ownershipProven: false });
    expect(JSON.stringify(row.domainReview)).toContain('paypal.com');

    const verify = await verifyByDns('a');
    expect(verify.json()).toMatchObject({ verified: false, pendingReview: true });
    row = await org('a');
    expect(row).toMatchObject({ domainVerified: false, domainReviewStatus: 'PENDING_REVIEW' });
    expect(row.domainReview).toMatchObject({ source: 'dns', ownershipProven: true });

    const approve = await asAdmin('POST', `/api/v1/admin/organizations/${owners.a.orgId}/domain-review/approve`, { note: 'Checked with PayPal' });
    expect(approve.statusCode).toBe(200);
    row = await org('a');
    expect(row).toMatchObject({ domainVerified: true, domainReviewStatus: 'APPROVED' });
    expect(row.domainReview).toMatchObject({ decision: 'approved', decidedBy: 'admin@review.test', note: 'Checked with PayPal' });

    // The approval stands for this domain: a later DNS check verifies again.
    await db.organization.update({ where: { id: owners.a.orgId }, data: { domainVerified: false } });
    expect((await verifyByDns('a')).json()).toMatchObject({ verified: true });

    const actions = (await db.auditLog.findMany({ where: { organizationId: owners.a.orgId }, orderBy: { createdAt: 'asc' } })).map((l) => l.action);
    // Setting the domain is an organization update; the final DNS check is a verification (ADR-0008).
    expect(actions).toEqual([
      'organization.update',
      'organization.domain.heldForReview',
      'organization.domain.heldForReview',
      'admin.organization.domainReviewApproved',
      'organization.domain.verify',
    ]);
  });

  it('a superadmin override is held too; reject keeps it unverified and blocks DNS verification', async () => {
    await db.organization.update({ where: { id: owners.b.orgId }, data: { domain: 'g00gle.com' } });

    const override = await asAdmin('POST', `/api/v1/admin/organizations/${owners.b.orgId}/verify-domain`, { note: 'ticket 1' });
    expect(override.statusCode).toBe(409);
    expect(override.json()).toMatchObject({ code: 'domain-review-required' });
    expect(JSON.stringify(override.json().matches)).toContain('google.com');
    expect(await org('b')).toMatchObject({ domainVerified: false, domainReviewStatus: 'PENDING_REVIEW' });

    const reject = await asAdmin('POST', `/api/v1/admin/organizations/${owners.b.orgId}/domain-review/reject`, {});
    expect(reject.statusCode).toBe(200);
    expect(await org('b')).toMatchObject({ domainVerified: false, domainReviewStatus: 'REJECTED' });
    expect((await verifyByDns('b')).json()).toMatchObject({ verified: false, rejected: true });
    expect(await db.auditLog.count({ where: { action: 'admin.organization.domainReviewRejected' } })).toBe(1);
  });

  it("a lookalike of another organization's verified domain is held", async () => {
    await db.organization.update({ where: { id: owners.a.orgId }, data: { domain: 'bigcorp-shop.com', domainVerified: true } });
    await setDomain('b', 'bigcorp-sh0p.com');
    const row = await org('b');
    expect(row.domainReviewStatus).toBe('PENDING_REVIEW');
    expect(JSON.stringify(row.domainReview)).toContain('bigcorp-shop.com');
    // The verified organization's name is not part of what is shown about it.
    expect((row.domainReview as { matches: Array<{ source: string }> }).matches[0].source).toBe('verified');
  });

  it('a clean domain is verified directly; changing the domain clears a hold', async () => {
    await setDomain('c', 'xn--l-7sba6dbr.com');
    expect((await org('c')).domainReviewStatus).toBe('PENDING_REVIEW');
    await setDomain('c', 'my-cafe-athens.gr');
    expect(await org('c')).toMatchObject({ domainReviewStatus: null, domainReview: null });
    expect((await verifyByDns('c')).json()).toMatchObject({ verified: true });
    expect((await org('c')).domainVerified).toBe(true);
  });

  it('only a superadmin decides, and only a pending review', async () => {
    await setDomain('a', 'xn--l-7sba6dbr.com');
    const notAdmin = await as(owner('a'), 'POST', `/api/v1/admin/organizations/${owners.a.orgId}/domain-review/approve`, {});
    expect(notAdmin.statusCode).toBe(403);
    expect((await asAdmin('POST', `/api/v1/admin/organizations/${owners.c.orgId}/domain-review/approve`, {})).statusCode).toBe(409);
  });
});

describe('verified domains are not exempt from the check (review findings 1-3)', () => {
  it("verification alone grants no exemption: the issuer's own verified lookalike domain is flagged on its codes", async () => {
    await db.organization.update({ where: { id: owners.a.orgId }, data: { domain: 'xn--l-7sba6dbr.com', domainVerified: true } });
    const { DomainService } = await import('../../src/services/domain.js');
    const check = await new DomainService(db).checkUrlAgainstVerifiedDomains('https://xn--l-7sba6dbr.com/login', owners.a.orgId);
    expect(check.isSuspicious).toBe(true);
  });

  it("a verified lookalike of a brand never makes the real brand's domain a lookalike", async () => {
    await db.organization.update({ where: { id: owners.a.orgId }, data: { domain: 'g00gle.com', domainVerified: true } });
    const { DomainService } = await import('../../src/services/domain.js');
    const svc = new DomainService(db);
    expect((await svc.checkUrlAgainstVerifiedDomains('https://google.com/', owners.b.orgId)).isSuspicious).toBe(false);
    expect((await svc.checkUrlAgainstVerifiedDomains('https://www.paypal.com/', owners.b.orgId)).isSuspicious).toBe(false);
  });

  it("another organization's exact verified domain is never flagged; the lookalike cannot get verified, so its codes are flagged", async () => {
    await db.organization.update({ where: { id: owners.a.orgId }, data: { domain: 'bigcorp.com', domainVerified: true } });
    // The attacker sets a lookalike: held at set and at DNS verification.
    await setDomain('b', 'bigc0rp.com');
    expect((await verifyByDns('b')).json()).toMatchObject({ verified: false, pendingReview: true });

    const { DomainService } = await import('../../src/services/domain.js');
    DomainService.clearCaches(db);
    const svc = new DomainService(db);
    expect((await svc.checkUrlAgainstVerifiedDomains('https://bigcorp.com/', owners.c.orgId)).isSuspicious).toBe(false);
    expect((await svc.checkUrlAgainstVerifiedDomains('https://bigc0rp.com/', owners.b.orgId)).warnings[0]).toMatchObject({ domain: 'bigcorp.com', source: 'verified' });
    expect((await svc.checkUrlAgainstVerifiedDomains('https://bigc0rp.com/', owners.c.orgId)).isSuspicious).toBe(true);
  });
});

describe('an approved domain is exempt for its own organization only (D10)', () => {
  const check = async (code: string, orgKey: string) => {
    const { DomainService } = await import('../../src/services/domain.js');
    return new DomainService(db).checkUrlAgainstVerifiedDomains(code, owners[orgKey].orgId);
  };
  const reload = async () => (await import('../../src/services/domain.js')).DomainService.clearCaches(db);

  it('own codes pass after approval; other organizations\' codes stay flagged; revoking the approval flags them again', async () => {
    await setDomain('a', 'xn--l-7sba6dbr.com');
    await verifyByDns('a');
    const approve = await asAdmin('POST', `/api/v1/admin/organizations/${owners.a.orgId}/domain-review/approve`, {});
    expect(approve.statusCode).toBe(200);
    const row = await org('a');
    expect(row.domainReview).toMatchObject({ decision: 'approved', decidedBy: 'admin@review.test' });
    expect(JSON.stringify((row.domainReview as { matches: unknown[] }).matches)).toContain('paypal.com');

    await reload();
    expect((await check('https://xn--l-7sba6dbr.com/login', 'a')).isSuspicious).toBe(false);
    expect((await check('https://shop.xn--l-7sba6dbr.com/', 'a')).isSuspicious).toBe(false);
    expect((await check('https://xn--l-7sba6dbr.com/login', 'b')).isSuspicious).toBe(true);
    // Never a reference that flags the real brand or another verified domain.
    expect((await check('https://www.paypal.com/', 'b')).isSuspicious).toBe(false);

    const revoke = await asAdmin('POST', `/api/v1/admin/organizations/${owners.a.orgId}/domain-review/reject`, { note: 'revoked' });
    expect(revoke.statusCode).toBe(200);
    expect(await org('a')).toMatchObject({ domainReviewStatus: 'REJECTED', domainVerified: false });
    expect(await db.auditLog.count({ where: { action: 'admin.organization.domainApprovalRevoked' } })).toBe(1);
    await reload();
    expect((await check('https://xn--l-7sba6dbr.com/login', 'a')).isSuspicious).toBe(true);
  });

  it('an approval applies only to the domain it was given for: changing the domain removes it', async () => {
    await setDomain('a', 'xn--l-7sba6dbr.com');
    await verifyByDns('a');
    await asAdmin('POST', `/api/v1/admin/organizations/${owners.a.orgId}/domain-review/approve`, {});
    await setDomain('a', 'g00gle.com');
    // Even if the new domain ends up verified by other means, the old approval does not carry over.
    await db.organization.update({ where: { id: owners.a.orgId }, data: { domainVerified: true } });
    await reload();
    expect((await check('https://g00gle.com/', 'a')).isSuspicious).toBe(true);
    expect((await check('https://xn--l-7sba6dbr.com/', 'a')).isSuspicious).toBe(true);
  });
});

describe('verified references never flag another organization\'s verified domain or its subdomains (re-review 1)', () => {
  const check = async (code: string, orgKey: string) => {
    const { DomainService } = await import('../../src/services/domain.js');
    return new DomainService(db).checkUrlAgainstVerifiedDomains(code, owners[orgKey].orgId);
  };
  const reload = async () => (await import('../../src/services/domain.js')).DomainService.clearCaches(db);

  it('an approved lookalike (bigc0rp.com, org B) never flags bigcorp.com (org A) or its subdomains', async () => {
    await db.organization.update({ where: { id: owners.a.orgId }, data: { domain: 'bigcorp.com', domainVerified: true } });
    await setDomain('b', 'bigc0rp.com');
    await verifyByDns('b');
    expect((await asAdmin('POST', `/api/v1/admin/organizations/${owners.b.orgId}/domain-review/approve`, {})).statusCode).toBe(200);
    expect(await org('b')).toMatchObject({ domainVerified: true, domainReviewStatus: 'APPROVED' });

    await reload();
    expect((await check('https://bigcorp.com/', 'a')).isSuspicious).toBe(false);
    expect((await check('https://shop.bigcorp.com/', 'a')).isSuspicious).toBe(false);
    expect((await check('https://shop.bigcorp.com/', 'c')).isSuspicious).toBe(false);
    // bigc0rp.com stays a lookalike for everyone but its own organization (D10).
    expect((await check('https://bigc0rp.com/', 'c')).warnings[0]).toMatchObject({ domain: 'bigcorp.com', source: 'verified' });
    expect((await check('https://bigc0rp.com/', 'b')).isSuspicious).toBe(false);
  });

  it("a verified organization's active code to bigc0rp.com is not a reference; bigc0rp.com stays flagged", async () => {
    await db.organization.update({ where: { id: owners.a.orgId }, data: { domain: 'bigcorp.com', domainVerified: true } });
    await db.organization.update({ where: { id: owners.b.orgId }, data: { domain: 'mcorp-trading.com', domainVerified: true } });
    const key = await db.signingKey.create({ data: { organizationId: owners.b.orgId, publicKey: 'pk', keyId: `key-${owners.b.orgId}` } });
    await db.qRCode.create({
      data: { token: 'bigc0rp-code', organizationId: owners.b.orgId, signingKeyId: key.id, signature: 's', algVersion: 'test', destinationUrl: 'https://bigc0rp.com/login' },
    });

    await reload();
    expect((await check('https://bigcorp.com/', 'a')).isSuspicious).toBe(false);
    expect((await check('https://login.bigcorp.com/', 'c')).isSuspicious).toBe(false);
    expect((await check('https://bigc0rp.com/login', 'b')).warnings[0]).toMatchObject({ domain: 'bigcorp.com', source: 'verified' });
    expect((await check('https://bigc0rp.com/login', 'c')).isSuspicious).toBe(true);
  });
});

describe('unverifying a domain clears its review (re-review 4)', () => {
  it('removes the approval: own codes are flagged again and verifying again runs the review', async () => {
    await setDomain('a', 'xn--l-7sba6dbr.com');
    await verifyByDns('a');
    await asAdmin('POST', `/api/v1/admin/organizations/${owners.a.orgId}/domain-review/approve`, {});
    expect(await org('a')).toMatchObject({ domainVerified: true, domainReviewStatus: 'APPROVED' });

    expect((await asAdmin('POST', `/api/v1/admin/organizations/${owners.a.orgId}/unverify-domain`)).statusCode).toBe(200);
    expect(await org('a')).toMatchObject({ domainVerified: false, domainReviewStatus: null, domainReview: null });

    const { DomainService } = await import('../../src/services/domain.js');
    DomainService.clearCaches(db);
    expect((await new DomainService(db).checkUrlAgainstVerifiedDomains('https://xn--l-7sba6dbr.com/', owners.a.orgId)).isSuspicious).toBe(true);
    expect((await verifyByDns('a')).json()).toMatchObject({ verified: false, pendingReview: true });
  });

  it('keeps a rejection', async () => {
    await setDomain('b', 'g00gle.com');
    await asAdmin('POST', `/api/v1/admin/organizations/${owners.b.orgId}/domain-review/reject`, {});
    await asAdmin('POST', `/api/v1/admin/organizations/${owners.b.orgId}/unverify-domain`);
    expect(await org('b')).toMatchObject({ domainVerified: false, domainReviewStatus: 'REJECTED' });
  });
});

describe('the review records the normalised host (re-review 5)', () => {
  it('a domain set with www. is recorded without it, so the approval matches the domain DNS verification checks', async () => {
    await setDomain('a', 'www.xn--l-7sba6dbr.com');
    expect((await org('a')).domainReview).toMatchObject({ domain: 'xn--l-7sba6dbr.com', source: 'domain_set' });
    expect((await asAdmin('POST', `/api/v1/admin/organizations/${owners.a.orgId}/domain-review/approve`, {})).statusCode).toBe(200);
    expect((await verifyByDns('a')).json()).toMatchObject({ verified: true });
    expect(await org('a')).toMatchObject({ domainVerified: true, domainReviewStatus: 'APPROVED' });
  });
});

describe('hold audit entries name the domain (re-review 8)', () => {
  it('on set, on DNS verification and on a superadmin override', async () => {
    await setDomain('a', 'www.xn--l-7sba6dbr.com');
    await verifyByDns('a');
    await db.organization.update({ where: { id: owners.b.orgId }, data: { domain: 'g00gle.com' } });
    await asAdmin('POST', `/api/v1/admin/organizations/${owners.b.orgId}/verify-domain`, {});

    const holds = await db.auditLog.findMany({ where: { action: { in: ['organization.domain.heldForReview', 'admin.organization.domainHeldForReview'] } }, orderBy: { createdAt: 'asc' } });
    expect(holds.map((h) => h.metadata)).toEqual([
      expect.objectContaining({ domain: 'xn--l-7sba6dbr.com', source: 'domain_set' }),
      expect.objectContaining({ domain: 'xn--l-7sba6dbr.com', source: 'dns' }),
      expect.objectContaining({ domain: 'g00gle.com', source: 'admin_override' }),
    ]);
  });
});
