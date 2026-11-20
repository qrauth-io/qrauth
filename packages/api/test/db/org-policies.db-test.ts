/**
 * Organization policies (ADR-0008 D8) against a real Postgres, through the
 * real QR code and policy routes: the allowlist on every destination write
 * (create, PATCH, restore, bulk, smart link and link list links), codes
 * marked outside the policy, the preview, the destination-edit role for
 * users and API keys, the plan gate and downgrade, tenant isolation and the
 * audit entries. Signing, MAC and transparency are stubbed; Web Risk is a
 * stub ("malware" is listed, "slow" waits on a gate); the lookalike check
 * is real. Run by scripts/ci-verify.sh `db`.
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

const stubs = vi.hoisted(() => ({
  noQueue: { add: async () => undefined },
  gate: { wait: Promise.resolve() as Promise<void>, entered: () => {} },
  async screen(u: string) {
    if (u.includes('slow')) {
      this.gate.entered();
      await this.gate.wait;
    }
    return u.includes('malware') ? { verdict: 'flagged' as const, threatTypes: ['MALWARE'] } : { verdict: 'clean' as const, threatTypes: [] };
  },
}));

vi.mock('../../src/lib/queue.js', () => ({
  scanQueue: stubs.noQueue, fraudQueue: stubs.noQueue, alertQueue: stubs.noQueue, webhookQueue: stubs.noQueue,
  cleanupQueue: stubs.noQueue, analyticsQueue: stubs.noQueue, webRiskQueue: stubs.noQueue,
  createQueueConnection: vi.fn(), closeQueues: vi.fn(async () => undefined),
}));
vi.mock('../../src/lib/cache.js', () => ({
  cacheGet: vi.fn(async () => null),
  cacheSet: vi.fn(async () => undefined),
  cacheDel: vi.fn(async () => undefined),
}));
vi.mock('../../src/lib/email.js', async (importOriginal) => ({
  ...(await importOriginal<object>()),
  sendLinkFlaggedEmail: vi.fn(async () => undefined),
}));
vi.mock('../../src/services/hybrid-signing.js', () => ({
  HybridSigningService: class {
    async signSingleQR() {
      return { ecdsaSignature: `sig-${Date.now()}`, algVersion: 'test', batchId: null, leafIndex: null, leafHash: null, leafNonce: null, merklePath: null, merkleRoot: null };
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
  screenDestination: (u: string) => stubs.screen(u),
  enqueueDestinationRecheck: vi.fn(async () => undefined),
}));

const db = new PrismaClient({ datasources: { db: { url } } });
let app: FastifyInstance;

const ROLES = ['OWNER', 'ADMIN', 'MANAGER', 'MEMBER', 'VIEWER'] as const;
type Role = (typeof ROLES)[number];
type OrgName = 'A' | 'B';
type Org = { id: string; keyId: string; users: Record<Role, string>; dashboardKeyId: string; cliKeyId: string };
const orgs: Record<OrgName, Org> = {} as never;

type CallOpts = { as?: Role; jwtRole?: Role; key?: 'dashboard' | 'cli' };

function call(org: OrgName, method: 'GET' | 'POST' | 'PATCH' | 'PUT', path: string, body?: unknown, opts: CallOpts = {}) {
  const o = orgs[org];
  const user = opts.key
    ? { id: 'api-key', orgId: o.id, role: opts.jwtRole ?? (opts.key === 'cli' ? 'MANAGER' : 'MEMBER'), email: '', apiKeyId: opts.key === 'cli' ? o.cliKeyId : o.dashboardKeyId }
    : { id: o.users[opts.as ?? 'OWNER'], orgId: o.id, role: opts.jwtRole ?? opts.as ?? 'OWNER', email: 'u@policy.test' };
  return app.inject({
    method,
    url: path,
    headers: { 'x-test-user': JSON.stringify(user), ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
    ...(body === undefined ? {} : { payload: JSON.stringify(body) }),
  });
}

const domain = (d: string, includeSubdomains = true) => ({ domain: d, includeSubdomains });
type PolicyBody = { allowlistMode?: 'OFF' | 'ENFORCE'; allowlist?: Array<{ domain: string; includeSubdomains: boolean }>; destinationEditMinRole?: 'MEMBER' | 'MANAGER' | 'ADMIN' };
const putPolicy = (org: OrgName, body: PolicyBody, opts: CallOpts = {}) =>
  call(org, 'PUT', '/api/v1/policies', { allowlistMode: 'OFF', allowlist: [], destinationEditMinRole: 'MEMBER', ...body }, opts);
const enforce = async (org: OrgName, allowlist: Array<{ domain: string; includeSubdomains: boolean }>, extra: PolicyBody = {}) => {
  const res = await putPolicy(org, { allowlistMode: 'ENFORCE', allowlist, ...extra });
  expect(res.statusCode, res.body).toBe(200);
  return res.json();
};
const createUrl = (org: OrgName, destinationUrl: string, opts: CallOpts = {}) => call(org, 'POST', '/api/v1/qrcodes', { destinationUrl, label: 'c' }, opts);
const patch = (org: OrgName, token: string, body: unknown, opts: CallOpts = {}) => call(org, 'PATCH', `/api/v1/qrcodes/${token}`, body, opts);
const code = (token: string) => db.qRCode.findUniqueOrThrow({ where: { token } });
const policyAudits = (org: OrgName) => db.auditLog.findMany({ where: { organizationId: orgs[org].id, action: 'policy.update' }, orderBy: { createdAt: 'asc' } });

const APP = { iosUrl: 'https://apps.apple.com/app/id1', androidUrl: 'https://play.google.com/store/apps/details?id=x', fallbackUrl: 'https://shop.allowed.test/app' };
const LIST = { title: 'Links', links: [{ label: 'Menu', url: 'https://allowed.test/menu' }] };

/** A code with its revision 1, as the create route writes it, created before any policy. */
async function makeCode(org: OrgName, token: string, extra: Record<string, unknown> = {}) {
  const { recordCreated, systemContext } = await import('../../src/services/qr-revisions.js');
  return db.$transaction(async (tx) => {
    const row = await tx.qRCode.create({
      data: { token, organizationId: orgs[org].id, signingKeyId: orgs[org].keyId, destinationUrl: 'https://allowed.test/', signature: 'sig', algVersion: 'test', ...extra },
    });
    await recordCreated(tx, row, systemContext('test'));
    return row;
  });
}

async function reset(): Promise<void> {
  await db.$executeRawUnsafe('TRUNCATE "organizations", "users" CASCADE');
  for (const name of ['A', 'B'] as const) {
    const o = await db.organization.create({ data: { name: `Org ${name}`, slug: `org-${name.toLowerCase()}-policy-test`, email: `${name}@policy.test`, plan: 'BUSINESS' } });
    const key = await db.signingKey.create({ data: { organizationId: o.id, publicKey: 'pk', keyId: `key-${name}-${o.id}` } });
    const users = {} as Record<Role, string>;
    for (const role of ROLES) {
      const u = await db.user.create({ data: { name: `${role} ${name}`, email: `${role.toLowerCase()}-${name.toLowerCase()}@policy.test`, passwordHash: 'x', emailVerified: true } });
      await db.membership.create({ data: { userId: u.id, organizationId: o.id, role } });
      users[role] = u.id;
    }
    const dashboardKey = await db.apiKey.create({ data: { organizationId: o.id, keyHash: `dash-${o.id}`, prefix: 'qrauth_da', label: 'Dashboard key' } });
    const cliKey = await db.apiKey.create({
      data: { organizationId: o.id, keyHash: `cli-${o.id}`, prefix: 'qrauth_cl', label: 'CLI key', role: 'MANAGER', source: 'cli', createdByUserId: users.MANAGER },
    });
    orgs[name] = { id: o.id, keyId: key.id, users, dashboardKeyId: dashboardKey.id, cliKeyId: cliKey.id };
  }
  // A verified organization the real lookalike check compares destinations with.
  await db.organization.create({ data: { name: 'PayPal', slug: 'paypal-policy-test', email: 'pp@policy.test', domain: 'paypal.com', domainVerified: true } });
}

beforeAll(async () => {
  app = Fastify({ genReqId: () => `req-${Math.random().toString(36).slice(2, 10)}` });
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
  const { default: policyRoutes } = await import('../../src/routes/org-policies.js');
  await app.register(qrcodeRoutes, { prefix: '/api/v1/qrcodes' });
  await app.register(policyRoutes, { prefix: '/api/v1/policies' });
  await app.ready();
});

afterAll(async () => {
  await app.close();
  await db.$disconnect();
});

beforeEach(async () => {
  const { DomainService } = await import('../../src/services/domain.js');
  DomainService.clearCaches(db);
  await reset();
});

// ---------------------------------------------------------------------------

describe('managing the policy', () => {
  it('reads the defaults when the organization has no policy', async () => {
    const res = await call('A', 'GET', '/api/v1/policies');
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({
      allowlistMode: 'OFF', allowlist: [], destinationEditMinRole: 'MEMBER', updatedAt: null,
      editable: true, outsidePolicyCount: 0, apiKeysWithoutCreator: 1,
    });
  });

  it('stores entries normalised (PSL, punycode, merged, sorted) and records policy.update with before and after', async () => {
    const res = await putPolicy('A', { allowlistMode: 'ENFORCE', allowlist: [domain('www.Allowed.test'), domain('münchen.de', false), domain('allowed.test', false)], destinationEditMinRole: 'MANAGER' });
    expect(res.statusCode, res.body).toBe(200);
    expect(res.json()).toMatchObject({
      allowlistMode: 'ENFORCE',
      destinationEditMinRole: 'MANAGER',
      allowlist: [
        { domain: 'allowed.test', includeSubdomains: true, unicode: 'allowed.test' },
        { domain: 'xn--mnchen-3ya.de', includeSubdomains: false, unicode: 'münchen.de' },
      ],
    });
    const [entry] = await policyAudits('A');
    expect(entry).toMatchObject({ actorType: 'USER', actorId: orgs.A.users.OWNER, resource: 'OrgPolicy', requestId: expect.stringMatching(/^req-/) });
    expect(entry.metadata).toEqual({
      before: null,
      after: {
        allowlistMode: 'ENFORCE',
        destinationEditMinRole: 'MANAGER',
        allowlist: [{ domain: 'allowed.test', includeSubdomains: true }, { domain: 'xn--mnchen-3ya.de', includeSubdomains: false }],
      },
      codesOutsidePolicy: 0,
    });
  });

  it('a request that changes nothing writes no audit entry; a change records the previous policy as before', async () => {
    await enforce('A', [domain('allowed.test')]);
    expect((await putPolicy('A', { allowlistMode: 'ENFORCE', allowlist: [domain('ALLOWED.test')] })).statusCode).toBe(200);
    expect(await policyAudits('A')).toHaveLength(1);
    await putPolicy('A', { allowlistMode: 'OFF', allowlist: [domain('allowed.test')] });
    const entries = await policyAudits('A');
    expect(entries).toHaveLength(2);
    expect(entries[1].metadata).toMatchObject({ before: { allowlistMode: 'ENFORCE' }, after: { allowlistMode: 'OFF' } });
  });

  it('an API key change is recorded with the key as actor', async () => {
    // An ADMIN-level key: ADMIN role, owned by an ADMIN.
    await db.apiKey.update({ where: { id: orgs.A.cliKeyId }, data: { role: 'ADMIN', createdByUserId: orgs.A.users.ADMIN } });
    const res = await putPolicy('A', { destinationEditMinRole: 'ADMIN' }, { key: 'cli', jwtRole: 'ADMIN' });
    expect(res.statusCode).toBe(200);
    expect((await policyAudits('A'))[0]).toMatchObject({ actorType: 'API_KEY', actorId: orgs.A.cliKeyId, userId: null });
  });

  it('re-reads the caller’s role: a demoted admin with a valid token cannot change or preview, and nothing is stored', async () => {
    await db.membership.update({
      where: { userId_organizationId: { userId: orgs.A.users.ADMIN, organizationId: orgs.A.id } },
      data: { role: 'MANAGER' },
    });
    const put = await putPolicy('A', { allowlistMode: 'ENFORCE', allowlist: [domain('allowed.test')] }, { as: 'ADMIN' });
    expect(put.statusCode).toBe(403);
    expect(put.json()).toMatchObject({ code: 'policy-role-required' });
    const preview = await call('A', 'POST', '/api/v1/policies/preview', { allowlist: [domain('allowed.test')] }, { as: 'ADMIN' });
    expect(preview.statusCode).toBe(403);
    expect(preview.json().code).toBe('policy-role-required');
    expect(await db.orgPolicy.count()).toBe(0);
    expect(await policyAudits('A')).toHaveLength(0);
    // A key whose owner was demoted is refused the same way.
    await db.apiKey.update({ where: { id: orgs.A.cliKeyId }, data: { role: 'ADMIN', createdByUserId: orgs.A.users.ADMIN } });
    expect((await putPolicy('A', { destinationEditMinRole: 'ADMIN' }, { key: 'cli', jwtRole: 'ADMIN' })).statusCode).toBe(403);
  });

  it('refuses invalid entries, an enforced empty list and more than 200 entries; nothing is stored or audited', async () => {
    const invalid = await putPolicy('A', { allowlistMode: 'ENFORCE', allowlist: [domain('allowed.test'), domain('co.uk'), domain('10.0.0.1')] });
    expect(invalid.statusCode).toBe(422);
    expect(invalid.json()).toMatchObject({ code: 'policy-invalid', entries: [{ ok: true }, { ok: false, input: 'co.uk' }, { ok: false, input: '10.0.0.1' }] });
    expect((await putPolicy('A', { allowlistMode: 'ENFORCE', allowlist: [] })).json()).toMatchObject({ code: 'policy-invalid', message: expect.stringContaining('at least one domain') });
    const many = Array.from({ length: 201 }, (_, i) => domain(`d${i}.example`));
    expect((await putPolicy('A', { allowlist: many })).statusCode).toBe(400);
    expect(await db.orgPolicy.count()).toBe(0);
    expect(await policyAudits('A')).toHaveLength(0);
  });

  it('is for OWNER and ADMIN only (read, change and preview)', async () => {
    for (const as of ['MANAGER', 'MEMBER', 'VIEWER'] as const) {
      expect((await call('A', 'GET', '/api/v1/policies', undefined, { as })).statusCode).toBe(403);
      expect((await putPolicy('A', { destinationEditMinRole: 'ADMIN' }, { as })).statusCode).toBe(403);
      expect((await call('A', 'POST', '/api/v1/policies/preview', { allowlist: [] }, { as })).statusCode).toBe(403);
    }
    expect((await putPolicy('A', { destinationEditMinRole: 'ADMIN' }, { as: 'ADMIN' })).statusCode).toBe(200);
    expect((await putPolicy('A', { destinationEditMinRole: 'MANAGER' }, { key: 'dashboard' })).statusCode).toBe(403);
  });
});

describe('plan gate and downgrade', () => {
  it('below Business a policy cannot be enabled or previewed', async () => {
    await db.organization.update({ where: { id: orgs.A.id }, data: { plan: 'PRO' } });
    const res = await putPolicy('A', { allowlistMode: 'ENFORCE', allowlist: [domain('allowed.test')] });
    expect(res.statusCode).toBe(403);
    expect(res.json()).toMatchObject({ code: 'governance-plan-required', message: expect.stringContaining('Business plan') });
    expect((await call('A', 'POST', '/api/v1/policies/preview', { allowlist: [domain('allowed.test')] })).json()).toMatchObject({ code: 'governance-plan-required' });
    expect((await call('A', 'GET', '/api/v1/policies')).json()).toMatchObject({ editable: false, allowlistMode: 'OFF' });
  });

  it('switch-off without the allowlist keeps a stored entry that would fail today’s normalisation', async () => {
    // Stored before a rule change: co.uk is a public suffix and is refused on input now.
    await db.orgPolicy.create({
      data: { organizationId: orgs.A.id, allowlistMode: 'ENFORCE', allowlist: [{ domain: 'co.uk', includeSubdomains: true }], destinationEditMinRole: 'MANAGER' },
    });
    await db.organization.update({ where: { id: orgs.A.id }, data: { plan: 'PRO' } });
    const put = (body: unknown) => call('A', 'PUT', '/api/v1/policies', body);

    // Resending the stored list re-normalises it and is refused, so switch-off must not depend on it.
    expect((await put({ allowlistMode: 'OFF', allowlist: [domain('co.uk')], destinationEditMinRole: 'MANAGER' })).json().code).toBe('policy-invalid');
    // Anything other than switching off is still refused below Business.
    expect((await put({ allowlistMode: 'ENFORCE', destinationEditMinRole: 'ADMIN' })).json().code).toBe('governance-plan-required');

    const off = await put({ allowlistMode: 'OFF', destinationEditMinRole: 'MANAGER' });
    expect(off.statusCode).toBe(200);
    expect(off.json()).toMatchObject({ allowlistMode: 'OFF', destinationEditMinRole: 'MANAGER', allowlist: [{ domain: 'co.uk', includeSubdomains: true }] });
    expect((await put({ allowlistMode: 'OFF', destinationEditMinRole: 'MEMBER' })).statusCode).toBe(200);
    expect(await db.orgPolicy.findUniqueOrThrow({ where: { organizationId: orgs.A.id } })).toMatchObject({
      allowlistMode: 'OFF',
      destinationEditMinRole: 'MEMBER',
      allowlist: [{ domain: 'co.uk', includeSubdomains: true }],
    });
    const entries = await policyAudits('A');
    expect(entries).toHaveLength(2);
    expect(entries[0].metadata).toMatchObject({ before: { allowlistMode: 'ENFORCE' }, after: { allowlistMode: 'OFF', allowlist: [{ domain: 'co.uk', includeSubdomains: true }] } });
  });

  it('on Business, omitting the allowlist keeps it; enforcing with no stored domains is refused', async () => {
    await enforce('A', [domain('allowed.test')]);
    const res = await call('A', 'PUT', '/api/v1/policies', { allowlistMode: 'ENFORCE', destinationEditMinRole: 'ADMIN' });
    expect(res.json()).toMatchObject({ destinationEditMinRole: 'ADMIN', allowlist: [{ domain: 'allowed.test' }] });
    expect((await call('A', 'PUT', '/api/v1/policies', { allowlistMode: 'ENFORCE', destinationEditMinRole: 'MEMBER' }, { as: 'OWNER' })).statusCode).toBe(200);
    expect((await call('B', 'PUT', '/api/v1/policies', { allowlistMode: 'ENFORCE', destinationEditMinRole: 'MEMBER' })).json().code).toBe('policy-invalid');
  });

  it('after a downgrade the policy stays enforced and can only be switched off', async () => {
    await enforce('A', [domain('allowed.test')], { destinationEditMinRole: 'MANAGER' });
    await db.organization.update({ where: { id: orgs.A.id }, data: { plan: 'PRO' } });

    expect((await createUrl('A', 'https://elsewhere.test/')).statusCode).toBe(422);
    const created = await createUrl('A', 'https://allowed.test/x');
    expect((await patch('A', created.json().token, { destinationUrl: 'https://allowed.test/y' }, { as: 'MEMBER' })).statusCode).toBe(403);

    const edit = await putPolicy('A', { allowlistMode: 'ENFORCE', allowlist: [domain('allowed.test'), domain('more.test')], destinationEditMinRole: 'MANAGER' });
    expect(edit.statusCode).toBe(403);
    expect(edit.json().message).toContain('can be switched off, but not changed');
    expect((await putPolicy('A', { allowlistMode: 'ENFORCE', allowlist: [domain('allowed.test')], destinationEditMinRole: 'ADMIN' })).statusCode).toBe(403);

    const off = await putPolicy('A', { allowlistMode: 'OFF', allowlist: [domain('allowed.test')], destinationEditMinRole: 'MANAGER' });
    expect(off.statusCode).toBe(200);
    expect(off.json()).toMatchObject({ allowlistMode: 'OFF', editable: false });
    expect((await putPolicy('A', { allowlistMode: 'OFF', allowlist: [domain('allowed.test')], destinationEditMinRole: 'MEMBER' })).statusCode).toBe(200);
    expect((await createUrl('A', 'https://elsewhere.test/')).statusCode).toBe(201);
    expect(await policyAudits('A')).toHaveLength(3);
  });
});

describe('preview and codes outside the policy', () => {
  async function seedCodes() {
    await makeCode('A', 'inside', { destinationUrl: 'https://www.allowed.test/' });
    await makeCode('A', 'outside', { destinationUrl: 'https://elsewhere.test/page', label: 'Old campaign' });
    await makeCode('A', 'list', { contentType: 'link-list', destinationUrl: 'https://qrauth.test/v/list', content: { title: 'L', links: [{ label: 'a', url: 'https://allowed.test/a' }, { label: 'b', url: 'https://other.test/b' }] } });
    await makeCode('A', 'vcard', { contentType: 'vcard', destinationUrl: 'https://qrauth.test/v/vcard', content: { firstName: 'A', lastName: 'B', website: 'https://other.test/' } });
    await makeCode('A', 'revoked', { destinationUrl: 'https://elsewhere.test/', status: 'REVOKED', revokedAt: new Date() });
    await makeCode('B', 'other-org', { destinationUrl: 'https://elsewhere.test/' });
  }

  it('the preview normalises the list and lists active codes outside it, with only the offending links; nothing is stored', async () => {
    await seedCodes();
    const res = await call('A', 'POST', '/api/v1/policies/preview', { allowlist: [domain('www.allowed.test'), domain('co.uk')] });
    expect(res.statusCode).toBe(200);
    const preview = res.json();
    expect(preview.entries).toMatchObject([{ ok: true, note: 'Reduced to the registrable domain allowed.test.' }, { ok: false }]);
    expect(preview.allowlist).toEqual([{ domain: 'allowed.test', includeSubdomains: true, unicode: 'allowed.test' }]);
    expect(preview.affectedTotal).toBe(2);
    expect(preview.affected).toEqual(expect.arrayContaining([
      { token: 'outside', label: 'Old campaign', contentType: 'url', outside: ['https://elsewhere.test/page'] },
      { token: 'list', label: null, contentType: 'link-list', outside: ['https://other.test/b'] },
    ]));
    expect(await db.orgPolicy.count()).toBe(0);
  });

  it('enabling marks those codes outside the policy (not revoked ones, not other organizations); they keep their destination and status', async () => {
    await seedCodes();
    const view = await enforce('A', [domain('allowed.test')]);
    expect(view.outsidePolicyCount).toBe(2);
    const rows = await db.qRCode.findMany({ select: { token: true, outsidePolicy: true, status: true, destinationUrl: true } });
    const byToken = Object.fromEntries(rows.map((r) => [r.token, r]));
    expect(byToken.outside).toMatchObject({ outsidePolicy: true, status: 'ACTIVE', destinationUrl: 'https://elsewhere.test/page' });
    expect(byToken.list.outsidePolicy).toBe(true);
    expect(byToken.inside.outsidePolicy).toBe(false);
    expect(byToken.vcard.outsidePolicy).toBe(false);
    expect(byToken.revoked.outsidePolicy).toBe(false);
    expect(byToken['other-org'].outsidePolicy).toBe(false);
    // Marking writes no edit-history revision.
    expect(await db.qRCodeRevision.count({ where: { kind: { not: 'CREATED' } } })).toBe(0);
    expect((await policyAudits('A'))[0].metadata).toMatchObject({ codesOutsidePolicy: 2 });
  });

  it('the list filter returns the marked codes of the caller’s organization', async () => {
    await seedCodes();
    await enforce('A', [domain('allowed.test')]);
    await enforce('B', [domain('allowed.test')]);
    const res = await call('A', 'GET', '/api/v1/qrcodes?outsidePolicy=true', undefined, { as: 'VIEWER' });
    expect(res.statusCode).toBe(200);
    expect(res.json().data.map((c: { token: string }) => c.token).sort()).toEqual(['list', 'outside']);
    expect(res.json().data[0].outsidePolicy).toBe(true);
    const compliant = await call('A', 'GET', '/api/v1/qrcodes?outsidePolicy=false', undefined, { as: 'VIEWER' });
    expect(compliant.json().data.map((c: { token: string }) => c.token)).not.toContain('outside');
  });

  it('label and unchanged-content saves of a marked code are not blocked; a compliant destination clears the mark', async () => {
    await seedCodes();
    await enforce('A', [domain('allowed.test')]);
    expect((await patch('A', 'outside', { label: 'Renamed', destinationUrl: 'HTTPS://ELSEWHERE.test/page' })).statusCode).toBe(200);
    expect(await code('outside')).toMatchObject({ label: 'Renamed', outsidePolicy: true });
    const list = await code('list');
    expect((await patch('A', 'list', { content: list.content, label: 'Same links' })).statusCode).toBe(200);
    expect((await code('list')).outsidePolicy).toBe(true);

    const refused = await patch('A', 'outside', { destinationUrl: 'https://still-elsewhere.test/' });
    expect(refused.statusCode).toBe(422);
    expect(refused.json()).toMatchObject({ code: 'destination-not-allowed', outside: ['https://still-elsewhere.test/'] });
    expect(refused.json().message).toBe("still-elsewhere.test is not on this organization's destination allowlist. Allowed: allowed.test (and subdomains).");

    expect((await patch('A', 'outside', { destinationUrl: 'https://go.allowed.test/' })).statusCode).toBe(200);
    expect(await code('outside')).toMatchObject({ destinationUrl: 'https://go.allowed.test/', outsidePolicy: false });
  });

  it('content sent with a URL code is not a destination change: the mark stays and no role gate applies', async () => {
    await seedCodes();
    await enforce('A', [domain('allowed.test')], { destinationEditMinRole: 'MANAGER' });
    const res = await patch('A', 'outside', { content: {}, label: 'Saved by a member' }, { as: 'MEMBER' });
    expect(res.statusCode).toBe(200);
    expect(await code('outside')).toMatchObject({ label: 'Saved by a member', outsidePolicy: true, destinationUrl: 'https://elsewhere.test/page' });
    // Through an API key (the dashboard key is MEMBER) the same save is not refused either.
    expect((await patch('A', 'outside', { content: {}, label: 'Saved by a key' }, { key: 'dashboard' })).statusCode).toBe(200);
    expect((await code('outside')).outsidePolicy).toBe(true);
  });

  it('a destination change sets the mark from the locked policy and the code’s destinations after the write', async () => {
    await seedCodes();
    // Allowlist off: a change marks nothing.
    expect((await patch('A', 'outside', { destinationUrl: 'https://still-elsewhere.test/' })).statusCode).toBe(200);
    expect((await code('outside')).outsidePolicy).toBe(false);
    await enforce('A', [domain('allowed.test')]);
    expect((await code('outside')).outsidePolicy).toBe(true);
    // A vCard content change has no destinations: never marked.
    expect((await patch('A', 'vcard', { content: { firstName: 'C', lastName: 'D' } })).statusCode).toBe(200);
    expect((await code('vcard')).outsidePolicy).toBe(false);
    // A link list change that keeps every link allowed clears its mark.
    expect((await code('list')).outsidePolicy).toBe(true);
    expect((await patch('A', 'list', { content: { title: 'L', links: [{ label: 'a', url: 'https://allowed.test/a' }] } })).statusCode).toBe(200);
    expect((await code('list')).outsidePolicy).toBe(false);
  });

  it('adding a domain clears the marks it covers; switching off clears every mark', async () => {
    await seedCodes();
    await enforce('A', [domain('allowed.test')]);
    expect((await enforce('A', [domain('allowed.test'), domain('elsewhere.test')])).outsidePolicyCount).toBe(1);
    expect((await code('outside')).outsidePolicy).toBe(false);
    await putPolicy('A', { allowlistMode: 'OFF', allowlist: [domain('allowed.test')] });
    expect(await db.qRCode.count({ where: { outsidePolicy: true } })).toBe(0);
  });
});

describe('the allowlist on every write path', () => {
  it('create: allowed domain and its subdomains pass; other hosts, and subdomains of an exact entry, are refused with 422', async () => {
    await enforce('A', [domain('allowed.test'), domain('exact.test', false)]);
    expect((await createUrl('A', 'https://allowed.test/')).statusCode).toBe(201);
    expect((await createUrl('A', 'https://deep.sub.allowed.test/')).statusCode).toBe(201);
    expect((await createUrl('A', 'https://exact.test/')).statusCode).toBe(201);
    const sub = await createUrl('A', 'https://www.exact.test/');
    expect(sub.statusCode).toBe(422);
    expect(sub.json().message).toContain('Allowed: allowed.test (and subdomains), exact.test.');
    expect((await createUrl('A', 'https://notallowed.test/')).statusCode).toBe(422);
    expect(await db.qRCode.count()).toBe(3);
  });

  it('IDN entries match the same name in Unicode or punycode, and not a confusable of an allowed domain', async () => {
    await enforce('A', [domain('münchen.de'), domain('allowed.test')]);
    expect((await createUrl('A', 'https://www.münchen.de/')).statusCode).toBe(201);
    expect((await createUrl('A', 'https://xn--mnchen-3ya.de/x')).statusCode).toBe(201);
    expect((await createUrl('A', 'https://аllowed.test/')).statusCode).toBe(422);
  });

  it('allowed hosts still go through Web Risk and the host rules', async () => {
    await enforce('A', [domain('allowed.test')]);
    const flagged = await createUrl('A', 'https://allowed.test/malware');
    expect(flagged.statusCode).toBe(422);
    expect(flagged.json()).toMatchObject({ error: 'DestinationFlagged', threatTypes: ['MALWARE'] });
    expect((await createUrl('A', 'https://localhost/')).statusCode).toBe(400);
  });

  it('a lookalike on an allowlisted host is still flagged (warning and fraud incident)', async () => {
    await enforce('A', [domain('paypa1.com')]);
    const res = await createUrl('A', 'https://paypa1.com/login');
    expect(res.statusCode).toBe(201);
    expect(res.json().domain_warnings[0]).toMatchObject({ similar_to: 'paypal.com' });
    expect(await db.fraudIncident.findFirstOrThrow()).toMatchObject({ details: expect.objectContaining({ reason: 'suspicious_domain', url: 'https://paypa1.com/login' }) });
  });

  it('smart link and link list: every link must be allowed, on create and on a content change', async () => {
    await enforce('A', [domain('allowed.test'), domain('apple.com'), domain('google.com')]);
    expect((await call('A', 'POST', '/api/v1/qrcodes', { contentType: 'app-link', content: APP })).statusCode).toBe(201);
    const badApp = await call('A', 'POST', '/api/v1/qrcodes', { contentType: 'app-link', content: { ...APP, fallbackUrl: 'https://other.test/' } });
    expect(badApp.statusCode).toBe(422);
    expect(badApp.json().outside).toEqual(['https://other.test/']);

    const list = await call('A', 'POST', '/api/v1/qrcodes', { contentType: 'link-list', content: LIST });
    expect(list.statusCode).toBe(201);
    const badList = { ...LIST, links: [...LIST.links, { label: 'x', url: 'https://other.test/x' }] };
    expect((await call('A', 'POST', '/api/v1/qrcodes', { contentType: 'link-list', content: badList })).statusCode).toBe(422);
    expect((await patch('A', list.json().token, { content: badList })).statusCode).toBe(422);
    expect((await patch('A', list.json().token, { content: { ...LIST, title: 'Renamed list' } })).statusCode).toBe(200);
  });

  it('restore: a revision outside the list cannot be restored; an allowed one can', async () => {
    await makeCode('A', 'r1', { destinationUrl: 'https://elsewhere.test/' });
    expect((await patch('A', 'r1', { destinationUrl: 'https://allowed.test/one' })).statusCode).toBe(200);
    expect((await patch('A', 'r1', { destinationUrl: 'https://allowed.test/two' })).statusCode).toBe(200);
    await enforce('A', [domain('allowed.test')]);
    const refused = await call('A', 'POST', '/api/v1/qrcodes/r1/history/1/restore');
    expect(refused.statusCode).toBe(422);
    expect(refused.json().code).toBe('destination-not-allowed');
    expect((await call('A', 'POST', '/api/v1/qrcodes/r1/history/2/restore')).statusCode).toBe(200);
    expect((await code('r1')).destinationUrl).toBe('https://allowed.test/one');
  });

  it('bulk: items outside the list fail with DESTINATION_NOT_ALLOWED, the rest are created', async () => {
    await enforce('A', [domain('allowed.test')]);
    const res = await call('A', 'POST', '/api/v1/qrcodes/bulk', {
      items: [{ destinationUrl: 'https://allowed.test/1' }, { destinationUrl: 'https://other.test/2', label: 'no' }, { destinationUrl: 'https://a.allowed.test/3' }],
    });
    expect(res.statusCode).toBe(207);
    expect(res.json().summary).toEqual({ total: 3, succeeded: 2, failed: 1 });
    expect(res.json().results[1]).toMatchObject({ index: 1, success: false, errorCode: 'DESTINATION_NOT_ALLOWED', label: 'no', error: expect.stringContaining('other.test') });
  });

  it('a policy enabled while a create is in flight refuses it in the create’s transaction', async () => {
    let release!: () => void;
    let entered!: () => void;
    const inScreening = new Promise<void>((r) => { entered = r; });
    stubs.gate = { wait: new Promise<void>((r) => { release = r; }), entered: () => entered() };
    try {
      const pending = createUrl('A', 'https://slow.elsewhere.test/');
      await inScreening;
      await enforce('A', [domain('allowed.test')]);
      release();
      const res = await pending;
      expect(res.statusCode).toBe(422);
      expect(res.json().code).toBe('destination-not-allowed');
      expect(await db.qRCode.count()).toBe(0);
    } finally {
      stubs.gate = { wait: Promise.resolve(), entered: () => {} };
    }
  });

  it('another organization’s policy does not apply', async () => {
    await enforce('B', [domain('allowed.test')]);
    expect((await createUrl('A', 'https://elsewhere.test/')).statusCode).toBe(201);
    expect((await createUrl('B', 'https://elsewhere.test/')).statusCode).toBe(422);
  });
});

describe('destination-edit role', () => {
  beforeEach(async () => {
    await makeCode('A', 'c1');
  });

  it('with MANAGER, a member cannot change the destination or content but can edit the label; a manager can', async () => {
    await putPolicy('A', { destinationEditMinRole: 'MANAGER' });
    const refused = await patch('A', 'c1', { destinationUrl: 'https://two.test/' }, { as: 'MEMBER' });
    expect(refused.statusCode).toBe(403);
    expect(refused.json()).toMatchObject({ code: 'destination-edit-role-required', requiredRole: 'MANAGER', message: expect.stringContaining('Manager role or higher') });
    expect((await patch('A', 'c1', { label: 'ok', destinationUrl: 'https://allowed.test/' }, { as: 'MEMBER' })).statusCode).toBe(200);
    expect((await patch('A', 'c1', { destinationUrl: 'https://two.test/' }, { as: 'MANAGER' })).statusCode).toBe(200);
    // Creating is not a change: members still create codes.
    expect((await createUrl('A', 'https://new.test/', { as: 'MEMBER' })).statusCode).toBe(201);
  });

  it('reads the user’s current membership, not the role in the token: demoted or removed members are refused', async () => {
    await putPolicy('A', { destinationEditMinRole: 'MANAGER' });
    await db.membership.update({ where: { userId_organizationId: { userId: orgs.A.users.MANAGER, organizationId: orgs.A.id } }, data: { role: 'MEMBER' } });
    expect((await patch('A', 'c1', { destinationUrl: 'https://two.test/' }, { as: 'MANAGER' })).statusCode).toBe(403);
    await db.membership.delete({ where: { userId_organizationId: { userId: orgs.A.users.ADMIN, organizationId: orgs.A.id } } });
    expect((await patch('A', 'c1', { destinationUrl: 'https://two.test/' }, { as: 'ADMIN' })).statusCode).toBe(403);
  });

  it('restore keeps its MANAGER floor and follows a higher minimum', async () => {
    await patch('A', 'c1', { destinationUrl: 'https://two.test/' });
    expect((await call('A', 'POST', '/api/v1/qrcodes/c1/history/1/restore', undefined, { as: 'MEMBER' })).statusCode).toBe(403);
    await putPolicy('A', { destinationEditMinRole: 'ADMIN' });
    const refused = await call('A', 'POST', '/api/v1/qrcodes/c1/history/1/restore', undefined, { as: 'MANAGER' });
    expect(refused.json()).toMatchObject({ code: 'destination-edit-role-required', requiredRole: 'ADMIN' });
    expect((await call('A', 'POST', '/api/v1/qrcodes/c1/history/1/restore', undefined, { as: 'ADMIN' })).statusCode).toBe(200);
  });

  it('a CLI key follows its creator’s current role: allowed as MANAGER, refused once the creator is demoted or removed', async () => {
    await putPolicy('A', { destinationEditMinRole: 'MANAGER' });
    expect((await patch('A', 'c1', { destinationUrl: 'https://two.test/' }, { key: 'cli' })).statusCode).toBe(200);
    const creator = { userId_organizationId: { userId: orgs.A.users.MANAGER, organizationId: orgs.A.id } };
    await db.membership.update({ where: creator, data: { role: 'MEMBER' } });
    const demoted = await patch('A', 'c1', { destinationUrl: 'https://three.test/' }, { key: 'cli' });
    expect(demoted.statusCode).toBe(403);
    expect(demoted.json().message).toContain("its owner's current role");
    await db.membership.delete({ where: creator });
    expect((await patch('A', 'c1', { destinationUrl: 'https://three.test/' }, { key: 'cli' })).statusCode).toBe(403);
  });

  it('a legacy key (no owner) cannot change destinations under a minimum above MEMBER', async () => {
    expect((await patch('A', 'c1', { destinationUrl: 'https://two.test/' }, { key: 'dashboard' })).statusCode).toBe(200);
    await putPolicy('A', { destinationEditMinRole: 'MANAGER' });
    const refused = await patch('A', 'c1', { destinationUrl: 'https://three.test/' }, { key: 'dashboard' });
    expect(refused.statusCode).toBe(403);
    expect(refused.json().message).toContain('legacy API key with no owner');
    expect((await patch('A', 'c1', { label: 'keys can still rename' }, { key: 'dashboard' })).statusCode).toBe(200);
  });

  it('a minimum raised while an edit is in flight refuses it in the edit’s transaction', async () => {
    let release!: () => void;
    let entered!: () => void;
    const inScreening = new Promise<void>((r) => { entered = r; });
    stubs.gate = { wait: new Promise<void>((r) => { release = r; }), entered: () => entered() };
    try {
      const pending = patch('A', 'c1', { destinationUrl: 'https://slow.two.test/' }, { as: 'MEMBER' });
      await inScreening;
      await putPolicy('A', { destinationEditMinRole: 'ADMIN' });
      release();
      expect((await pending).statusCode).toBe(403);
      expect((await code('c1')).destinationUrl).toBe('https://allowed.test/');
    } finally {
      stubs.gate = { wait: Promise.resolve(), entered: () => {} };
    }
  });
});
