/**
 * Organization audit log (Milestone 2, ADR-0008) against a real Postgres:
 * the append-only triggers on audit_logs and qr_code_revisions (UPDATE and
 * DELETE refused outside retention and erasure), actor types written by
 * real routes (user, API key, superadmin) and by a system job, and
 * GET /api/v1/audit: tenant isolation, role and plan gating, the merged
 * timeline of audit rows and QR revisions with cursor pagination, filters,
 * and the CSV export with formula cells neutralised. Run by
 * scripts/ci-verify.sh `db`.
 */
import { readFileSync } from 'node:fs';

import { PrismaClient } from '@prisma/client';
import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

const url = process.env.TEST_DATABASE_URL;
if (!url) throw new Error('TEST_DATABASE_URL is not set');
if (!/test/i.test(new URL(url).pathname)) throw new Error('TEST_DATABASE_URL must name a test database (the suite truncates tables)');

process.env.DATABASE_URL ??= url;
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'db-test-only-throwaway-secret-0000000000';
process.env.ADMIN_EMAILS = 'staff@qrauth.audit.test';

const stubs = vi.hoisted(() => ({ noQueue: { add: async () => undefined } }));
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

const db = new PrismaClient({ datasources: { db: { url } } });
let app: FastifyInstance;

type Role = 'OWNER' | 'ADMIN' | 'MANAGER' | 'MEMBER' | 'VIEWER';
type Org = { id: string; userId: string; apiKeyId: string };
const orgs: Record<'A' | 'B', Org> = {} as never;
let staffUserId = '';
const DAY = 24 * 60 * 60 * 1000;

type Actor = { role?: Role; viaApiKey?: boolean; staff?: boolean };

function call(org: 'A' | 'B', method: 'GET' | 'POST' | 'PATCH' | 'DELETE', path: string, body?: unknown, actor: Actor = {}) {
  const o = orgs[org];
  const user = actor.staff
    ? { id: staffUserId, orgId: o.id, role: 'OWNER', email: 'staff@qrauth.audit.test' }
    : actor.viaApiKey
      ? { id: 'api-key', orgId: o.id, role: actor.role ?? 'ADMIN', email: '', apiKeyId: o.apiKeyId }
      : { id: o.userId, orgId: o.id, role: actor.role ?? 'OWNER', email: `owner@${org}.audit.test` };
  return app.inject({
    method,
    url: path,
    headers: {
      'x-test-user': JSON.stringify(user),
      'user-agent': 'audit-db-test/1.0',
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    ...(body === undefined ? {} : { payload: JSON.stringify(body) }),
  });
}

async function reset(plan: 'FREE' | 'PRO' | 'BUSINESS' | 'ENTERPRISE' = 'BUSINESS'): Promise<void> {
  await db.$executeRawUnsafe('TRUNCATE "organizations", "users" CASCADE');
  for (const org of ['A', 'B'] as const) {
    const o = await db.organization.create({ data: { name: `Org ${org}`, slug: `org-${org.toLowerCase()}-audit-test`, email: `${org}@audit.test`, plan } });
    const user = await db.user.create({ data: { name: `Owner ${org}`, email: `owner@${org}.audit.test`, passwordHash: 'x', emailVerified: true } });
    await db.membership.create({ data: { userId: user.id, organizationId: o.id, role: 'OWNER' } });
    const apiKey = await db.apiKey.create({ data: { organizationId: o.id, keyHash: `hash-${o.id}`, prefix: 'qrauth_ab12', label: `CI key ${org}` } });
    orgs[org] = { id: o.id, userId: user.id, apiKeyId: apiKey.id };
  }
  staffUserId = (await db.user.create({ data: { name: 'Staff', email: 'staff@qrauth.audit.test', passwordHash: 'x', emailVerified: true } })).id;
}

async function makeCode(org: 'A' | 'B', token: string) {
  const key = await db.signingKey.upsert({
    where: { keyId: `key-${orgs[org].id}` },
    create: { organizationId: orgs[org].id, publicKey: 'pk', keyId: `key-${orgs[org].id}` },
    update: {},
  });
  return db.qRCode.create({
    data: { token, organizationId: orgs[org].id, signingKeyId: key.id, destinationUrl: 'https://one.example.test/', signature: 'sig', algVersion: 'test' },
  });
}

async function revision(org: 'A' | 'B', qrCodeId: string, n: number, createdAt: Date, extra: Record<string, unknown> = {}) {
  return db.qRCodeRevision.create({
    data: {
      qrCodeId, organizationId: orgs[org].id, revision: n, kind: n === 1 ? 'CREATED' : 'UPDATED',
      changes: { destinationUrl: { before: null, after: `https://v${n}.example.test/` } },
      actorType: 'USER', actorUserId: orgs[org].userId, createdAt, ...extra,
    },
  });
}

async function logRow(org: 'A' | 'B', createdAt: Date, extra: Record<string, unknown> = {}) {
  return db.auditLog.create({
    data: {
      organizationId: orgs[org].id, userId: orgs[org].userId, actorType: 'USER', actorId: orgs[org].userId,
      action: 'member.role.update', resource: 'Membership', resourceId: 'm1', ipAddress: '203.0.113.9',
      userAgent: 'ua', createdAt, ...extra,
    },
  });
}

/** A date range around now, as the export requires one. */
const RANGE = `from=${encodeURIComponent(new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString())}&to=${encodeURIComponent(new Date(Date.now() + 2 * 24 * 60 * 60 * 1000).toISOString())}`;

const audit = async (org: 'A' | 'B', qs = '', actor: Actor = {}) => call(org, 'GET', `/api/v1/audit${qs}`, undefined, actor);

beforeAll(async () => {
  app = Fastify({ genReqId: () => `req-${Math.random().toString(36).slice(2, 10)}` });
  app.decorate('prisma', db as never);
  app.decorateRequest('user', null);
  app.decorate('authenticate', async (request: { headers: Record<string, string | undefined>; user: unknown }) => {
    request.user = JSON.parse(request.headers['x-test-user'] ?? '{}');
  });
  const { default: auditRoutes } = await import('../../src/routes/audit.js');
  const { default: adminRoutes } = await import('../../src/routes/admin.js');
  const { tagRoutes } = await import('../../src/routes/qr-organize.js');
  const { default: organizationRoutes } = await import('../../src/routes/organizations.js');
  const { default: analyticsRoutes } = await import('../../src/routes/analytics.js');
  await app.register(auditRoutes, { prefix: '/api/v1/audit' });
  await app.register(adminRoutes, { prefix: '/api/v1/admin' });
  await app.register(tagRoutes, { prefix: '/api/v1/tags' });
  await app.register(organizationRoutes, { prefix: '/api/v1/organizations' });
  await app.register(analyticsRoutes, { prefix: '/api/v1/analytics' });
  await app.ready();
});

afterAll(async () => {
  await app.close();
  await db.$disconnect();
});

// ---------------------------------------------------------------------------

describe('append-only audit_logs', () => {
  beforeEach(() => reset());

  it('refuses UPDATE and DELETE outside retention and erasure', async () => {
    const row = await logRow('A', new Date());
    await expect(db.$executeRawUnsafe(`UPDATE "audit_logs" SET "action" = 'x' WHERE "id" = '${row.id}'`)).rejects.toThrow(/append-only/);
    await expect(db.auditLog.update({ where: { id: row.id }, data: { metadata: { forged: true } } })).rejects.toThrow(/append-only/);
    await expect(db.$executeRawUnsafe(`DELETE FROM "audit_logs" WHERE "id" = '${row.id}'`)).rejects.toThrow(/append-only/);
    // Old enough, but without the retention flag.
    const old = await logRow('A', new Date(Date.now() - 731 * DAY));
    await expect(db.auditLog.delete({ where: { id: old.id } })).rejects.toThrow(/append-only/);
    expect(await db.auditLog.count()).toBe(2);
  });

  it('the retention purge removes entries older than 730 days and keeps the rest', async () => {
    const { purgeExpiredAuditLogs } = await import('../../src/services/audit.js');
    await logRow('A', new Date(Date.now() - 731 * DAY));
    const kept = await logRow('A', new Date(Date.now() - 729 * DAY));
    expect(await purgeExpiredAuditLogs(db)).toBe(1);
    expect((await db.auditLog.findMany()).map((r) => r.id)).toEqual([kept.id]);
  });

  it('the retention flag does not allow deleting recent entries or any update', async () => {
    const { withAuditMaintenance } = await import('../../src/services/audit.js');
    const row = await logRow('A', new Date());
    await expect(withAuditMaintenance(db, 'retention', (tx) => tx.auditLog.delete({ where: { id: row.id } }))).rejects.toThrow(/append-only/);
    await expect(withAuditMaintenance(db, 'retention', (tx) => tx.auditLog.update({ where: { id: row.id }, data: { ipAddress: null } }))).rejects.toThrow(/append-only/);
  });

  it('erasure clears only IP and user agent, and the flag ends with its transaction', async () => {
    const { eraseAuditPersonalData, withAuditMaintenance } = await import('../../src/services/audit.js');
    const row = await logRow('A', new Date());
    expect(await db.$transaction((tx) => eraseAuditPersonalData(tx, { userId: orgs.A.userId, email: 'owner@a.audit.test' }))).toBe(1);
    expect(await db.auditLog.findUniqueOrThrow({ where: { id: row.id } })).toMatchObject({ ipAddress: null, userAgent: null, action: 'member.role.update' });
    await expect(withAuditMaintenance(db, 'erasure', (tx) => tx.auditLog.update({ where: { id: row.id }, data: { action: 'forged' } }))).rejects.toThrow(/append-only/);
    // Set inside one transaction, the flag does not leak to the next statement on the pool.
    await expect(db.auditLog.update({ where: { id: row.id }, data: { ipAddress: null } })).rejects.toThrow(/append-only/);
  });

  it("erasure covers the user's API keys and redacts the email elsewhere; nothing else may change", async () => {
    const { eraseAuditPersonalData, withAuditMaintenance } = await import('../../src/services/audit.js');
    const EMAIL = 'owner@a.audit.test';
    const userKey = await db.apiKey.create({ data: { organizationId: orgs.A.id, keyHash: 'h-user-key', prefix: 'qrauth_cli1', createdByUserId: orgs.A.userId, source: 'cli' } });
    const byKey = await db.auditLog.create({
      data: { organizationId: orgs.A.id, actorType: 'API_KEY', actorId: userKey.id, action: 'tag.create', resource: 'Tag', resourceId: 't1', ipAddress: '203.0.113.20', userAgent: 'cli' },
    });
    const otherKey = await db.auditLog.create({
      data: { organizationId: orgs.A.id, actorType: 'API_KEY', actorId: orgs.A.apiKeyId, action: 'tag.create', resource: 'Tag', resourceId: 't2', ipAddress: '203.0.113.21', userAgent: 'ci' },
    });
    // Another admin invited the user: their IP stays, the user's address goes.
    const invite = await db.auditLog.create({
      data: {
        organizationId: orgs.B.id, userId: orgs.B.userId, actorType: 'USER', actorId: orgs.B.userId, action: 'invitation.create',
        resource: 'Invitation', resourceId: 'i1', ipAddress: '203.0.113.30', userAgent: 'admin-ua',
        metadata: { email: EMAIL, role: 'MEMBER', note: `not ${EMAIL}` },
      },
    });
    const own = await logRow('A', new Date(), { metadata: { ipCountry: 'GR', reason: 'x' } });

    expect(await db.$transaction((tx) => eraseAuditPersonalData(tx, { userId: orgs.A.userId, email: EMAIL }))).toBe(3);

    expect(await db.auditLog.findUniqueOrThrow({ where: { id: byKey.id } })).toMatchObject({ ipAddress: null, userAgent: null });
    expect(await db.auditLog.findUniqueOrThrow({ where: { id: otherKey.id } })).toMatchObject({ ipAddress: '203.0.113.21', userAgent: 'ci' });
    expect(await db.auditLog.findUniqueOrThrow({ where: { id: invite.id } })).toMatchObject({
      ipAddress: '203.0.113.30', userAgent: 'admin-ua',
      // Whole values only: a longer string containing the address is not rewritten.
      metadata: { email: '[redacted]', role: 'MEMBER', note: `not ${EMAIL}` },
    });
    expect((await db.auditLog.findUniqueOrThrow({ where: { id: own.id } })).metadata).toEqual({ reason: 'x' });

    // Under the erasure flag, any other metadata change is still refused.
    await expect(withAuditMaintenance(db, 'erasure', (tx) => tx.auditLog.update({ where: { id: invite.id }, data: { metadata: { email: 'someone@else.test' } } }))).rejects.toThrow(/append-only/);
    // So is setting an IP to anything but null.
    await expect(withAuditMaintenance(db, 'erasure', (tx) => tx.auditLog.update({ where: { id: otherKey.id }, data: { ipAddress: '192.0.2.1' } }))).rejects.toThrow(/append-only/);
  });

  it('erasure matches the email case-insensitively, including mixed-case legacy entries', async () => {
    const { eraseAuditPersonalData } = await import('../../src/services/audit.js');
    // A legacy entry (before actor columns) that stored the address as typed.
    const legacy = await db.auditLog.create({
      data: {
        organizationId: orgs.B.id, userId: orgs.B.userId, action: 'invitation.create', resource: 'Invitation', resourceId: 'i-legacy',
        ipAddress: '203.0.113.31', userAgent: 'admin-ua',
        metadata: { email: 'Owner@A.Audit.TEST', invitees: ['OWNER@a.audit.test', 'other@b.audit.test'], role: 'MEMBER' },
      },
    });

    expect(await db.$transaction((tx) => eraseAuditPersonalData(tx, { userId: orgs.A.userId, email: 'owner@A.audit.test' }))).toBe(1);

    expect(await db.auditLog.findUniqueOrThrow({ where: { id: legacy.id } })).toMatchObject({
      ipAddress: '203.0.113.31', userAgent: 'admin-ua',
      metadata: { email: '[redacted]', invitees: ['[redacted]', 'other@b.audit.test'], role: 'MEMBER' },
    });
  });

  it('deleting an organization removes its entries (cascade)', async () => {
    await logRow('A', new Date());
    await logRow('B', new Date());
    await db.organization.delete({ where: { id: orgs.A.id } });
    expect(await db.auditLog.count()).toBe(1);
  });

  it('a user can be deleted while the trail keeps the actor id (no foreign key)', async () => {
    const row = await logRow('A', new Date());
    await db.membership.deleteMany({ where: { userId: orgs.A.userId } });
    await db.apiKey.deleteMany({ where: { organizationId: orgs.A.id } });
    await db.user.delete({ where: { id: orgs.A.userId } });
    expect((await db.auditLog.findUniqueOrThrow({ where: { id: row.id } })).actorId).toBe(orgs.A.userId);
  });
});

describe('append-only qr_code_revisions (retention flag)', () => {
  beforeEach(() => reset());

  it('refuses an age-based DELETE without the retention flag; the purge still works', async () => {
    const { purgeExpiredRevisions } = await import('../../src/services/qr-revisions.js');
    const code = await makeCode('A', 'r1');
    const old = await revision('A', code.id, 1, new Date(Date.now() - 800 * DAY));
    await revision('A', code.id, 2, new Date(Date.now() - 731 * DAY));
    await revision('A', code.id, 3, new Date());
    await expect(db.qRCodeRevision.delete({ where: { id: old.id } })).rejects.toThrow(/append-only/);
    await expect(db.$executeRawUnsafe(`UPDATE "qr_code_revisions" SET "kind" = 'X'`)).rejects.toThrow(/append-only/);
    expect(await purgeExpiredRevisions(db)).toBe(2);
    expect(await db.qRCodeRevision.count()).toBe(1);
  });
});

describe('actor types', () => {
  beforeEach(() => reset());

  it('a route called with an API key records an API_KEY actor, with request id, IP and user agent', async () => {
    const res = await call('A', 'POST', '/api/v1/tags', { name: 'Spring' }, { viaApiKey: true, role: 'ADMIN' });
    expect(res.statusCode).toBe(201);
    const row = await db.auditLog.findFirstOrThrow({ where: { action: 'tag.create' } });
    expect(row).toMatchObject({ organizationId: orgs.A.id, actorType: 'API_KEY', actorId: orgs.A.apiKeyId, userId: null, userAgent: 'audit-db-test/1.0' });
    expect(row.requestId).toMatch(/^req-/);
    expect(row.ipAddress).toBeTruthy();
  });

  it('a superadmin route records a SUPERADMIN actor in the affected organization, shown to it as QRAuth', async () => {
    const res = await call('A', 'POST', `/api/v1/admin/organizations/${orgs.B.id}/suspend`, { reason: 'Phishing reports confirmed' }, { staff: true });
    expect(res.statusCode).toBe(200);
    const row = await db.auditLog.findFirstOrThrow({ where: { action: 'admin.organization.suspend' } });
    expect(row).toMatchObject({ organizationId: orgs.B.id, actorType: 'SUPERADMIN', actorId: staffUserId });
    await db.organization.update({ where: { id: orgs.B.id }, data: { suspendedAt: null } });
    const [entry] = (await audit('B')).json().data;
    expect(entry.actor).toEqual({ type: 'SUPERADMIN', id: null, name: 'QRAuth' });
    expect(entry.ipAddress).toBeNull();
    expect(entry.userAgent).toBeNull();
    // Staff are not found by id.
    expect((await audit('B', `?actor=${staffUserId}`)).json().data).toEqual([]);
  });

  it('a system job records a SYSTEM actor with no request, IP or user agent', async () => {
    const { recordAudit, systemAuditContext } = await import('../../src/services/audit.js');
    await recordAudit(db, systemAuditContext('stripe'), {
      organizationId: orgs.A.id, action: 'billing.plan.change', resource: 'Organization', resourceId: orgs.A.id, metadata: { from: 'PRO', to: 'BUSINESS' },
    });
    const [entry] = (await audit('A', '?actorType=SYSTEM')).json().data;
    expect(entry).toMatchObject({ action: 'billing.plan.change', actor: { type: 'SYSTEM', id: 'stripe' }, requestId: null, ipAddress: null, userAgent: null });
  });
});

describe('no-op and concurrent calls', () => {
  beforeEach(() => reset());

  const ctxA = () => ({ actor: { type: 'USER' as const, userId: orgs.A.userId }, requestId: 'req-test', ip: null, userAgent: null });

  it('two concurrent revokes of one device write one entry', async () => {
    const { DeviceService } = await import('../../src/services/device.js');
    const { recordAudit } = await import('../../src/services/audit.js');
    const device = await db.trustedDevice.create({ data: { userId: orgs.A.userId, fingerprint: 'fp-1', name: 'Laptop', trustLevel: 'TRUSTED' } });
    const service = new DeviceService(db);
    const hook = (tx: never, metadata: Record<string, unknown>) =>
      recordAudit(tx, ctxA(), { organizationId: orgs.A.id, action: 'device.revoke', resource: 'TrustedDevice', resourceId: device.id, metadata });
    const results = await Promise.all([service.revokeDevice(device.id, orgs.A.userId, hook), service.revokeDevice(device.id, orgs.A.userId, hook)]);
    expect(results.filter(Boolean)).toHaveLength(1);
    expect(await db.auditLog.count({ where: { action: 'device.revoke' } })).toBe(1);
    // Revoking it again later is a no-op.
    expect(await service.revokeDevice(device.id, orgs.A.userId, hook)).toBeNull();
    expect(await db.auditLog.count({ where: { action: 'device.revoke' } })).toBe(1);
  });

  it('acknowledging or resolving a fraud incident twice writes one entry each', async () => {
    const code = await makeCode('A', 'fraud1');
    const incident = await db.fraudIncident.create({ data: { qrCodeId: code.id, type: 'PROXY_DETECTED', severity: 'HIGH', details: {} } });
    for (let i = 0; i < 2; i++) {
      expect((await call('A', 'POST', `/api/v1/analytics/fraud/${incident.id}/acknowledge`, {})).statusCode).toBe(200);
      expect((await call('A', 'POST', `/api/v1/analytics/fraud/${incident.id}/resolve`, { note: 'checked' })).statusCode).toBe(200);
    }
    expect(await db.auditLog.count({ where: { action: 'fraudIncident.acknowledge' } })).toBe(1);
    expect(await db.auditLog.count({ where: { action: 'fraudIncident.resolve' } })).toBe(1);
  });

  it('saving the same device policy twice writes one entry', async () => {
    const { DevicePolicyService } = await import('../../src/services/device-policy.js');
    const { recordAudit } = await import('../../src/services/audit.js');
    const service = new DevicePolicyService(db);
    const hook = (tx: never, metadata: Record<string, unknown>) =>
      recordAudit(tx, ctxA(), { organizationId: orgs.A.id, action: 'devicePolicy.update', resource: 'DevicePolicy', resourceId: orgs.A.id, metadata });
    await service.upsertPolicy(orgs.A.id, { maxDevices: 3 }, hook);
    await service.upsertPolicy(orgs.A.id, { maxDevices: 3 }, hook);
    expect(await db.auditLog.count({ where: { action: 'devicePolicy.update' } })).toBe(1);
    await service.upsertPolicy(orgs.A.id, { maxDevices: 4 }, hook);
    expect(await db.auditLog.count({ where: { action: 'devicePolicy.update' } })).toBe(2);
  });
});

describe('an audit entry commits with its change', () => {
  beforeEach(() => reset());

  it('when the audit insert fails, the change rolls back (route)', async () => {
    // Make the insert of this one action fail inside the database.
    await db.$executeRawUnsafe(`
      CREATE FUNCTION test_fail_tag_audit() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN IF NEW."action" = 'tag.create' THEN RAISE EXCEPTION 'audit insert refused for test'; END IF; RETURN NEW; END; $$`);
    await db.$executeRawUnsafe(`CREATE TRIGGER test_fail_tag_audit BEFORE INSERT ON "audit_logs" FOR EACH ROW EXECUTE FUNCTION test_fail_tag_audit()`);
    try {
      const res = await call('A', 'POST', '/api/v1/tags', { name: 'Doomed', color: 'blue' });
      expect(res.statusCode).toBe(500);
      expect(await db.tag.count({ where: { organizationId: orgs.A.id } })).toBe(0);
      expect(await db.auditLog.count()).toBe(0);
    } finally {
      await db.$executeRawUnsafe('DROP TRIGGER test_fail_tag_audit ON "audit_logs"');
      await db.$executeRawUnsafe('DROP FUNCTION test_fail_tag_audit()');
    }
  });

  it('device revoke is one transaction: a failing audit entry leaves device, passkeys and OIDC sessions untouched', async () => {
    const { DeviceService } = await import('../../src/services/device.js');
    const device = await db.trustedDevice.create({ data: { userId: orgs.A.userId, fingerprint: 'fp-tx', trustLevel: 'TRUSTED' } });
    const passkey = await db.passkey.create({
      data: { userId: orgs.A.userId, deviceId: device.id, credentialId: 'cred-tx', publicKey: Buffer.from('pk'), transports: [] },
    });
    const session = await db.oidcSession.create({
      data: { userId: orgs.A.userId, sessionTokenHash: 'session-hash-tx', expiresAt: new Date(Date.now() + DAY) },
    });
    const failing = async () => {
      throw new Error('audit write failed');
    };

    await expect(new DeviceService(db).revokeDevice(device.id, orgs.A.userId, failing)).rejects.toThrow('audit write failed');

    expect(await db.trustedDevice.findUniqueOrThrow({ where: { id: device.id } })).toMatchObject({ revokedAt: null, trustLevel: 'TRUSTED' });
    expect((await db.passkey.findUniqueOrThrow({ where: { id: passkey.id } })).revokedAt).toBeNull();
    expect((await db.oidcSession.findUniqueOrThrow({ where: { id: session.id } })).revokedAt).toBeNull();
    expect(await db.auditLog.count()).toBe(0);

    // Without the failure, all of it happens together, with one entry.
    const { recordAudit } = await import('../../src/services/audit.js');
    await new DeviceService(db).revokeDevice(device.id, orgs.A.userId, (tx, metadata) =>
      recordAudit(tx as never, { actor: { type: 'USER', userId: orgs.A.userId }, requestId: null, ip: null, userAgent: null }, {
        organizationId: orgs.A.id, action: 'device.revoke', resource: 'TrustedDevice', resourceId: device.id, metadata,
      }));
    expect((await db.trustedDevice.findUniqueOrThrow({ where: { id: device.id } })).revokedAt).not.toBeNull();
    expect((await db.passkey.findUniqueOrThrow({ where: { id: passkey.id } })).revokedAt).not.toBeNull();
    expect((await db.oidcSession.findUniqueOrThrow({ where: { id: session.id } })).revokedAt).not.toBeNull();
    expect(await db.auditLog.count({ where: { action: 'device.revoke' } })).toBe(1);
  });
});

describe('staff entries written before the actor model', () => {
  beforeEach(() => reset());

  /** Runs the backfill of migration 20261103130000, as `migrate deploy` did. */
  async function runStaffBackfill(): Promise<void> {
    const dir = new URL('../../prisma/migrations/20261103130000_audit_log_staff_actor_backfill/migration.sql', import.meta.url);
    const sql = readFileSync(dir, 'utf8');
    const block = sql.slice(sql.indexOf('-- BEGIN staff-actor-backfill'), sql.indexOf('-- END staff-actor-backfill'));
    for (const stmt of block.split(';').map((s) => s.replace(/--.*$/gm, '').trim()).filter(Boolean)) {
      await db.$executeRawUnsafe(stmt);
    }
  }

  it('are SUPERADMIN after the backfill: shown as QRAuth on both endpoints and the CSV, never found by staff id', async () => {
    // A legacy row: staff user as a USER actor, with IP and user agent.
    await db.auditLog.create({
      data: {
        organizationId: orgs.A.id, userId: staffUserId, actorType: 'USER', actorId: staffUserId,
        action: 'admin.organization.suspend', resource: 'Organization', resourceId: orgs.A.id,
        metadata: { reason: 'Phishing' }, ipAddress: '198.51.100.7', userAgent: 'StaffBrowser/1.0',
      },
    });
    const member = await logRow('A', new Date(Date.now() - 1000));
    await runStaffBackfill();
    expect((await db.auditLog.findFirstOrThrow({ where: { action: 'admin.organization.suspend' } })).actorType).toBe('SUPERADMIN');
    expect((await db.auditLog.findUniqueOrThrow({ where: { id: member.id } })).actorType).toBe('USER');

    const leaks = (body: string) => {
      for (const secret of [staffUserId, 'staff@qrauth.audit.test', 'Staff', '198.51.100.7', 'StaffBrowser']) {
        expect(body, secret).not.toContain(secret);
      }
    };

    const page = await audit('A');
    const staffEntry = page.json().data.find((e: { action: string }) => e.action === 'admin.organization.suspend');
    expect(staffEntry.actor).toEqual({ type: 'SUPERADMIN', id: null, name: 'QRAuth' });
    leaks(page.body);

    const csv = await call('A', 'GET', `/api/v1/audit/export.csv?from=${encodeURIComponent(new Date(Date.now() - DAY).toISOString())}&to=${encodeURIComponent(new Date(Date.now() + DAY).toISOString())}`);
    expect(csv.body).toContain('SUPERADMIN,,QRAuth');
    leaks(csv.body);

    expect((await audit('A', `?actor=${staffUserId}`)).json().data).toEqual([]);
  });

  it('the legacy endpoint shows them without staff identity, IP or user agent, and userId cannot find them', async () => {
    await db.auditLog.create({
      data: {
        organizationId: orgs.A.id, userId: staffUserId, actorType: 'SUPERADMIN', actorId: staffUserId,
        action: 'admin.organization.suspend', resource: 'Organization', resourceId: orgs.A.id,
        ipAddress: '198.51.100.7', userAgent: 'StaffBrowser/1.0',
      },
    });
    const legacy = await call('A', 'GET', `/api/v1/organizations/${orgs.A.id}/audit-logs`);
    expect(legacy.statusCode).toBe(200);
    expect(legacy.json().data[0]).toMatchObject({ actorType: 'SUPERADMIN', actorId: null, user: null, ipAddress: null, userAgent: null });
    for (const secret of [staffUserId, 'staff@qrauth.audit.test', '198.51.100.7', 'StaffBrowser']) expect(legacy.body).not.toContain(secret);
    expect((await call('A', 'GET', `/api/v1/organizations/${orgs.A.id}/audit-logs?userId=${staffUserId}`)).json().data).toEqual([]);
  });
});

describe('GET /api/v1/audit', () => {
  beforeEach(() => reset());

  it('returns only the caller organization (tenant isolation)', async () => {
    await logRow('A', new Date());
    const codeB = await makeCode('B', 'b1');
    await revision('B', codeB.id, 1, new Date());
    await logRow('B', new Date());
    const page = (await audit('A')).json();
    expect(page.data).toHaveLength(1);
    expect(page.data[0].source).toBe('audit');
    // Another organization's resource id finds nothing.
    expect((await audit('A', `?resourceId=${codeB.id}`)).json().data).toEqual([]);
  });

  it('is for OWNER and ADMIN only, with an explanation', async () => {
    for (const role of ['OWNER', 'ADMIN'] as const) expect((await audit('A', '', { role })).statusCode).toBe(200);
    for (const role of ['MANAGER', 'MEMBER', 'VIEWER'] as const) {
      const res = await audit('A', '', { role });
      expect(res.statusCode).toBe(403);
      expect(res.json()).toMatchObject({ code: 'audit-role-required' });
    }
    expect((await call('A', 'GET', `/api/v1/audit/export.csv?${RANGE}`, undefined, { role: 'MEMBER' })).statusCode).toBe(403);
  });

  it('needs the Business plan or above (403 with explanation)', async () => {
    for (const plan of ['FREE', 'PRO'] as const) {
      await reset(plan);
      const res = await audit('A');
      expect(res.statusCode).toBe(403);
      expect(res.json()).toMatchObject({ code: 'governance-plan-required', message: expect.stringContaining('Business plan') });
      expect((await call('A', 'GET', `/api/v1/audit/export.csv?${RANGE}`)).statusCode).toBe(403);
    }
    for (const plan of ['BUSINESS', 'ENTERPRISE'] as const) {
      await reset(plan);
      expect((await audit('A')).statusCode).toBe(200);
    }
  });

  it('merges audit entries and QR revisions newest first, across pages, without gaps or repeats', async () => {
    const code = await makeCode('A', 'm1');
    const t = (s: number) => new Date(Date.UTC(2026, 10, 1, 12, 0, s));
    // Interleaved, with two rows of each source in the same millisecond.
    await revision('A', code.id, 1, t(1));
    await logRow('A', t(2));
    await revision('A', code.id, 2, t(3));
    await logRow('A', t(3));
    await logRow('A', t(3));
    await revision('A', code.id, 3, t(3));
    await logRow('A', t(5));
    const all = (await audit('A', '?limit=100')).json().data as Array<{ id: string; createdAt: string; source: string }>;
    expect(all).toHaveLength(7);
    const order = all.map((e) => [e.createdAt, e.id] as const);
    const sorted = [...order].sort((a, b) => (a[0] === b[0] ? (a[1] < b[1] ? 1 : -1) : a[0] < b[0] ? 1 : -1));
    expect(order).toEqual(sorted);
    expect(all[0].createdAt).toBe(t(5).toISOString());
    expect(all.at(-1)!.source).toBe('qr_revision');

    for (const limit of [1, 2, 3]) {
      const seen: string[] = [];
      let cursor: string | null = null;
      do {
        const page = (await audit('A', `?limit=${limit}${cursor ? `&cursor=${cursor}` : ''}`)).json();
        seen.push(...page.data.map((e: { id: string }) => e.id));
        cursor = page.nextCursor;
      } while (cursor);
      expect(seen).toEqual(all.map((e) => e.id));
    }
  });

  it('QR events carry the diff and the code token; filters narrow by source', async () => {
    const code = await makeCode('A', 'diff1');
    await revision('A', code.id, 1, new Date(Date.now() - 1000));
    await revision('A', code.id, 2, new Date(), { changes: { destinationUrl: { before: 'https://v1.example.test/', after: 'https://v2.example.test/' } } });
    await logRow('A', new Date());
    const qrOnly = (await audit('A', '?action=qr.updated')).json().data;
    expect(qrOnly).toHaveLength(1);
    expect(qrOnly[0]).toMatchObject({
      action: 'qr.updated', label: 'QR code updated', resourceType: 'QRCode', resourceId: code.id, resourceName: 'diff1',
      changes: { destinationUrl: { before: 'https://v1.example.test/', after: 'https://v2.example.test/' } },
      actor: { type: 'USER', id: orgs.A.userId, name: 'Owner A' },
    });
    expect((await audit('A', '?resourceType=QRCode')).json().data).toHaveLength(2);
    expect((await audit('A', '?resourceType=Membership')).json().data).toHaveLength(1);
    expect((await audit('A', '?actorType=API_KEY')).json().data).toEqual([]);
    expect((await audit('A', `?actor=${orgs.A.userId}`)).json().data).toHaveLength(3);
    const since = new Date(Date.now() - 500).toISOString();
    expect((await audit('A', `?from=${encodeURIComponent(since)}&resourceType=QRCode`)).json().data).toHaveLength(1);
  });

  it('rejects a malformed cursor and an inverted date range', async () => {
    expect((await audit('A', '?cursor=not-a-cursor')).statusCode).toBe(400);
    const from = new Date().toISOString();
    const to = new Date(Date.now() - DAY).toISOString();
    expect((await audit('A', `?from=${from}&to=${to}`)).statusCode).toBe(400);
  });

  it('the export needs a date range and refuses more than 100,000 entries', async () => {
    expect((await call('A', 'GET', '/api/v1/audit/export.csv')).statusCode).toBe(400);
    expect((await call('A', 'GET', `/api/v1/audit/export.csv?from=${encodeURIComponent(new Date().toISOString())}`)).statusCode).toBe(400);
    await db.$executeRawUnsafe(`
      INSERT INTO "audit_logs" ("id", "organizationId", "actorType", "actorId", "action", "resource", "resourceId", "createdAt")
      SELECT 'bulk' || g, '${orgs.A.id}', 'SYSTEM', 'test', 'tag.create', 'Tag', 't' || g, now() - (g || ' milliseconds')::interval
      FROM generate_series(1, 100001) g`);
    const res = await call('A', 'GET', `/api/v1/audit/export.csv?${RANGE}`);
    expect(res.statusCode).toBe(422);
    expect(res.json()).toMatchObject({ code: 'audit-export-too-large', rows: 100001, maxRows: 100000, message: expect.stringContaining('shorter date range') });
    // A narrower range fits.
    const narrow = `from=${encodeURIComponent(new Date(Date.now() - 1000).toISOString())}&to=${encodeURIComponent(new Date(Date.now() + 1000).toISOString())}`;
    expect((await call('A', 'GET', `/api/v1/audit/export.csv?${narrow}`)).statusCode).toBe(200);
  });

  it('exports CSV with formula cells neutralised', async () => {
    await logRow('A', new Date(), { userAgent: '=HYPERLINK("https://evil.example","x")', metadata: { note: '+1' } });
    await db.user.update({ where: { id: orgs.A.userId }, data: { email: '@sum(owner)@a.audit.test' } });
    const res = await call('A', 'GET', `/api/v1/audit/export.csv?${RANGE}`);
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('text/csv');
    expect(res.headers['content-disposition']).toMatch(/attachment; filename="qrauth-audit-log-\d{4}-\d{2}-\d{2}\.csv"/);
    const [header, line] = res.body.split('\r\n');
    expect(header).toBe('time,action,description,actor_type,actor_id,actor,resource_type,resource_id,resource_name,request_id,ip_address,user_agent,details');
    expect(line).toContain(`"'=HYPERLINK(""https://evil.example"",""x"")"`);
    expect(line).toContain("'@sum(owner)@a.audit.test");
    expect(line).not.toMatch(/,=|,@|,\+/);
  });
});
