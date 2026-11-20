/**
 * API key owners (ADR-0008 D8) against a real Postgres, through the real
 * auth middleware (signed JWTs and X-API-Key headers) and the real API-key,
 * organization and policy routes: a new key records the member who created
 * it and its chosen role, acts with the lower of its role and that member's
 * current role, and is refused once they leave; legacy keys (no owner) are
 * unchanged; rotation replaces a key with one owned by the rotating member.
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

const noQueue = vi.hoisted(() => ({ add: async () => undefined }));
vi.mock('../../src/lib/queue.js', () => ({
  scanQueue: noQueue, fraudQueue: noQueue, alertQueue: noQueue, webhookQueue: noQueue,
  cleanupQueue: noQueue, analyticsQueue: noQueue, webRiskQueue: noQueue,
  createQueueConnection: vi.fn(), closeQueues: vi.fn(async () => undefined),
}));
vi.mock('../../src/lib/cache.js', () => ({
  cacheGet: vi.fn(async () => null),
  cacheSet: vi.fn(async () => undefined),
  cacheDel: vi.fn(async () => undefined),
}));
vi.mock('../../src/lib/email.js', async (importOriginal) => ({
  ...(await importOriginal<object>()),
  sendApiKeyCreatedEmail: vi.fn(async () => undefined),
  sendApiKeyRevokedEmail: vi.fn(async () => undefined),
}));

const db = new PrismaClient({ datasources: { db: { url } } });
let app: FastifyInstance;

const ROLES = ['OWNER', 'ADMIN', 'MANAGER', 'MEMBER'] as const;
type Role = (typeof ROLES)[number];
type Org = { id: string; users: Record<Role, string> };
const orgs: Record<'A' | 'B', Org> = {} as never;

function bearer(org: 'A' | 'B', as: Role, jwtRole: Role = as): Record<string, string> {
  const o = orgs[org];
  return { authorization: `Bearer ${app.jwt.sign({ userId: o.users[as], orgId: o.id, role: jwtRole, email: `${as.toLowerCase()}@owner.test` })}` };
}

const withKey = (key: string): Record<string, string> => ({ 'x-api-key': key });

function call(method: 'GET' | 'POST' | 'DELETE', path: string, headers: Record<string, string>, body?: unknown) {
  return app.inject({
    method,
    url: path,
    headers: { ...headers, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
    ...(body === undefined ? {} : { payload: JSON.stringify(body) }),
  });
}

/** OWNER/ADMIN-only: answers 200 to an ADMIN-level key, 403 below it, 401 to a refused key. */
const probe = (key: string) => call('GET', '/api/v1/policies', withKey(key));

const membership = (org: 'A' | 'B', role: Role) => ({ userId_organizationId: { userId: orgs[org].users[role], organizationId: orgs[org].id } });

/** A key created before owners were recorded: no creator, stored role as given. */
async function legacyKey(org: 'A' | 'B', role: Role = 'MEMBER', label = 'Legacy integration'): Promise<{ id: string; key: string }> {
  const { generateApiKey } = await import('../../src/lib/crypto.js');
  const { fullKey, prefix, hash } = generateApiKey();
  const row = await db.apiKey.create({ data: { organizationId: orgs[org].id, keyHash: hash, prefix, label, role } });
  return { id: row.id, key: fullKey };
}

async function reset(): Promise<void> {
  await db.$executeRawUnsafe('TRUNCATE "organizations", "users" CASCADE');
  for (const name of ['A', 'B'] as const) {
    const o = await db.organization.create({ data: { name: `Org ${name}`, slug: `org-${name.toLowerCase()}-owner-test`, email: `${name}@owner.test`, plan: 'BUSINESS' } });
    const users = {} as Record<Role, string>;
    for (const role of ROLES) {
      const u = await db.user.create({ data: { name: `${role} ${name}`, email: `${role.toLowerCase()}-${name.toLowerCase()}@owner.test`, passwordHash: 'x', emailVerified: true } });
      await db.membership.create({ data: { userId: u.id, organizationId: o.id, role } });
      users[role] = u.id;
    }
    orgs[name] = { id: o.id, users };
  }
}

beforeAll(async () => {
  app = Fastify({ genReqId: () => `req-${Math.random().toString(36).slice(2, 10)}` });
  app.decorate('prisma', db as never);
  app.decorate('signingService', {} as never);
  const { authMiddleware } = await import('../../src/middleware/auth.js');
  await app.register(authMiddleware);
  const { default: apiKeyRoutes } = await import('../../src/routes/api-keys.js');
  const { default: organizationRoutes } = await import('../../src/routes/organizations.js');
  const { default: policyRoutes } = await import('../../src/routes/org-policies.js');
  await app.register(apiKeyRoutes, { prefix: '/api/v1/api-keys' });
  await app.register(organizationRoutes, { prefix: '/api/v1/organizations' });
  await app.register(policyRoutes, { prefix: '/api/v1/policies' });
  await app.ready();
});

afterAll(async () => {
  await app.close();
  await db.$disconnect();
});

beforeEach(reset);

// ---------------------------------------------------------------------------

describe('a new key records its creator', () => {
  it('POST /api/v1/api-keys stores the creator and the chosen role; apiKey.create names the creator', async () => {
    const res = await call('POST', '/api/v1/api-keys', bearer('A', 'ADMIN'), { label: 'Print shop', role: 'MANAGER' });
    expect(res.statusCode).toBe(201);
    expect(res.json()).toMatchObject({ role: 'MANAGER', createdByUserId: orgs.A.users.ADMIN, label: 'Print shop' });
    const row = await db.apiKey.findUniqueOrThrow({ where: { id: res.json().id } });
    expect(row).toMatchObject({ createdByUserId: orgs.A.users.ADMIN, role: 'MANAGER', source: null });
    const entry = await db.auditLog.findFirstOrThrow({ where: { action: 'apiKey.create' } });
    expect(entry).toMatchObject({ actorType: 'USER', actorId: orgs.A.users.ADMIN, resourceId: row.id });
    expect(entry.metadata).toMatchObject({ createdByUserId: orgs.A.users.ADMIN, role: 'MANAGER', prefix: row.prefix });
  });

  it('the role defaults to MEMBER; OWNER is not offered; an empty label is no label', async () => {
    const res = await call('POST', '/api/v1/api-keys', bearer('A', 'OWNER'), { label: '' });
    expect(res.json()).toMatchObject({ role: 'MEMBER', label: null, createdByUserId: orgs.A.users.OWNER });
    expect((await call('POST', '/api/v1/api-keys', bearer('A', 'OWNER'), { role: 'OWNER' })).statusCode).toBe(400);
  });

  it('the organization endpoint records the creator too', async () => {
    const res = await call('POST', `/api/v1/organizations/${orgs.A.id}/api-keys`, bearer('A', 'OWNER'), { role: 'ADMIN' });
    expect(res.statusCode).toBe(201);
    expect(res.json()).toMatchObject({ role: 'ADMIN', createdByUserId: orgs.A.users.OWNER });
    const list = await call('GET', `/api/v1/organizations/${orgs.A.id}/api-keys`, bearer('A', 'OWNER'));
    expect(list.json().data[0]).toMatchObject({ createdByUserId: orgs.A.users.OWNER, role: 'ADMIN' });
    expect((await db.auditLog.findFirstOrThrow({ where: { action: 'apiKey.create' } })).metadata).toMatchObject({ createdByUserId: orgs.A.users.OWNER });
  });

  it('the creator is read from the membership, not the session: a demoted admin cannot create keys', async () => {
    await db.membership.update({ where: membership('A', 'ADMIN'), data: { role: 'MANAGER' } });
    const res = await call('POST', '/api/v1/api-keys', bearer('A', 'ADMIN'), { role: 'MANAGER' });
    expect(res.statusCode).toBe(403);
    expect(res.json().code).toBe('api-key-role-too-high');
    expect(await db.apiKey.count()).toBe(0);
  });

  it('a key created with an owned API key belongs to that key’s owner; a legacy key cannot create keys', async () => {
    const owned = (await call('POST', '/api/v1/api-keys', bearer('A', 'ADMIN'), { role: 'ADMIN' })).json().key as string;
    const child = await call('POST', '/api/v1/api-keys', withKey(owned), { role: 'MANAGER' });
    expect(child.statusCode).toBe(201);
    expect(child.json().createdByUserId).toBe(orgs.A.users.ADMIN);

    const legacy = await legacyKey('A', 'ADMIN');
    const refused = await call('POST', '/api/v1/api-keys', withKey(legacy.key), {});
    expect(refused.statusCode).toBe(403);
    expect(refused.json().code).toBe('api-key-owner-required');
  });
});

describe('an owned key follows its creator', () => {
  it('acts with the lower of its role and the creator’s current role, per request', async () => {
    const key = (await call('POST', '/api/v1/api-keys', bearer('A', 'ADMIN'), { role: 'ADMIN' })).json().key as string;
    expect((await probe(key)).statusCode).toBe(200);
    await db.membership.update({ where: membership('A', 'ADMIN'), data: { role: 'MANAGER' } });
    expect((await probe(key)).statusCode).toBe(403);
    await db.membership.update({ where: membership('A', 'ADMIN'), data: { role: 'ADMIN' } });
    expect((await probe(key)).statusCode).toBe(200);
  });

  it('is refused once the creator leaves the organization', async () => {
    const key = (await call('POST', '/api/v1/api-keys', bearer('A', 'ADMIN'), { role: 'ADMIN' })).json().key as string;
    await db.membership.delete({ where: membership('A', 'ADMIN') });
    const res = await probe(key);
    expect(res.statusCode).toBe(401);
    const list = (await call('GET', '/api/v1/api-keys', bearer('A', 'OWNER'))).json().data;
    expect(list[0].owner).toEqual({ id: orgs.A.users.ADMIN, name: 'ADMIN A', email: 'admin-a@owner.test', isMember: false });
  });
});

describe('legacy keys are unchanged', () => {
  it('keep their stored role and keep working whoever leaves; the list shows no owner', async () => {
    const legacy = await legacyKey('A', 'ADMIN');
    expect((await probe(legacy.key)).statusCode).toBe(200);
    await db.membership.delete({ where: membership('A', 'ADMIN') });
    await db.membership.delete({ where: membership('A', 'MANAGER') });
    expect((await probe(legacy.key)).statusCode).toBe(200);
    expect(await db.apiKey.findUniqueOrThrow({ where: { id: legacy.id } })).toMatchObject({ createdByUserId: null, role: 'ADMIN', revokedAt: null });
    const list = (await call('GET', '/api/v1/api-keys', bearer('A', 'OWNER'))).json().data;
    expect(list).toEqual([expect.objectContaining({ id: legacy.id, owner: null, createdByUserId: null })]);
  });
});

describe('rotation', () => {
  it('replaces a legacy key with one owned by the rotating member; the old key stops working at once', async () => {
    const legacy = await legacyKey('A', 'MEMBER', 'Print shop');
    const res = await call('POST', `/api/v1/api-keys/${legacy.id}/rotate`, bearer('A', 'ADMIN'));
    expect(res.statusCode).toBe(201);
    const body = res.json();
    expect(body).toMatchObject({ label: 'Print shop', role: 'MEMBER', createdByUserId: orgs.A.users.ADMIN, rotatedFrom: legacy.id });
    expect((await probe(legacy.key)).statusCode).toBe(401);
    expect((await probe(body.key)).statusCode).toBe(403); // MEMBER: authenticated, below ADMIN
    expect(await db.apiKey.findUniqueOrThrow({ where: { id: legacy.id } })).toMatchObject({ revokedAt: expect.any(Date) });

    const entries = await db.auditLog.findMany({ where: { organizationId: orgs.A.id } });
    expect(entries.map((e) => e.action)).toEqual(['apiKey.rotate']);
    expect(entries[0]).toMatchObject({ actorId: orgs.A.users.ADMIN, resourceId: body.id });
    expect(entries[0].metadata).toMatchObject({
      createdByUserId: orgs.A.users.ADMIN,
      role: 'MEMBER',
      previous: { id: legacy.id, createdByUserId: null, role: 'MEMBER' },
    });
    expect((await call('POST', `/api/v1/api-keys/${legacy.id}/rotate`, bearer('A', 'ADMIN'))).statusCode).toBe(404);
  });

  it('can set the new key’s role up to the rotator’s, and caps a kept role at it', async () => {
    const legacy = await legacyKey('A', 'MEMBER');
    const raised = await call('POST', `/api/v1/api-keys/${legacy.id}/rotate`, bearer('A', 'ADMIN'), { role: 'ADMIN' });
    expect(raised.json()).toMatchObject({ role: 'ADMIN', createdByUserId: orgs.A.users.ADMIN });
    expect((await probe(raised.json().key)).statusCode).toBe(200);

    const ownerLevel = await legacyKey('A', 'OWNER');
    const capped = await call('POST', `/api/v1/api-keys/${ownerLevel.id}/rotate`, bearer('A', 'ADMIN'));
    expect(capped.json().role).toBe('ADMIN');
  });

  it('a refused rotation changes nothing; another organization’s key is 404; MANAGER cannot rotate', async () => {
    const legacy = await legacyKey('A');
    await db.membership.update({ where: membership('A', 'ADMIN'), data: { role: 'MANAGER' } });
    expect((await call('POST', `/api/v1/api-keys/${legacy.id}/rotate`, bearer('A', 'ADMIN'))).statusCode).toBe(403);
    expect((await probe(legacy.key)).statusCode).toBe(403); // still active (MEMBER)
    expect((await call('POST', `/api/v1/api-keys/${legacy.id}/rotate`, bearer('B', 'OWNER'))).statusCode).toBe(404);
    expect((await call('POST', `/api/v1/api-keys/${legacy.id}/rotate`, bearer('A', 'MANAGER'))).statusCode).toBe(403);
    expect(await db.apiKey.count({ where: { revokedAt: null } })).toBe(1);
    expect(await db.auditLog.count()).toBe(0);
  });
});
