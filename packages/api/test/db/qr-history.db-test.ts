/**
 * QR code edit history (Milestone 1) against a real Postgres, through the
 * real routes: revisions written with each change (user and API-key
 * actors, request id), the history endpoint, "Restore this destination"
 * under today's rules, tenant isolation, the append-only trigger and the
 * 730-day retention. Signing, MAC, domain checks and Web Risk are stubbed;
 * everything else is real. Run by scripts/ci-verify.sh `db`.
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
  // Lets a test hold a screening call open (URLs containing "slow").
  gate: { wait: Promise.resolve() as Promise<void>, entered: () => {} },
  // Web Risk: URLs containing "malware" are flagged, the rest are clean.
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
vi.mock('../../src/services/domain.js', () => ({
  DomainService: class {
    async checkUrlAgainstVerifiedDomains() {
      return { isSuspicious: false, warnings: [] };
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

type Role = 'OWNER' | 'ADMIN' | 'MANAGER' | 'MEMBER' | 'VIEWER';
type Org = { id: string; keyId: string; userId: string; apiKeyId: string };
const orgs: Record<'A' | 'B', Org> = {} as never;

function call(
  org: 'A' | 'B',
  method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
  path: string,
  body?: unknown,
  opts: { role?: Role; viaApiKey?: boolean } = {},
) {
  const o = orgs[org];
  const user = opts.viaApiKey
    ? { id: 'api-key', orgId: o.id, role: opts.role ?? 'MEMBER', email: '', apiKeyId: o.apiKeyId }
    : { id: o.userId, orgId: o.id, role: opts.role ?? 'OWNER', email: 'u@history.test' };
  return app.inject({
    method,
    url: path,
    headers: {
      'x-test-user': JSON.stringify(user),
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    ...(body === undefined ? {} : { payload: JSON.stringify(body) }),
  });
}

/** A code with its revision 1, as the create route writes it. */
async function makeCode(org: 'A' | 'B', token: string, extra: Record<string, unknown> = {}) {
  const { recordCreated, systemContext } = await import('../../src/services/qr-revisions.js');
  return db.$transaction(async (tx) => {
    const row = await tx.qRCode.create({
      data: {
        token,
        organizationId: orgs[org].id,
        signingKeyId: orgs[org].keyId,
        destinationUrl: 'https://one.example.test/',
        signature: 'sig',
        algVersion: 'test',
        ...extra,
      },
    });
    await recordCreated(tx, row, systemContext('test'));
    return row;
  });
}

const history = async (org: 'A' | 'B', token: string, qs = '') => (await call(org, 'GET', `/api/v1/qrcodes/${token}/history${qs}`, undefined, { role: 'VIEWER' })).json();

async function reset(): Promise<void> {
  await db.$executeRawUnsafe('TRUNCATE "organizations", "users" CASCADE');
  for (const org of ['A', 'B'] as const) {
    const o = await db.organization.create({ data: { name: `Org ${org}`, slug: `org-${org.toLowerCase()}-history-test`, email: `${org}@history.test` } });
    const key = await db.signingKey.create({ data: { organizationId: o.id, publicKey: 'pk', keyId: `key-${org}-${o.id}` } });
    const user = await db.user.create({ data: { name: `Owner ${org}`, email: `owner-${org.toLowerCase()}@history.test`, passwordHash: 'x', emailVerified: true } });
    await db.membership.create({ data: { userId: user.id, organizationId: o.id, role: 'OWNER' } });
    const apiKey = await db.apiKey.create({ data: { organizationId: o.id, keyHash: `hash-${o.id}`, prefix: 'qrauth_ab12', label: `CI key ${org}` } });
    orgs[org] = { id: o.id, keyId: key.id, userId: user.id, apiKeyId: apiKey.id };
  }
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
  await app.register(qrcodeRoutes, { prefix: '/api/v1/qrcodes' });
  await app.ready();
});

afterAll(async () => {
  await app.close();
  await db.$disconnect();
});

// ---------------------------------------------------------------------------

describe('revisions are written with each change', () => {
  beforeEach(reset);

  it('PATCH by a user: one UPDATED revision with before/after of the changed tracked fields, actor and request id', async () => {
    await makeCode('A', 'c1');
    const res = await call('A', 'PATCH', '/api/v1/qrcodes/c1', {
      destinationUrl: 'https://two.example.test/',
      scanMode: 'PAGE',
      label: 'labels are not tracked',
    });
    expect(res.statusCode).toBe(200);

    const { data, total } = await history('A', 'c1');
    expect(total).toBe(2);
    expect(data[0]).toMatchObject({
      revision: 2,
      kind: 'UPDATED',
      changes: {
        destinationUrl: { before: 'https://one.example.test/', after: 'https://two.example.test/' },
        scanMode: { before: 'FLASH', after: 'PAGE' },
      },
      actor: { type: 'USER', id: orgs.A.userId, name: 'Owner A', email: 'owner-a@history.test' },
    });
    expect(Object.keys(data[0].changes).sort()).toEqual(['destinationUrl', 'scanMode']);
    expect(data[0].requestId).toMatch(/^req-/);
    expect(data[1]).toMatchObject({ revision: 1, kind: 'CREATED' });
  });

  it('PATCH through an API key records the key as the actor, with its label and prefix', async () => {
    await makeCode('A', 'c1');
    const res = await call('A', 'PATCH', '/api/v1/qrcodes/c1', { expiresAt: '2030-01-01T00:00:00.000Z' }, { viaApiKey: true });
    expect(res.statusCode).toBe(200);
    const row = await db.qRCodeRevision.findFirstOrThrow({ where: { revision: 2 } });
    expect(row).toMatchObject({ actorType: 'API_KEY', actorApiKeyId: orgs.A.apiKeyId, actorUserId: null });
    const { data } = await history('A', 'c1');
    expect(data[0]).toMatchObject({
      changes: { expiresAt: { before: null, after: '2030-01-01T00:00:00.000Z' } },
      actor: { type: 'API_KEY', id: orgs.A.apiKeyId, label: 'CI key A', prefix: 'qrauth_ab12' },
    });
  });

  it('a change to untracked fields only writes no revision', async () => {
    await makeCode('A', 'c1');
    expect((await call('A', 'PATCH', '/api/v1/qrcodes/c1', { label: 'renamed', maxScans: 5 })).statusCode).toBe(200);
    expect(await db.qRCodeRevision.count()).toBe(1);
  });

  it('revoke and bulk revoke write REVOKED revisions; the code row and its revision commit together', async () => {
    await makeCode('A', 'c1');
    await makeCode('A', 'c2');
    await makeCode('A', 'c3');
    expect((await call('A', 'DELETE', '/api/v1/qrcodes/c1')).statusCode).toBe(204);
    const bulk = await call('A', 'POST', '/api/v1/qrcodes/bulk-revoke', { tokens: ['c1', 'c2', 'c3'] }, { viaApiKey: true, role: 'ADMIN' });
    expect(bulk.statusCode).toBe(207);

    const revoked = await db.qRCodeRevision.findMany({ where: { kind: 'REVOKED' }, include: { qrCode: true }, orderBy: { qrCode: { token: 'asc' } } });
    expect(revoked.map((r) => [r.qrCode.token, r.revision, r.actorType])).toEqual([
      ['c1', 2, 'USER'],
      ['c2', 2, 'API_KEY'],
      ['c3', 2, 'API_KEY'],
    ]);
    expect(revoked.every((r) => (r.changes as { status: unknown }).status !== undefined)).toBe(true);
    expect(await db.qRCode.count({ where: { status: 'REVOKED' } })).toBe(3);
  });

  it('concurrent PATCHes get distinct, gapless revision numbers', async () => {
    await makeCode('A', 'c1');
    const results = await Promise.all(
      Array.from({ length: 6 }, (_, i) => call('A', 'PATCH', '/api/v1/qrcodes/c1', { destinationUrl: `https://p${i}.example.test/` })),
    );
    expect(results.every((r) => r.statusCode === 200)).toBe(true);
    const revisions = (await db.qRCodeRevision.findMany({ orderBy: { revision: 'asc' } })).map((r) => r.revision);
    expect(revisions).toEqual([1, 2, 3, 4, 5, 6, 7]);
  });

  it('a refused change (Web Risk) writes neither the code nor a revision', async () => {
    await makeCode('A', 'c1');
    const res = await call('A', 'PATCH', '/api/v1/qrcodes/c1', { destinationUrl: 'https://malware.example.test/' });
    expect(res.statusCode).toBe(422);
    expect(await db.qRCodeRevision.count()).toBe(1);
    expect((await db.qRCode.findUniqueOrThrow({ where: { token: 'c1' } })).destinationUrl).toBe('https://one.example.test/');
  });
});

// ---------------------------------------------------------------------------

describe('restore this destination', () => {
  beforeEach(async () => {
    await reset();
    await makeCode('A', 'c1');
    await call('A', 'PATCH', '/api/v1/qrcodes/c1', { destinationUrl: 'https://two.example.test/' });
    await call('A', 'PATCH', '/api/v1/qrcodes/c1', { scanMode: 'PAGE' });
    await call('A', 'PATCH', '/api/v1/qrcodes/c1', { destinationUrl: 'https://three.example.test/' });
  });

  it('restores the destination as it was after that revision, re-signs, and records RESTORED with restoredFrom', async () => {
    const before = await db.qRCode.findUniqueOrThrow({ where: { token: 'c1' } });
    // Revision 3 changed only scanMode; the destination then was the one set at revision 2.
    const res = await call('A', 'POST', '/api/v1/qrcodes/c1/history/3/restore', undefined, { role: 'MANAGER' });
    expect(res.statusCode).toBe(200);

    const after = await db.qRCode.findUniqueOrThrow({ where: { token: 'c1' } });
    expect(after.destinationUrl).toBe('https://two.example.test/');
    expect(after.signature).not.toBe(before.signature);
    expect(after.scanMode).toBe('PAGE'); // only the destination is restored

    const { data } = await history('A', 'c1');
    expect(data[0]).toMatchObject({
      revision: 5,
      kind: 'RESTORED',
      restoredFrom: 3,
      changes: { destinationUrl: { before: 'https://three.example.test/', after: 'https://two.example.test/' } },
    });
  });

  it('is MANAGER and above: MEMBER and VIEWER are 403 and nothing changes', async () => {
    for (const role of ['MEMBER', 'VIEWER'] as const) {
      expect((await call('A', 'POST', '/api/v1/qrcodes/c1/history/1/restore', undefined, { role })).statusCode).toBe(403);
    }
    expect(await db.qRCodeRevision.count()).toBe(4);
  });

  it('refuses the current destination, a missing revision and a revoked code', async () => {
    const same = await call('A', 'POST', '/api/v1/qrcodes/c1/history/4/restore');
    expect(same.statusCode).toBe(409);
    expect(same.json().code).toBe('already-current');
    expect((await call('A', 'POST', '/api/v1/qrcodes/c1/history/99/restore')).statusCode).toBe(404);
    await call('A', 'DELETE', '/api/v1/qrcodes/c1');
    const revoked = await call('A', 'POST', '/api/v1/qrcodes/c1/history/1/restore');
    expect(revoked.statusCode).toBe(409);
    expect(revoked.json().code).toBe('revoked');
  });

  it('a code revoked while the restore was being checked is not changed (409 revoked)', async () => {
    await makeCode('A', 'r1', { destinationUrl: 'https://slow.example.test/' });
    await call('A', 'PATCH', '/api/v1/qrcodes/r1', { destinationUrl: 'https://now.example.test/' });

    let release!: () => void;
    let entered!: () => void;
    const inScreening = new Promise<void>((resolve) => { entered = resolve; });
    stubs.gate = { wait: new Promise<void>((resolve) => { release = resolve; }), entered };
    const restoring = call('A', 'POST', '/api/v1/qrcodes/r1/history/1/restore');
    await inScreening; // the restore has read the code and is past its own revoked check
    expect((await call('A', 'DELETE', '/api/v1/qrcodes/r1')).statusCode).toBe(204);
    release();

    const res = await restoring;
    stubs.gate = { wait: Promise.resolve(), entered: () => {} };
    expect(res.statusCode).toBe(409);
    expect(res.json().code).toBe('revoked');
    const row = await db.qRCode.findUniqueOrThrow({ where: { token: 'r1' } });
    expect(row).toMatchObject({ status: 'REVOKED', destinationUrl: 'https://now.example.test/' });
    expect((await db.qRCodeRevision.findMany({ where: { qrCodeId: row.id } })).map((r) => r.kind)).toEqual(['CREATED', 'UPDATED', 'REVOKED']);
  });

  it('applies today\'s rules: a destination now flagged by Web Risk is refused', async () => {
    // Revision 1 of this code pointed at a URL that has since been listed.
    await makeCode('A', 'c2', { destinationUrl: 'https://malware.example.test/old' });
    await call('A', 'PATCH', '/api/v1/qrcodes/c2', { destinationUrl: 'https://safe.example.test/' });
    const res = await call('A', 'POST', '/api/v1/qrcodes/c2/history/1/restore');
    expect(res.statusCode).toBe(422);
    expect((await db.qRCode.findUniqueOrThrow({ where: { token: 'c2' } })).destinationUrl).toBe('https://safe.example.test/');
  });

  it('applies today\'s rules: a destination that is no longer an allowed URL is refused', async () => {
    // A row from before the http(s)-only rule.
    await makeCode('A', 'c3', { destinationUrl: 'ftp://files.example.test/menu.pdf' });
    await call('A', 'PATCH', '/api/v1/qrcodes/c3', { destinationUrl: 'https://files.example.test/menu.pdf' });
    const res = await call('A', 'POST', '/api/v1/qrcodes/c3/history/1/restore');
    expect(res.statusCode).toBe(422);
    expect(res.json().code).toBe('restore-not-allowed');
  });

  it('applies today\'s rules: a destination on a private host is refused', async () => {
    // A row from before the public-host rule.
    await makeCode('A', 'c4', { destinationUrl: 'https://192.168.1.10/menu' });
    await call('A', 'PATCH', '/api/v1/qrcodes/c4', { destinationUrl: 'https://menu.example.test/' });
    const res = await call('A', 'POST', '/api/v1/qrcodes/c4/history/1/restore');
    expect(res.statusCode).toBe(422);
    expect(res.json()).toMatchObject({ code: 'restore-not-allowed', message: expect.stringContaining('public host name') });
    expect((await db.qRCode.findUniqueOrThrow({ where: { token: 'c4' } })).destinationUrl).toBe('https://menu.example.test/');
  });

  it('restores the content of a non-URL code, validated against its content type', async () => {
    const v1 = { firstName: 'Cafe', phone: '+30 210 0000000' };
    await makeCode('A', 'v1', { contentType: 'vcard', content: v1, destinationUrl: 'https://qrauth.test/v/v1' });
    const patched = await call('A', 'PATCH', '/api/v1/qrcodes/v1', { content: { firstName: 'Cafe Two', phone: '+30 210 1111111' } });
    expect(patched.statusCode).toBe(200);
    const res = await call('A', 'POST', '/api/v1/qrcodes/v1/history/1/restore');
    expect(res.statusCode).toBe(200);
    expect((await db.qRCode.findUniqueOrThrow({ where: { token: 'v1' } })).content).toEqual(v1);
    const { data } = await history('A', 'v1');
    expect(data[0]).toMatchObject({ kind: 'RESTORED', restoredFrom: 1, changes: { content: { after: v1 } } });
  });

  it('refuses restoring content that no longer passes its content type schema', async () => {
    // Stored before today's schema: no firstName.
    await makeCode('A', 'v2', { contentType: 'vcard', content: { lastName: 'Old' }, destinationUrl: 'https://qrauth.test/v/v2' });
    await call('A', 'PATCH', '/api/v1/qrcodes/v2', { content: { firstName: 'New' } });
    const res = await call('A', 'POST', '/api/v1/qrcodes/v2/history/1/restore');
    expect(res.statusCode).toBe(422);
    expect(res.json().code).toBe('restore-not-allowed');
    expect((await db.qRCode.findUniqueOrThrow({ where: { token: 'v2' } })).content).toEqual({ firstName: 'New' });
  });
});

// ---------------------------------------------------------------------------

describe('tenant isolation', () => {
  beforeEach(async () => {
    await reset();
    await makeCode('B', 'b1');
    await call('B', 'PATCH', '/api/v1/qrcodes/b1', { destinationUrl: 'https://b-two.example.test/' });
  });

  it('another org\'s code is 404 on history and restore, and its history is untouched', async () => {
    expect((await call('A', 'GET', '/api/v1/qrcodes/b1/history')).statusCode).toBe(404);
    expect((await call('A', 'POST', '/api/v1/qrcodes/b1/history/1/restore')).statusCode).toBe(404);
    expect(await db.qRCodeRevision.count({ where: { organizationId: orgs.B.id } })).toBe(2);
    expect(await db.qRCodeRevision.count({ where: { organizationId: orgs.A.id } })).toBe(0);
  });

  it('API-key actors are only resolved within the code\'s org', async () => {
    // A revision naming org A's key on org B's code (as if forged) shows no label.
    const code = await db.qRCode.findUniqueOrThrow({ where: { token: 'b1' } });
    await db.qRCodeRevision.create({
      data: { qrCodeId: code.id, organizationId: orgs.B.id, revision: 3, kind: 'UPDATED', changes: {}, actorType: 'API_KEY', actorApiKeyId: orgs.A.apiKeyId },
    });
    const { data } = await history('B', 'b1');
    expect(data[0].actor).toEqual({ type: 'API_KEY', id: orgs.A.apiKeyId, label: null, prefix: null });
  });
});

// ---------------------------------------------------------------------------

describe('append-only and retention', () => {
  beforeEach(async () => {
    await reset();
    await makeCode('A', 'c1');
  });

  it('refuses UPDATE and early DELETE of a revision', async () => {
    await expect(db.$executeRawUnsafe(`UPDATE "qr_code_revisions" SET "kind" = 'X'`)).rejects.toThrow(/append-only/);
    await expect(db.qRCodeRevision.deleteMany({})).rejects.toThrow(/append-only/);
    expect(await db.qRCodeRevision.count()).toBe(1);
  });

  it('the cleanup purge removes revisions older than 730 days and keeps the rest', async () => {
    const { purgeExpiredRevisions } = await import('../../src/services/qr-revisions.js');
    const code = await db.qRCode.findUniqueOrThrow({ where: { token: 'c1' } });
    const day = 24 * 60 * 60 * 1000;
    await db.qRCodeRevision.createMany({
      data: [
        { qrCodeId: code.id, organizationId: orgs.A.id, revision: 2, kind: 'UPDATED', changes: {}, actorType: 'SYSTEM', createdAt: new Date(Date.now() - 731 * day) },
        { qrCodeId: code.id, organizationId: orgs.A.id, revision: 3, kind: 'UPDATED', changes: {}, actorType: 'SYSTEM', createdAt: new Date(Date.now() - 729 * day) },
      ],
    });
    expect(await purgeExpiredRevisions(db)).toBe(1);
    expect((await db.qRCodeRevision.findMany({ orderBy: { revision: 'asc' } })).map((r) => r.revision)).toEqual([1, 3]);
  });

  it('keeps a code\'s latest revision however old, so numbering never restarts', async () => {
    const { purgeExpiredRevisions } = await import('../../src/services/qr-revisions.js');
    const old = await db.qRCode.create({
      data: { token: 'old1', organizationId: orgs.A.id, signingKeyId: orgs.A.keyId, destinationUrl: 'https://old.example.test/', signature: 's', algVersion: 'test' },
    });
    const day = 24 * 60 * 60 * 1000;
    await db.qRCodeRevision.createMany({
      data: [1, 2].map((revision) => ({
        qrCodeId: old.id, organizationId: orgs.A.id, revision, kind: revision === 1 ? 'CREATED' : 'UPDATED',
        changes: {}, actorType: 'SYSTEM' as const, createdAt: new Date(Date.now() - (900 - revision) * day),
      })),
    });
    expect(await purgeExpiredRevisions(db)).toBe(1);
    expect((await db.qRCodeRevision.findMany({ where: { qrCodeId: old.id } })).map((r) => r.revision)).toEqual([2]);
    await call('A', 'PATCH', '/api/v1/qrcodes/old1', { destinationUrl: 'https://new.example.test/' });
    expect((await db.qRCodeRevision.findMany({ where: { qrCodeId: old.id }, orderBy: { revision: 'asc' } })).map((r) => r.revision)).toEqual([2, 3]);
  });

  it('deleting the organization cascades through its codes to their history', async () => {
    await db.organization.delete({ where: { id: orgs.A.id } });
    expect(await db.qRCodeRevision.count()).toBe(0);
  });

  it('restore reports history-incomplete when retention removed every revision that set the destination', async () => {
    const code = await db.qRCode.findUniqueOrThrow({ where: { token: 'c1' } });
    // Only a later revision that did not touch the destination is left.
    await db.$executeRawUnsafe(`ALTER TABLE "qr_code_revisions" DISABLE TRIGGER "qr_code_revisions_append_only"`);
    await db.qRCodeRevision.deleteMany({ where: { qrCodeId: code.id } });
    await db.$executeRawUnsafe(`ALTER TABLE "qr_code_revisions" ENABLE TRIGGER "qr_code_revisions_append_only"`);
    await db.qRCodeRevision.create({ data: { qrCodeId: code.id, organizationId: orgs.A.id, revision: 7, kind: 'UPDATED', changes: { scanMode: { before: 'FLASH', after: 'PAGE' } }, actorType: 'SYSTEM' } });
    const res = await call('A', 'POST', '/api/v1/qrcodes/c1/history/7/restore');
    expect(res.statusCode).toBe(409);
    expect(res.json().code).toBe('history-incomplete');
  });
});

describe('history pagination', () => {
  beforeAll(async () => {
    await reset();
    await makeCode('A', 'c1');
    for (let i = 0; i < 4; i++) await call('A', 'PATCH', '/api/v1/qrcodes/c1', { destinationUrl: `https://p${i}.example.test/` });
  });

  it('pages newest first', async () => {
    const p1 = await history('A', 'c1', '?pageSize=2&page=1');
    const p3 = await history('A', 'c1', '?pageSize=2&page=3');
    expect(p1).toMatchObject({ total: 5, totalPages: 3 });
    expect(p1.data.map((r: { revision: number }) => r.revision)).toEqual([5, 4]);
    expect(p3.data.map((r: { revision: number }) => r.revision)).toEqual([1]);
  });
});
