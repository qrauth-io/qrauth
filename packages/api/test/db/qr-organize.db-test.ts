/**
 * Search, tags and folders (Milestone 1) against a real Postgres, through
 * the real routes: tenant isolation on every endpoint, roles, per-org
 * limits under concurrency, search semantics, and search latency at 10k
 * codes per organization. Run by scripts/ci-verify.sh `db`
 * (TEST_DATABASE_URL).
 */
import { PrismaClient } from '@prisma/client';
import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { MAX_FOLDERS_PER_ORG, MAX_TAGS_PER_ORG } from '@qrauth/shared';

import { seedQrVolume } from '../../scripts/qr-volume-seed.js';

const url = process.env.TEST_DATABASE_URL;
if (!url) throw new Error('TEST_DATABASE_URL is not set');
if (!/test/i.test(new URL(url).pathname)) throw new Error('TEST_DATABASE_URL must name a test database (the suite truncates tables)');

// The routes import config.ts, which validates these at load; no Redis
// connection is opened (queues and cache are mocked, rate limiting is not
// registered here).
process.env.DATABASE_URL ??= url;
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'db-test-only-throwaway-secret-0000000000';

vi.mock('../../src/lib/cache.js', () => ({
  cacheGet: vi.fn(async () => null),
  cacheSet: vi.fn(async () => undefined),
  cacheDel: vi.fn(async () => undefined),
}));
// lib/queue.ts opens Redis connections at import; nothing here enqueues.
const noQueue = vi.hoisted(() => ({ add: async () => undefined }));
vi.mock('../../src/lib/queue.js', () => ({
  scanQueue: noQueue, fraudQueue: noQueue, alertQueue: noQueue, webhookQueue: noQueue,
  cleanupQueue: noQueue, analyticsQueue: noQueue, webRiskQueue: noQueue,
  createQueueConnection: vi.fn(), closeQueues: vi.fn(async () => undefined),
}));
vi.mock('../../src/services/hybrid-signing.js', () => ({ HybridSigningService: class {} }));
vi.mock('../../src/services/mac.js', () => ({ MacService: class {} }));
vi.mock('../../src/services/domain.js', () => ({ DomainService: class {} }));

const db = new PrismaClient({ datasources: { db: { url } } });
let app: FastifyInstance;

type Role = 'OWNER' | 'ADMIN' | 'MANAGER' | 'MEMBER' | 'VIEWER';
const orgs: Record<'A' | 'B', { id: string; keyId: string }> = {} as never;

function call(org: 'A' | 'B', method: 'GET' | 'POST' | 'PATCH' | 'DELETE', path: string, body?: unknown, role: Role = 'MEMBER') {
  return app.inject({
    method,
    url: path,
    headers: {
      'x-test-user': JSON.stringify({ orgId: orgs[org].id, role }),
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    ...(body === undefined ? {} : { payload: JSON.stringify(body) }),
  });
}

async function makeCode(org: 'A' | 'B', token: string, extra: Record<string, unknown> = {}) {
  return db.qRCode.create({
    data: {
      token,
      organizationId: orgs[org].id,
      signingKeyId: orgs[org].keyId,
      destinationUrl: 'https://example.test/',
      signature: 'sig',
      algVersion: 'test',
      ...extra,
    },
  });
}

async function reset(): Promise<void> {
  await db.$executeRawUnsafe('TRUNCATE "organizations" CASCADE');
  for (const org of ['A', 'B'] as const) {
    const o = await db.organization.create({ data: { name: `Org ${org}`, slug: `org-${org.toLowerCase()}-organize-test`, email: `${org}@organize.test` } });
    const key = await db.signingKey.create({ data: { organizationId: o.id, publicKey: 'pk', keyId: `key-${org}-${o.id}` } });
    orgs[org] = { id: o.id, keyId: key.id };
  }
}

const tokensOf = (res: { json: () => { data: Array<{ token: string }> } }) => res.json().data.map((r) => r.token).sort();

beforeAll(async () => {
  app = Fastify();
  app.decorate('prisma', db as never);
  app.decorate('signingService', {} as never);
  app.decorate('batchSigner', {} as never);
  app.decorateRequest('user', null);
  app.decorate('authenticate', async (request: { headers: Record<string, string | undefined>; user: unknown }) => {
    const { orgId, role } = JSON.parse(request.headers['x-test-user'] ?? '{}');
    request.user = { id: `user-${role}`, orgId, role, email: 'u@organize.test' };
  });
  const { default: qrcodeRoutes } = await import('../../src/routes/qrcodes.js');
  const { tagRoutes, folderRoutes } = await import('../../src/routes/qr-organize.js');
  await app.register(qrcodeRoutes, { prefix: '/api/v1/qrcodes' });
  await app.register(tagRoutes, { prefix: '/api/v1/tags' });
  await app.register(folderRoutes, { prefix: '/api/v1/folders' });
  await app.ready();
});

afterAll(async () => {
  await app.close();
  await db.$disconnect();
});

// ---------------------------------------------------------------------------

describe('tags and folders: CRUD, names and limits', () => {
  beforeEach(reset);

  it('creates, lists with code counts, renames, recolours and deletes a tag', async () => {
    const created = await call('A', 'POST', '/api/v1/tags', { name: '  Summer  ', color: 'teal' });
    expect(created.statusCode).toBe(201);
    const tag = created.json();
    expect(tag).toMatchObject({ name: 'Summer', color: 'teal', codeCount: 0 });

    await makeCode('A', 'c1');
    await call('A', 'POST', '/api/v1/qrcodes/bulk-tag', { tokens: ['c1'], add: [tag.id] });
    const list = await call('A', 'GET', '/api/v1/tags', undefined, 'VIEWER');
    expect(list.json().data).toEqual([expect.objectContaining({ id: tag.id, codeCount: 1 })]);

    const patched = await call('A', 'PATCH', `/api/v1/tags/${tag.id}`, { name: 'Summer 2027', color: 'red' });
    expect(patched.json()).toMatchObject({ name: 'Summer 2027', color: 'red' });

    expect((await call('A', 'DELETE', `/api/v1/tags/${tag.id}`)).statusCode).toBe(204);
    expect(await db.qRCodeTag.count()).toBe(0);
  });

  it('refuses a name already used in the org, ignoring case; another org may use it', async () => {
    await call('A', 'POST', '/api/v1/tags', { name: 'Promo' });
    const clash = await call('A', 'POST', '/api/v1/tags', { name: 'PROMO' });
    expect(clash.statusCode).toBe(409);
    expect(clash.json().code).toBe('name-taken');
    expect((await call('B', 'POST', '/api/v1/tags', { name: 'Promo' })).statusCode).toBe(201);

    await call('A', 'POST', '/api/v1/folders', { name: 'Lobby' });
    expect((await call('A', 'POST', '/api/v1/folders', { name: 'lobby' })).statusCode).toBe(409);
  });

  it('validates tag name length and colour against the fixed palette', async () => {
    expect((await call('A', 'POST', '/api/v1/tags', { name: 'x'.repeat(33) })).statusCode).toBe(400);
    expect((await call('A', 'POST', '/api/v1/tags', { name: 'ok', color: '#ff0000' })).statusCode).toBe(400);
    expect((await call('A', 'POST', '/api/v1/tags', { name: '   ' })).statusCode).toBe(400);
    expect((await call('A', 'POST', '/api/v1/tags', { name: 'x'.repeat(32) })).statusCode).toBe(201);
  });

  it(`holds the ${MAX_TAGS_PER_ORG}-tag cap under concurrent creates`, async () => {
    await db.tag.createMany({
      data: Array.from({ length: MAX_TAGS_PER_ORG - 3 }, (_, i) => ({ organizationId: orgs.A.id, name: `t${i}`, color: 'grey' })),
    });
    const results = await Promise.all(
      Array.from({ length: 10 }, (_, i) => call('A', 'POST', '/api/v1/tags', { name: `race${i}` })),
    );
    expect(results.filter((r) => r.statusCode === 201)).toHaveLength(3);
    expect(results.filter((r) => r.statusCode === 409).every((r) => r.json().code === 'limit-reached')).toBe(true);
    expect(await db.tag.count({ where: { organizationId: orgs.A.id } })).toBe(MAX_TAGS_PER_ORG);
    // The cap is per org.
    expect((await call('B', 'POST', '/api/v1/tags', { name: 'race0' })).statusCode).toBe(201);
  });

  it(`holds the ${MAX_FOLDERS_PER_ORG}-folder cap`, async () => {
    await db.qRFolder.createMany({
      data: Array.from({ length: MAX_FOLDERS_PER_ORG - 1 }, (_, i) => ({ organizationId: orgs.A.id, name: `f${i}` })),
    });
    expect((await call('A', 'POST', '/api/v1/folders', { name: 'last' })).statusCode).toBe(201);
    const over = await call('A', 'POST', '/api/v1/folders', { name: 'one too many' });
    expect(over.statusCode).toBe(409);
    expect(over.json().code).toBe('limit-reached');
  });

  it('deleting a folder leaves its codes unfiled; folder list counts unfiled codes', async () => {
    const folder = (await call('A', 'POST', '/api/v1/folders', { name: 'Events' })).json();
    await makeCode('A', 'c1');
    await makeCode('A', 'c2');
    await call('A', 'POST', '/api/v1/qrcodes/bulk-move', { tokens: ['c1'], folderId: folder.id });

    const before = (await call('A', 'GET', '/api/v1/folders', undefined, 'VIEWER')).json();
    expect(before).toEqual({ data: [expect.objectContaining({ name: 'Events', codeCount: 1 })], unfiledCount: 1 });

    expect((await call('A', 'DELETE', `/api/v1/folders/${folder.id}`)).statusCode).toBe(204);
    expect((await db.qRCode.findUnique({ where: { token: 'c1' } }))?.folderId).toBeNull();
  });
});

// ---------------------------------------------------------------------------

describe('tenant isolation: another org\'s ids are 404 on every endpoint', () => {
  let bTag: string;
  let bFolder: string;

  beforeEach(async () => {
    await reset();
    await makeCode('A', 'a1');
    await makeCode('B', 'b1');
    bTag = (await call('B', 'POST', '/api/v1/tags', { name: 'B secret' })).json().id;
    bFolder = (await call('B', 'POST', '/api/v1/folders', { name: 'B folder' })).json().id;
    await call('B', 'POST', '/api/v1/qrcodes/bulk-tag', { tokens: ['b1'], add: [bTag] });
    await call('B', 'POST', '/api/v1/qrcodes/bulk-move', { tokens: ['b1'], folderId: bFolder });
  });

  it.each([
    ['PATCH tag', () => call('A', 'PATCH', `/api/v1/tags/${bTag}`, { name: 'mine now' })],
    ['DELETE tag', () => call('A', 'DELETE', `/api/v1/tags/${bTag}`)],
    ['PATCH folder', () => call('A', 'PATCH', `/api/v1/folders/${bFolder}`, { name: 'mine now' })],
    ['DELETE folder', () => call('A', 'DELETE', `/api/v1/folders/${bFolder}`)],
    ['bulk-tag add', () => call('A', 'POST', '/api/v1/qrcodes/bulk-tag', { tokens: ['a1'], add: [bTag] })],
    ['bulk-tag remove', () => call('A', 'POST', '/api/v1/qrcodes/bulk-tag', { tokens: ['a1'], remove: [bTag] })],
    ['bulk-move', () => call('A', 'POST', '/api/v1/qrcodes/bulk-move', { tokens: ['a1'], folderId: bFolder })],
    ['list by tag', () => call('A', 'GET', `/api/v1/qrcodes?tagIds=${bTag}`)],
    ['list by folder', () => call('A', 'GET', `/api/v1/qrcodes?folderId=${bFolder}`)],
  ])('%s → 404, and org B is unchanged', async (_name, request) => {
    const res = await request();
    expect(res.statusCode).toBe(404);

    const tag = await db.tag.findUnique({ where: { id: bTag } });
    const folder = await db.qRFolder.findUnique({ where: { id: bFolder } });
    expect(tag?.name).toBe('B secret');
    expect(folder?.name).toBe('B folder');
    expect(await db.qRCodeTag.count({ where: { tagId: bTag } })).toBe(1);
    expect((await db.qRCode.findUnique({ where: { token: 'a1' } }))?.folderId).toBeNull();
    expect(await db.qRCodeTag.count({ where: { qrCode: { token: 'a1' } } })).toBe(0);
  });

  it('bulk actions report another org\'s tokens as not found and leave them alone', async () => {
    const tag = (await call('A', 'POST', '/api/v1/tags', { name: 'A tag' })).json().id;
    const folder = (await call('A', 'POST', '/api/v1/folders', { name: 'A folder' })).json().id;

    const tagged = await call('A', 'POST', '/api/v1/qrcodes/bulk-tag', { tokens: ['a1', 'b1', 'nope'], add: [tag] });
    expect(tagged.json()).toEqual({ updated: ['a1'], notFound: ['b1', 'nope'] });
    const moved = await call('A', 'POST', '/api/v1/qrcodes/bulk-move', { tokens: ['b1', 'a1'], folderId: folder });
    expect(moved.json()).toEqual({ updated: ['a1'], notFound: ['b1'] });

    const b1 = await db.qRCode.findUnique({ where: { token: 'b1' }, include: { tags: true } });
    expect(b1?.folderId).toBe(bFolder);
    expect(b1?.tags.map((t) => t.tagId)).toEqual([bTag]);
  });

  it('lists only the caller\'s tags, folders and codes', async () => {
    expect((await call('A', 'GET', '/api/v1/tags')).json().data).toEqual([]);
    expect((await call('A', 'GET', '/api/v1/folders')).json()).toEqual({ data: [], unfiledCount: 1 });
    expect(tokensOf(await call('A', 'GET', '/api/v1/qrcodes?q=b1'))).toEqual([]);
  });
});

// ---------------------------------------------------------------------------

describe('roles: VIEWER reads, MEMBER and above organise', () => {
  beforeEach(async () => {
    await reset();
    await makeCode('A', 'a1');
  });

  it('VIEWER can list but every write is 403', async () => {
    const tag = (await call('A', 'POST', '/api/v1/tags', { name: 't' })).json().id;
    const folder = (await call('A', 'POST', '/api/v1/folders', { name: 'f' })).json().id;

    for (const path of ['/api/v1/tags', '/api/v1/folders', '/api/v1/qrcodes']) {
      expect((await call('A', 'GET', path, undefined, 'VIEWER')).statusCode).toBe(200);
    }
    const writes = [
      call('A', 'POST', '/api/v1/tags', { name: 'v' }, 'VIEWER'),
      call('A', 'PATCH', `/api/v1/tags/${tag}`, { name: 'v' }, 'VIEWER'),
      call('A', 'DELETE', `/api/v1/tags/${tag}`, undefined, 'VIEWER'),
      call('A', 'POST', '/api/v1/folders', { name: 'v' }, 'VIEWER'),
      call('A', 'PATCH', `/api/v1/folders/${folder}`, { name: 'v' }, 'VIEWER'),
      call('A', 'DELETE', `/api/v1/folders/${folder}`, undefined, 'VIEWER'),
      call('A', 'POST', '/api/v1/qrcodes/bulk-tag', { tokens: ['a1'], add: [tag] }, 'VIEWER'),
      call('A', 'POST', '/api/v1/qrcodes/bulk-move', { tokens: ['a1'], folderId: folder }, 'VIEWER'),
    ];
    for (const res of await Promise.all(writes)) expect(res.statusCode).toBe(403);
    expect(await db.qRCodeTag.count()).toBe(0);
  });

  it.each(['MEMBER', 'MANAGER', 'ADMIN', 'OWNER'] as const)('%s can tag and move', async (role) => {
    const tag = (await call('A', 'POST', '/api/v1/tags', { name: `t-${role}` }, role)).json().id;
    const folder = (await call('A', 'POST', '/api/v1/folders', { name: `f-${role}` }, role)).json().id;
    expect((await call('A', 'POST', '/api/v1/qrcodes/bulk-tag', { tokens: ['a1'], add: [tag] }, role)).statusCode).toBe(200);
    expect((await call('A', 'POST', '/api/v1/qrcodes/bulk-move', { tokens: ['a1'], folderId: folder }, role)).statusCode).toBe(200);
  });
});

// ---------------------------------------------------------------------------

describe('bulk actions', () => {
  beforeEach(async () => {
    await reset();
    for (const t of ['a1', 'a2', 'a3']) await makeCode('A', t);
  });

  it('adds and removes tags in one call, idempotently', async () => {
    const red = (await call('A', 'POST', '/api/v1/tags', { name: 'red' })).json().id;
    const blue = (await call('A', 'POST', '/api/v1/tags', { name: 'blue' })).json().id;
    await call('A', 'POST', '/api/v1/qrcodes/bulk-tag', { tokens: ['a1', 'a2'], add: [red] });
    await call('A', 'POST', '/api/v1/qrcodes/bulk-tag', { tokens: ['a1', 'a2'], add: [red] });
    const res = await call('A', 'POST', '/api/v1/qrcodes/bulk-tag', { tokens: ['a1', 'a2', 'a3'], add: [blue], remove: [red] });
    expect(res.statusCode).toBe(200);
    const links = await db.qRCodeTag.findMany({ include: { qrCode: true } });
    expect(links.map((l) => `${l.qrCode.token}:${l.tagId === blue ? 'blue' : 'red'}`).sort()).toEqual(['a1:blue', 'a2:blue', 'a3:blue']);
  });

  it('refuses a tag both added and removed, an empty change, and more than 100 codes', async () => {
    const t = (await call('A', 'POST', '/api/v1/tags', { name: 't' })).json().id;
    expect((await call('A', 'POST', '/api/v1/qrcodes/bulk-tag', { tokens: ['a1'], add: [t], remove: [t] })).statusCode).toBe(400);
    expect((await call('A', 'POST', '/api/v1/qrcodes/bulk-tag', { tokens: ['a1'] })).statusCode).toBe(400);
    const many = Array.from({ length: 101 }, (_, i) => `t${i}`);
    expect((await call('A', 'POST', '/api/v1/qrcodes/bulk-move', { tokens: many, folderId: null })).statusCode).toBe(400);
  });

  it('moves codes between folders and back to unfiled', async () => {
    const f = (await call('A', 'POST', '/api/v1/folders', { name: 'f' })).json().id;
    await call('A', 'POST', '/api/v1/qrcodes/bulk-move', { tokens: ['a1', 'a2'], folderId: f });
    expect(tokensOf(await call('A', 'GET', `/api/v1/qrcodes?folderId=${f}`))).toEqual(['a1', 'a2']);
    await call('A', 'POST', '/api/v1/qrcodes/bulk-move', { tokens: ['a1'], folderId: null });
    expect(tokensOf(await call('A', 'GET', '/api/v1/qrcodes?folderId=unfiled'))).toEqual(['a1', 'a3']);
  });
});

// ---------------------------------------------------------------------------

describe('search and filters', () => {
  let promo: string;
  let event: string;
  let lobby: string;

  beforeAll(async () => {
    await reset();
    await makeCode('A', 'AbcToken1', { label: 'Summer poster', destinationUrl: 'https://Shop.Example.com/sale?x=1' });
    await makeCode('A', 'AbcToken2', { label: 'Lobby screen', destinationUrl: 'https://tickets.events.test/path/shop' });
    await makeCode('A', 'Xyz9', { label: '50% off_coupon', contentType: 'coupon', destinationUrl: 'https://qrauth.io/v/Xyz9' });
    await makeCode('A', 'Rev1', { label: 'Old summer', status: 'REVOKED', destinationUrl: 'https://user:pw@shop.example.com:8443/' });
    await makeCode('A', 'Card1', { label: null, contentType: 'vcard', destinationUrl: 'https://qrauth.io/v/Card1' });
    await makeCode('B', 'AbcToken3', { label: 'Summer poster B', destinationUrl: 'https://shop.example.com/' });
    promo = (await call('A', 'POST', '/api/v1/tags', { name: 'promo' })).json().id;
    event = (await call('A', 'POST', '/api/v1/tags', { name: 'event' })).json().id;
    lobby = (await call('A', 'POST', '/api/v1/folders', { name: 'Lobby' })).json().id;
    await call('A', 'POST', '/api/v1/qrcodes/bulk-tag', { tokens: ['AbcToken1', 'Xyz9'], add: [promo] });
    await call('A', 'POST', '/api/v1/qrcodes/bulk-tag', { tokens: ['AbcToken2'], add: [event] });
    await call('A', 'POST', '/api/v1/qrcodes/bulk-move', { tokens: ['AbcToken2', 'Card1'], folderId: lobby });
  });

  const search = (qs: string) => call('A', 'GET', `/api/v1/qrcodes?${qs}`, undefined, 'VIEWER');

  it.each([
    ['label substring, any case', 'q=SUMMER', ['AbcToken1', 'Rev1']],
    ['destination host, not path', 'q=shop', ['AbcToken1', 'Rev1']],
    ['host ignores userinfo and port', 'q=example.com:8443', []],
    ['token prefix', 'q=AbcTok', ['AbcToken1', 'AbcToken2']],
    ['token is case-sensitive', 'q=abctok', []],
    ['content type key', 'q=vcard', ['Card1']],
    ['LIKE wildcards match literally', 'q=50%25 off_', ['Xyz9']],
    ['a bare % matches only labels containing %', 'q=%25', ['Xyz9']],
    ['search + status', 'q=summer&status=ACTIVE', ['AbcToken1']],
    ['contentType filter, any case', 'contentType=Coupon', ['Xyz9']],
    ['non-URL codes do not match on the verify-page host', 'q=qrauth.io', []],
  ])('%s', async (_name, qs, expected) => {
    const res = await search(qs);
    expect(res.statusCode).toBe(200);
    expect(tokensOf(res)).toEqual([...expected].sort());
  });

  it('filters by tags (codes with any of them), combined with search and folder', async () => {
    expect(tokensOf(await search(`tagIds=${promo}`))).toEqual(['AbcToken1', 'Xyz9']);
    expect(tokensOf(await search(`tagIds=${promo},${event}`))).toEqual(['AbcToken1', 'AbcToken2', 'Xyz9']);
    expect(tokensOf(await search(`tagIds=${promo},${event}&q=lobby`))).toEqual(['AbcToken2']);
    expect(tokensOf(await search(`folderId=${lobby}&tagIds=${event}`))).toEqual(['AbcToken2']);
    expect(tokensOf(await search(`folderId=${lobby}`))).toEqual(['AbcToken2', 'Card1']);
    expect(tokensOf(await search('folderId=unfiled'))).toEqual(['AbcToken1', 'Rev1', 'Xyz9']);
  });

  it('returns each code with its tags and folder, and paginates the filtered set', async () => {
    const page1 = (await search('q=AbcTok&pageSize=1&page=1')).json();
    const page2 = (await search('q=AbcTok&pageSize=1&page=2')).json();
    expect(page1).toMatchObject({ total: 2, totalPages: 2, page: 1, pageSize: 1 });
    expect([page1.data[0].token, page2.data[0].token].sort()).toEqual(['AbcToken1', 'AbcToken2']);
    const two = [...page1.data, ...page2.data].find((r: { token: string }) => r.token === 'AbcToken2');
    expect(two.tags).toEqual([{ id: event, name: 'event', color: 'grey' }]);
    expect(two.folder).toEqual({ id: lobby, name: 'Lobby' });
    expect(two._count).toEqual({ scans: 0 });
  });

  it('refuses an over-long query', async () => {
    expect((await search(`q=${'x'.repeat(101)}`)).statusCode).toBe(400);
  });
});

// ---------------------------------------------------------------------------

describe('search latency at 10k codes per org', () => {
  const ORG_CODES = 10_000;
  const RUNS = 40;
  const P95_BUDGET_MS = 50;

  beforeAll(async () => {
    await reset();
    // The org under test plus two neighbours, so org scoping is exercised.
    await seedQrVolume(db, { orgId: orgs.A.id, signingKeyId: orgs.A.keyId, count: ORG_CODES, tokenPrefix: 'pa' });
    await seedQrVolume(db, { orgId: orgs.B.id, signingKeyId: orgs.B.keyId, count: ORG_CODES * 2, tokenPrefix: 'pb' });
    const tags = await Promise.all(['promo', 'print', 'event'].map((name) => db.tag.create({ data: { organizationId: orgs.A.id, name, color: 'blue' } })));
    const folder = await db.qRFolder.create({ data: { organizationId: orgs.A.id, name: 'Campaign' } });
    await db.$executeRaw`
      INSERT INTO "qr_code_tags" ("qrCodeId", "tagId")
      SELECT q."id", (ARRAY[${tags[0].id}, ${tags[1].id}, ${tags[2].id}])[1 + (abs(hashtext(q."id")) % 3)]
      FROM "qr_codes" q WHERE q."organizationId" = ${orgs.A.id} AND abs(hashtext(q."id")) % 4 = 0`;
    await db.$executeRaw`UPDATE "qr_codes" SET "folderId" = ${folder.id} WHERE "organizationId" = ${orgs.A.id} AND abs(hashtext("id")) % 5 = 0`;
    await db.$executeRawUnsafe('ANALYZE "qr_codes"');
    await db.$executeRawUnsafe('ANALYZE "qr_code_tags"');
    Object.assign(perfIds, { tag: tags[0].id, folder: folder.id });
  }, 120_000);

  const perfIds: { tag?: string; folder?: string } = {};

  const QUERIES = () => [
    'q=poster',
    'q=harbour',
    'q=thessaloniki',
    'q=tickets.acme',
    'q=pa12',
    'q=vcard',
    'q=nothing-matches-this',
    'q=menu&status=ACTIVE',
    `q=north&tagIds=${perfIds.tag}`,
    `folderId=${perfIds.folder}&q=flyer`,
    'folderId=unfiled&page=5&pageSize=50',
    'page=20&pageSize=100',
  ];

  it(`p95 under ${P95_BUDGET_MS} ms per list request (search, filters, count, rows)`, async () => {
    const queries = QUERIES();
    for (const qs of queries) await call('A', 'GET', `/api/v1/qrcodes?${qs}`); // warm up
    const timings: number[] = [];
    const perQuery: Record<string, number[]> = {};
    for (let run = 0; run < RUNS; run++) {
      for (const qs of queries) {
        const start = performance.now();
        const res = await call('A', 'GET', `/api/v1/qrcodes?${qs}`, undefined, 'VIEWER');
        const ms = performance.now() - start;
        expect(res.statusCode).toBe(200);
        timings.push(ms);
        (perQuery[qs] ??= []).push(ms);
      }
    }
    const pct = (xs: number[], p: number) => [...xs].sort((a, b) => a - b)[Math.min(xs.length - 1, Math.floor(xs.length * p))];
    const report = Object.entries(perQuery).map(([qs, xs]) => `  p50 ${pct(xs, 0.5).toFixed(1)} ms  p95 ${pct(xs, 0.95).toFixed(1)} ms  ${qs.replace(/[a-z0-9]{20,}/g, '<id>')}`);
    console.log(`[qr-search] ${timings.length} requests at ${ORG_CODES} codes/org: p50 ${pct(timings, 0.5).toFixed(1)} ms, p95 ${pct(timings, 0.95).toFixed(1)} ms, max ${Math.max(...timings).toFixed(1)} ms\n${report.join('\n')}`);
    expect(pct(timings, 0.95)).toBeLessThan(P95_BUDGET_MS);
  }, 120_000);

  it('generates the host on write and the host and label searches can use the trigram indexes', async () => {
    const hosts = await db.$queryRaw<Array<{ destinationHost: string | null }>>`
      SELECT "destinationHost" FROM "qr_codes" WHERE "token" IN ('pa1', 'pa2') ORDER BY "token"`;
    expect(hosts.map((h) => h.destinationHost)).toEqual(['menu.example.com', 'events.example.com']);

    // Planner choice depends on statistics; with sequential scans disabled
    // the trigram indexes must be usable for both expressions.
    const plan = await db.$transaction(async (tx) => {
      await tx.$executeRawUnsafe('SET LOCAL enable_seqscan = off');
      await tx.$executeRawUnsafe('SET LOCAL enable_indexscan = off');
      return tx.$queryRawUnsafe<Array<{ 'QUERY PLAN': string }>>(`
        EXPLAIN SELECT id FROM qr_codes
        WHERE label ILIKE '%harbour%'
           OR "destinationHost" LIKE '%tickets%'`);
    });
    const text = plan.map((r) => r['QUERY PLAN']).join('\n');
    expect(text).toContain('qr_codes_label_trgm_idx');
    expect(text).toContain('qr_codes_destination_host_trgm_idx');
  });
});
