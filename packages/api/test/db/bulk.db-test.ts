/**
 * Bulk CSV import and ZIP export (ADR-0008 D9) against a real Postgres,
 * through the real bulk routes and job processors: dry run, commit,
 * re-validation at commit, one active job per organization, results CSV,
 * ZIP export with manifest, signed download links, tenant isolation of dry
 * run, job and ZIP ids, the plan and role gates, audit entries and the
 * cleanup sweep. Signing, MAC and transparency are stubbed; Web Risk is a
 * stub ("malware" is listed, "unavailable" does not answer); the lookalike
 * check is real. Redis is an in-memory map. Run by scripts/ci-verify.sh `db`.
 */
import { PrismaClient } from '@prisma/client';
import Fastify, { type FastifyInstance } from 'fastify';
import { mkdtempSync, readFileSync, readdirSync, existsSync, rmSync, writeFileSync, utimesSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { unzipSync, strFromU8 } from 'fflate';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

const url = process.env.TEST_DATABASE_URL;
if (!url) throw new Error('TEST_DATABASE_URL is not set');
if (!/test/i.test(new URL(url).pathname)) throw new Error('TEST_DATABASE_URL must name a test database (the suite truncates tables)');

process.env.DATABASE_URL ??= url;
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'db-test-only-throwaway-secret-0000000000';
const exportDir = mkdtempSync(join(tmpdir(), 'qrauth-bulk-db-test-'));
process.env.BULK_EXPORT_DIR = exportDir;

const stubs = vi.hoisted(() => ({
  noQueue: { add: async () => undefined },
  store: new Map<string, unknown>(),
  enqueued: [] as Array<{ kind: string; id: string }>,
  failEnqueue: false,
  failCacheDel: false,
  screened: [] as string[],
  async screen(u: string) {
    this.screened.push(u);
    if (u.includes('unavailable')) return { verdict: 'unavailable' as const, threatTypes: [] };
    return u.includes('malware') ? { verdict: 'flagged' as const, threatTypes: ['MALWARE'] } : { verdict: 'clean' as const, threatTypes: [] };
  },
}));

vi.mock('../../src/lib/queue.js', () => ({
  scanQueue: stubs.noQueue, fraudQueue: stubs.noQueue, alertQueue: stubs.noQueue, webhookQueue: stubs.noQueue,
  cleanupQueue: stubs.noQueue, analyticsQueue: stubs.noQueue, webRiskQueue: stubs.noQueue,
  bulkImportQueue: stubs.noQueue, exportQueue: stubs.noQueue,
  createQueueConnection: vi.fn(), closeQueues: vi.fn(async () => undefined),
}));
vi.mock('../../src/lib/cache.js', () => ({
  cacheGet: vi.fn(async (k: string) => (stubs.store.has(k) ? structuredClone(stubs.store.get(k)) : null)),
  cacheSet: vi.fn(async (k: string, v: unknown) => void stubs.store.set(k, structuredClone(v))),
  cacheDel: vi.fn(async (k: string) => {
    if (stubs.failCacheDel) throw new Error('redis down');
    stubs.store.delete(k);
  }),
}));
vi.mock('../../src/workers/bulk.js', () => ({
  enqueueBulkJob: vi.fn(async (kind: string, id: string) => {
    if (stubs.failEnqueue) throw new Error('redis down');
    stubs.enqueued.push({ kind, id });
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
  screenDestination: (u: string) => stubs.screen(u),
  enqueueDestinationRecheck: vi.fn(async () => undefined),
}));

const db = new PrismaClient({ datasources: { db: { url } } });
let app: FastifyInstance;

const ROLES = ['OWNER', 'ADMIN', 'MANAGER', 'MEMBER', 'VIEWER'] as const;
type Role = (typeof ROLES)[number];
type OrgName = 'A' | 'B' | 'PRO';
type Org = { id: string; keyId: string; users: Record<Role, string>; apiKeyId: string };
const orgs: Record<OrgName, Org> = {} as never;
type CallOpts = { as?: Role; key?: boolean; contentType?: string };

function headers(org: OrgName, opts: CallOpts): Record<string, string> {
  const o = orgs[org];
  const user = opts.key
    ? { id: 'api-key', orgId: o.id, role: 'MANAGER', email: '', apiKeyId: o.apiKeyId }
    : { id: o.users[opts.as ?? 'OWNER'], orgId: o.id, role: opts.as ?? 'OWNER', email: 'u@bulk.test' };
  return { 'x-test-user': JSON.stringify(user) };
}

function call(org: OrgName, method: 'GET' | 'POST', path: string, body?: unknown, opts: CallOpts = {}) {
  return app.inject({
    method,
    url: path,
    headers: { ...headers(org, opts), ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
    ...(body === undefined ? {} : { payload: JSON.stringify(body) }),
  });
}

function upload(org: OrgName, csv: string | Buffer, opts: CallOpts & { timezone?: string } = {}) {
  return app.inject({
    method: 'POST',
    url: `/api/v1/bulk/imports/dry-run${opts.timezone ? `?timezone=${encodeURIComponent(opts.timezone)}` : ''}`,
    headers: { ...headers(org, opts), 'content-type': opts.contentType ?? 'text/csv' },
    payload: csv,
  });
}

async function runImport(id: string) {
  const { runImportJob } = await import('../../src/workers/bulk-import.js');
  await runImportJob({ prisma: db, log: app.log, signingService: app.signingService, batchSigner: app.batchSigner }, id);
  return db.bulkJob.findUniqueOrThrow({ where: { id } });
}

async function runExport(id: string) {
  const { runExportJob } = await import('../../src/workers/bulk-export.js');
  await runExportJob({ prisma: db, log: app.log }, id);
  return db.bulkJob.findUniqueOrThrow({ where: { id } });
}

/** Upload, commit and run an import; returns the job row. */
async function importCsv(org: OrgName, csv: string, opts: CallOpts = {}) {
  const dry = await upload(org, csv, opts);
  expect(dry.statusCode, dry.body).toBe(201);
  const commit = await call(org, 'POST', `/api/v1/bulk/imports/dry-run/${dry.json().id}/commit`, undefined, opts);
  expect(commit.statusCode, commit.body).toBe(202);
  return runImport(commit.json().id);
}

const audits = (org: OrgName, action: string) =>
  db.auditLog.findMany({ where: { organizationId: orgs[org].id, action }, orderBy: { createdAt: 'asc' } });

async function reset(): Promise<void> {
  await db.$executeRawUnsafe('TRUNCATE "organizations", "users" CASCADE');
  stubs.store.clear();
  for (const name of readdirSync(exportDir)) rmSync(join(exportDir, name));
  stubs.enqueued.length = 0;
  stubs.failEnqueue = false;
  stubs.failCacheDel = false;
  stubs.screened.length = 0;
  for (const name of ['A', 'B', 'PRO'] as const) {
    const o = await db.organization.create({
      data: { name: `Org ${name}`, slug: `org-${name.toLowerCase()}-bulk-test`, email: `${name}@bulk.test`, plan: name === 'PRO' ? 'PRO' : 'BUSINESS' },
    });
    const key = await db.signingKey.create({ data: { organizationId: o.id, publicKey: 'pk', keyId: `key-${name}-${o.id}` } });
    const users = {} as Record<Role, string>;
    for (const role of ROLES) {
      const u = await db.user.create({ data: { name: `${role} ${name}`, email: `${role.toLowerCase()}-${name.toLowerCase()}@bulk.test`, passwordHash: 'x', emailVerified: true } });
      await db.membership.create({ data: { userId: u.id, organizationId: o.id, role } });
      users[role] = u.id;
    }
    const apiKey = await db.apiKey.create({
      data: { organizationId: o.id, keyHash: `k-${o.id}`, prefix: 'qrauth_bk', label: 'Bulk key', role: 'MANAGER', createdByUserId: users.MANAGER },
    });
    orgs[name] = { id: o.id, keyId: key.id, users, apiKeyId: apiKey.id };
  }
  await db.organization.create({ data: { name: 'PayPal', slug: 'paypal-bulk-test', email: 'pp@bulk.test', domain: 'paypal.com', domainVerified: true } });
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
  const { default: bulkRoutes } = await import('../../src/routes/bulk.js');
  const { default: policyRoutes } = await import('../../src/routes/org-policies.js');
  await app.register(bulkRoutes, { prefix: '/api/v1/bulk' });
  await app.register(policyRoutes, { prefix: '/api/v1/policies' });
  await app.ready();
});

afterAll(async () => {
  await app.close();
  await db.$disconnect();
  rmSync(exportDir, { recursive: true, force: true });
});

beforeEach(async () => {
  const { DomainService } = await import('../../src/services/domain.js');
  DomainService.clearCaches(db);
  await reset();
});

const GREEK_SEMICOLON =
  'url;label;folder;tags;expiresAt;scanMode\r\n' +
  'https://example.gr/menu;Μενού τραπέζι 1;Εστιατόριο;μενού|τραπέζι;2030-12-31;FLASH\r\n' +
  'https://example.gr/offer;"Προσφορά; άνοιξη";Εστιατόριο;προσφορές;;page\r\n';

describe('dry run', () => {
  it('reads a Greek semicolon file: delimiter, tags split on |, new folder and tags listed, nothing created', async () => {
    const res = await upload('A', '\uFEFF' + GREEK_SEMICOLON);
    expect(res.statusCode, res.body).toBe(201);
    const view = res.json();
    expect(view.delimiter).toBe(';');
    expect(view.totals).toMatchObject({ rows: 2, ok: 2, error: 0, newFolders: ['Εστιατόριο'], newTags: ['μενού', 'τραπέζι', 'προσφορές'] });
    expect(view.rows[0]).toMatchObject({ row: 2, label: 'Μενού τραπέζι 1', tags: ['μενού', 'τραπέζι'], expiresAt: '2030-12-31T23:59:59.000Z', expiresDate: '2030-12-31', scanMode: 'FLASH' });
    expect(view.rows[1]).toMatchObject({ label: 'Προσφορά; άνοιξη', scanMode: 'PAGE' });
    expect(await db.qRCode.count()).toBe(0);
    expect(await db.qRFolder.count()).toBe(0);
  });

  it('reads date-only expiry in the upload\'s time zone (default UTC) and keeps the date; the job stores that instant', async () => {
    const csv = 'url,expiresAt\nhttps://example.com/a,2027-12-31';
    expect((await upload('A', csv)).json()).toMatchObject({ timezone: 'UTC', rows: [{ expiresAt: '2027-12-31T23:59:59.000Z', expiresDate: '2027-12-31' }] });
    const athens = (await upload('A', csv, { timezone: 'Europe/Athens' })).json();
    expect(athens).toMatchObject({ timezone: 'Europe/Athens', rows: [{ expiresAt: '2027-12-31T21:59:59.000Z', expiresDate: '2027-12-31' }] });
    expect((await upload('A', csv, { timezone: 'Mars/Olympus' })).json()).toMatchObject({ statusCode: 422, code: 'timezone-invalid' });
    const commit = await call('A', 'POST', `/api/v1/bulk/imports/dry-run/${athens.id}/commit`);
    await runImport(commit.json().id);
    expect((await db.qRCode.findFirstOrThrow({ where: { organizationId: orgs.A.id } })).expiresAt!.toISOString()).toBe('2027-12-31T21:59:59.000Z');
  });

  it('marks policy, Web Risk, lookalike, duplicate and field problems per row', async () => {
    const policy = await call('A', 'PUT' as never, '/api/v1/policies', {
      allowlistMode: 'ENFORCE', allowlist: [{ domain: 'example.com', includeSubdomains: true }, { domain: 'paypa1.com', includeSubdomains: true }], destinationEditMinRole: 'MEMBER',
    });
    expect(policy.statusCode, policy.body).toBe(200);
    const csv = [
      'url,label',
      'https://example.com/a,ok',
      'https://other.org/x,outside',
      'https://example.com/malware,listed',
      'https://example.com/unavailable,slow web risk',
      'https://paypa1.com/login,lookalike',
      'https://example.com/a,duplicate',
      'ftp://example.com/file,bad scheme',
      'http://localhost/admin,private host',
    ].join('\n');
    const view = (await upload('A', csv)).json();
    const by = (row: number) => view.rows.find((r: { row: number }) => r.row === row);
    expect(by(2)).toMatchObject({ status: 'ok' });
    expect(by(3)).toMatchObject({ status: 'error', code: 'destination-not-allowed' });
    expect(by(4)).toMatchObject({ status: 'error', code: 'destination-flagged' });
    expect(by(5)).toMatchObject({ status: 'warning', code: 'web-risk-unavailable' });
    expect(by(6)).toMatchObject({ status: 'warning', code: 'lookalike' });
    expect(by(7)).toMatchObject({ status: 'warning', code: 'duplicate-url' });
    expect(by(8)).toMatchObject({ status: 'error', code: 'url-invalid' });
    expect(by(9)).toMatchObject({ status: 'error', code: 'url-invalid' });
    // Web Risk once per distinct URL (row 7 repeats row 2's URL).
    expect(stubs.screened.filter((u) => u === 'https://example.com/a')).toHaveLength(1);
  });

  it('refuses whole files: too large, binary, unknown columns, 1,001 rows, wrong content type', async () => {
    const big = await upload('A', 'url\n' + 'https://example.com/x\n'.repeat(60000));
    expect(big.statusCode).toBe(413);
    const binary = await upload('A', Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x00, 0x00, 0x08]));
    expect(binary.json()).toMatchObject({ statusCode: 422, code: 'file-not-text' });
    const unknown = await upload('A', 'url,colour,size\nhttps://example.com,red,1');
    expect(unknown.json()).toMatchObject({ code: 'header-unknown-columns' });
    expect(unknown.json().message).toContain('"colour", "size"');
    const rows = (n: number) => 'url\n' + Array.from({ length: n }, (_, i) => `https://example.com/${i}`).join('\n');
    expect((await upload('A', rows(1001))).json()).toMatchObject({ code: 'too-many-rows' });
    const thousand = await upload('A', rows(1000));
    expect(thousand.statusCode).toBe(201);
    expect(thousand.json().totals.ok).toBe(1000);
    const json = await upload('A', '{"url":"x"}', { contentType: 'application/json' });
    expect(json.json()).toMatchObject({ statusCode: 422, code: 'file-not-text' });
  });

  it('is gated: lower plan 403 governance-plan-required, VIEWER 403, unverified email 403', async () => {
    expect((await upload('PRO', 'url\nhttps://example.com')).json()).toMatchObject({ statusCode: 403, code: 'governance-plan-required' });
    expect((await upload('A', 'url\nhttps://example.com', { as: 'VIEWER' })).statusCode).toBe(403);
    await db.user.update({ where: { id: orgs.A.users.MEMBER }, data: { emailVerified: false } });
    expect((await upload('A', 'url\nhttps://example.com', { as: 'MEMBER' })).json()).toMatchObject({ statusCode: 403, error: 'EmailNotVerified' });
  });

  it('belongs to its member and organization (404 for anyone else)', async () => {
    const id = (await upload('A', 'url\nhttps://example.com', { as: 'MEMBER' })).json().id;
    expect((await call('A', 'GET', `/api/v1/bulk/imports/dry-run/${id}`, undefined, { as: 'MEMBER' })).statusCode).toBe(200);
    expect((await call('A', 'GET', `/api/v1/bulk/imports/dry-run/${id}`, undefined, { as: 'OWNER' })).statusCode).toBe(404);
    expect((await call('A', 'GET', `/api/v1/bulk/imports/dry-run/${id}`, undefined, { key: true })).statusCode).toBe(404);
    expect((await call('B', 'GET', `/api/v1/bulk/imports/dry-run/${id}`)).statusCode).toBe(404);
    expect((await call('B', 'POST', `/api/v1/bulk/imports/dry-run/${id}/commit`)).statusCode).toBe(404);
  });
});

describe('commit and the import job', () => {
  it('creates the valid rows with folder and tags, skips the rest, and audits start, finish and new folders/tags', async () => {
    const csv = GREEK_SEMICOLON + 'https://example.com/malware;bad;;;;\r\n';
    const job = await importCsv('A', csv, { as: 'MEMBER' });
    expect(job).toMatchObject({ status: 'SUCCEEDED', total: 3, succeeded: 2, skipped: 1, failed: 0, processed: 3 });
    expect(job.expiresAt!.getTime() - job.finishedAt!.getTime()).toBe(24 * 3600 * 1000);

    const codes = await db.qRCode.findMany({ where: { organizationId: orgs.A.id }, include: { folder: true, tags: { include: { tag: true } } }, orderBy: { label: 'asc' } });
    expect(codes).toHaveLength(2);
    expect(codes.every((c) => c.folder?.name === 'Εστιατόριο')).toBe(true);
    expect(codes.find((c) => c.label === 'Μενού τραπέζι 1')!.tags.map((t) => t.tag.name).sort()).toEqual(['μενού', 'τραπέζι']);
    expect(codes.find((c) => c.label === 'Προσφορά; άνοιξη')!.scanMode).toBe('PAGE');

    const revisions = await db.qRCodeRevision.findMany({ where: { qrCode: { organizationId: orgs.A.id } } });
    expect(revisions).toHaveLength(2);
    expect(revisions.every((r) => r.kind === 'CREATED' && r.actorType === 'USER' && r.actorUserId === orgs.A.users.MEMBER)).toBe(true);

    const [start] = await audits('A', 'bulk.start');
    const [finish] = await audits('A', 'bulk.finish');
    expect(start).toMatchObject({ actorType: 'USER', actorId: orgs.A.users.MEMBER, resourceId: job.id });
    expect(start.metadata).toMatchObject({ jobId: job.id, kind: 'IMPORT', total: 3, ok: 2, error: 1 });
    expect(finish.metadata).toMatchObject({ jobId: job.id, status: 'SUCCEEDED', succeeded: 2, skipped: 1, failed: 0, newFolders: 1, newTags: 3 });
    expect(await audits('A', 'folder.create')).toHaveLength(1);
    expect(await audits('A', 'tag.create')).toHaveLength(3);

    // The dry run is used up.
    expect(stubs.store.size).toBe(0);
  });

  it('re-validates at commit: a row the policy no longer allows is skipped', async () => {
    const dry = (await upload('A', 'url\nhttps://example.com/a\nhttps://other.org/b')).json();
    expect(dry.totals.ok).toBe(2);
    await call('A', 'PUT' as never, '/api/v1/policies', { allowlistMode: 'ENFORCE', allowlist: [{ domain: 'example.com', includeSubdomains: true }], destinationEditMinRole: 'MEMBER' });
    const commit = await call('A', 'POST', `/api/v1/bulk/imports/dry-run/${dry.id}/commit`);
    const job = await runImport(commit.json().id);
    expect(job).toMatchObject({ status: 'SUCCEEDED', succeeded: 1, skipped: 1 });
    const results = (await call('A', 'GET', `/api/v1/bulk/imports/${job.id}/results.csv`)).body;
    expect(results).toContain('other.org is not on');
  });

  it('allows one active import per organization (409) and frees it when the job ends', async () => {
    const first = (await upload('A', 'url\nhttps://example.com/1')).json();
    const second = (await upload('A', 'url\nhttps://example.com/2', { as: 'ADMIN' })).json();
    const started = await call('A', 'POST', `/api/v1/bulk/imports/dry-run/${first.id}/commit`);
    expect(started.statusCode).toBe(202);
    const blocked = await call('A', 'POST', `/api/v1/bulk/imports/dry-run/${second.id}/commit`, undefined, { as: 'ADMIN' });
    expect(blocked.json()).toMatchObject({ statusCode: 409, code: 'bulk-job-active', activeJobId: started.json().id });
    // Another organization is not blocked.
    const other = (await upload('B', 'url\nhttps://example.com/3')).json();
    expect((await call('B', 'POST', `/api/v1/bulk/imports/dry-run/${other.id}/commit`)).statusCode).toBe(202);
    await runImport(started.json().id);
    expect((await call('A', 'POST', `/api/v1/bulk/imports/dry-run/${second.id}/commit`, undefined, { as: 'ADMIN' })).statusCode).toBe(202);
  });

  it('does not run for a member removed after starting it', async () => {
    const dry = (await upload('A', 'url\nhttps://example.com/a', { as: 'MEMBER' })).json();
    const commit = await call('A', 'POST', `/api/v1/bulk/imports/dry-run/${dry.id}/commit`, undefined, { as: 'MEMBER' });
    await db.membership.deleteMany({ where: { userId: orgs.A.users.MEMBER } });
    const job = await runImport(commit.json().id);
    expect(job).toMatchObject({ status: 'FAILED', succeeded: 0, error: 'The member or API key that started the job no longer has access.' });
    expect(await db.qRCode.count()).toBe(0);
    expect((await audits('A', 'bulk.finish'))[0].metadata).toMatchObject({ status: 'FAILED' });
  });

  it('fails the job (with bulk.finish) and answers 503 when it cannot be queued', async () => {
    const dry = (await upload('A', 'url\nhttps://example.com/a')).json();
    stubs.failEnqueue = true;
    const res = await call('A', 'POST', `/api/v1/bulk/imports/dry-run/${dry.id}/commit`);
    expect(res.statusCode).toBe(503);
    expect(await db.bulkJob.findFirst()).toMatchObject({ status: 'FAILED', error: 'The job could not be queued.' });
  });

  it('still starts the job when the committed dry run cannot be deleted from the cache', async () => {
    const dry = (await upload('A', 'url\nhttps://example.com/a')).json();
    stubs.failCacheDel = true;
    const res = await call('A', 'POST', `/api/v1/bulk/imports/dry-run/${dry.id}/commit`);
    expect(res.statusCode).toBe(202);
    expect(stubs.enqueued).toEqual([{ kind: 'IMPORT', id: res.json().id }]);
  });

  it('works with an API key, attributed to the key', async () => {
    const job = await importCsv('A', 'url\nhttps://example.com/k', { key: true });
    expect(job.status).toBe('SUCCEEDED');
    expect((await audits('A', 'bulk.start'))[0]).toMatchObject({ actorType: 'API_KEY', actorId: orgs.A.apiKeyId });
    expect(await db.qRCodeRevision.findFirst()).toMatchObject({ actorType: 'API_KEY', actorApiKeyId: orgs.A.apiKeyId });
  });

  it('results CSV: formula labels stay text in the database and are neutralised in the CSV; only the starter can read it', async () => {
    const job = await importCsv('A', 'url,label\nhttps://example.com/x,"=HYPERLINK(""http://evil.test"",""click"")"\nhttps://example.com/y,@SUM(1)');
    const stored = await db.qRCode.findMany({ select: { label: true }, orderBy: { label: 'asc' } });
    expect(stored.map((c) => c.label)).toEqual(['=HYPERLINK("http://evil.test","click")', '@SUM(1)']);
    const res = await call('A', 'GET', `/api/v1/bulk/imports/${job.id}/results.csv`);
    expect(res.headers['content-type']).toContain('text/csv');
    expect(res.body.startsWith('\uFEFFrow,status,token,verifyUrl,url,label,error\r\n')).toBe(true);
    expect(res.body).toContain(`"'=HYPERLINK(""http://evil.test"",""click"")"`);
    expect(res.body).toContain(",'@SUM(1),");
    expect((await call('A', 'GET', `/api/v1/bulk/imports/${job.id}/results.csv`, undefined, { as: 'ADMIN' })).statusCode).toBe(404);
    expect((await call('B', 'GET', `/api/v1/bulk/imports/${job.id}/results.csv`)).statusCode).toBe(404);
    expect((await call('B', 'GET', `/api/v1/bulk/jobs/${job.id}`)).statusCode).toBe(404);
  });
});

describe('validateDrafts quota', () => {
  it('refuses rows past the plan quota, counted over the whole file', async () => {
    const { validateDrafts } = await import('../../src/services/bulk-import.js');
    const { DomainService } = await import('../../src/services/domain.js');
    const usage = { getLimits: () => ({ qrcodes: 5 }) as never, current: async () => 3, checkQuota: async () => null };
    const drafts = [1, 2, 3].map((i) => ({ draft: { row: i + 1, url: `https://example.com/${i}`, label: null, folder: null, tags: [], expiresAt: null, scanMode: null } }));
    const { rows } = await validateDrafts({ prisma: db, domainService: new DomainService(db, app.log), usage }, orgs.A.id, 'FREE', drafts);
    expect(rows.map((r) => r.issues.map((i) => i.code))).toEqual([[], [], ['quota-exceeded']]);
  });
});

describe('ZIP export', () => {
  async function exportJob(org: OrgName, body: unknown, opts: CallOpts = {}) {
    const res = await call(org, 'POST', '/api/v1/bulk/exports', body, opts);
    expect(res.statusCode, res.body).toBe(202);
    return runExport(res.json().id);
  }

  it('exports an import\'s codes as SVG and PNG with a manifest, downloadable once by link', async () => {
    const imported = await importCsv('A', 'url,label\nhttps://example.com/1,"../../etc/passwd"\nhttps://example.com/2,"=cmd|\' /C calc\'!A0"\nhttps://example.com/3,Καφές');
    const job = await exportJob('A', { selection: { importJobId: imported.id }, formats: ['svg', 'png'], png: { px: 256 } });
    expect(job).toMatchObject({ status: 'SUCCEEDED', succeeded: 3, failed: 0, total: 3 });
    expect(job.filePath).toBe(join(exportDir, `${job.id}.zip`));
    expect(existsSync(`${job.filePath}.part`)).toBe(false);

    const files = unzipSync(readFileSync(job.filePath!));
    const names = Object.keys(files).sort();
    expect(names).toHaveLength(7);
    expect(names).toContain('manifest.csv');
    expect(names.every((n) => !n.includes('/') && !n.includes('\\') && !n.startsWith('.'))).toBe(true);
    expect(names.some((n) => n.startsWith('Καφές_') && n.endsWith('.svg'))).toBe(true);
    expect(names.some((n) => n.startsWith('etc-passwd_'))).toBe(true);
    const png = files[names.find((n) => n.endsWith('.png'))!];
    expect([...png.subarray(1, 4)]).toEqual([0x50, 0x4e, 0x47]);
    expect([...files['manifest.csv'].subarray(0, 3)]).toEqual([0xef, 0xbb, 0xbf]);
    const manifest = strFromU8(files['manifest.csv']);
    expect(manifest.startsWith('file,format,token,label,destination,verifyUrl,status,note\r\n')).toBe(true);
    expect(manifest).toContain(`'=cmd|`);
    expect((await audits('A', 'bulk.finish')).at(-1)!.metadata).toMatchObject({ kind: 'EXPORT', status: 'SUCCEEDED', succeeded: 3 });

    // Link: only for its starter; the download needs the signature.
    expect((await call('A', 'POST', `/api/v1/bulk/exports/${job.id}/link`, undefined, { as: 'ADMIN' })).statusCode).toBe(404);
    expect((await call('B', 'POST', `/api/v1/bulk/exports/${job.id}/link`)).statusCode).toBe(404);
    const link = await call('A', 'POST', `/api/v1/bulk/exports/${job.id}/link`);
    expect(link.statusCode).toBe(200);
    const path = new URL(link.json().url).pathname + new URL(link.json().url).search;
    const download = await app.inject({ method: 'GET', url: path });
    expect(download.statusCode).toBe(200);
    expect(download.headers['content-type']).toBe('application/zip');
    expect(download.rawPayload.equals(readFileSync(job.filePath!))).toBe(true);
    const tampered = path.replace(/sig=([A-Za-z0-9_-])/, (_m, c: string) => `sig=${c === 'A' ? 'B' : 'A'}`);
    expect((await app.inject({ method: 'GET', url: tampered })).json()).toMatchObject({ statusCode: 403, code: 'link-invalid' });
    const expired = path.replace(/expires=\d+/, `expires=${Math.floor(Date.now() / 1000) - 1}`);
    expect((await app.inject({ method: 'GET', url: expired })).statusCode).toBe(403);
  });

  it('a link signed for one export does not open another', async () => {
    await importCsv('A', 'url\nhttps://example.com/1');
    const tokens = (await db.qRCode.findMany({ select: { token: true } })).map((c) => c.token);
    const one = await exportJob('A', { selection: { tokens }, formats: ['svg'] });
    const two = await exportJob('A', { selection: { tokens }, formats: ['svg'] });
    const link = (await call('A', 'POST', `/api/v1/bulk/exports/${one.id}/link`)).json().url as string;
    const forged = new URL(link).pathname.replace(one.id, two.id) + new URL(link).search;
    expect((await app.inject({ method: 'GET', url: forged })).statusCode).toBe(403);
  });

  it('selects by list filter within the organization only, and refuses other organizations\' tokens', async () => {
    await importCsv('A', 'url,folder\nhttps://example.com/1,Menus\nhttps://example.com/2,');
    await importCsv('B', 'url\nhttps://example.com/b');
    const folder = await db.qRFolder.findFirstOrThrow({ where: { organizationId: orgs.A.id } });
    const job = await exportJob('A', { selection: { filter: { folderId: folder.id } }, formats: ['svg'] });
    expect(job.total).toBe(1);
    const bTokens = (await db.qRCode.findMany({ where: { organizationId: orgs.B.id }, select: { token: true } })).map((c) => c.token);
    expect((await call('A', 'POST', '/api/v1/bulk/exports', { selection: { tokens: bTokens }, formats: ['svg'] })).json()).toMatchObject({ statusCode: 422, code: 'export-empty' });
    const bFolder = await db.qRFolder.create({ data: { organizationId: orgs.B.id, name: 'B only' } });
    expect((await call('A', 'POST', '/api/v1/bulk/exports', { selection: { filter: { folderId: bFolder.id } }, formats: ['svg'] })).statusCode).toBe(404);
    const bImport = await db.bulkJob.findFirstOrThrow({ where: { organizationId: orgs.B.id } });
    expect((await call('A', 'POST', '/api/v1/bulk/exports', { selection: { importJobId: bImport.id }, formats: ['svg'] })).statusCode).toBe(404);
  });

  it('is gated by plan, allows VIEWER, and validates sizes', async () => {
    expect((await call('PRO', 'POST', '/api/v1/bulk/exports', { selection: { tokens: ['x'] }, formats: ['svg'] })).json()).toMatchObject({ code: 'governance-plan-required' });
    expect((await call('A', 'POST', '/api/v1/bulk/exports', { selection: { tokens: ['x'] }, formats: ['svg'] }, { as: 'VIEWER' })).json()).toMatchObject({ code: 'export-empty' });
    expect((await call('A', 'POST', '/api/v1/bulk/exports', { selection: { tokens: ['x'] }, formats: ['png'] })).statusCode).toBe(400);
    expect((await call('A', 'POST', '/api/v1/bulk/exports', { selection: { tokens: ['x'] }, formats: ['png'], png: { sizeMm: 500, dpi: 600 } })).statusCode).toBe(400);
    const tooMany = Array.from({ length: 1001 }, (_, i) => `t${i}`);
    expect((await call('A', 'POST', '/api/v1/bulk/exports', { selection: { tokens: tooMany }, formats: ['svg'] })).statusCode).toBe(400);
  });
});

describe('export failures', () => {
  it('fails the job (not left RUNNING) when the export directory cannot be created', async () => {
    const { config } = await import('../../src/lib/config.js');
    await importCsv('A', 'url\nhttps://example.com/1');
    const tokens = (await db.qRCode.findMany({ select: { token: true } })).map((c) => c.token);
    const res = await call('A', 'POST', '/api/v1/bulk/exports', { selection: { tokens }, formats: ['svg'] });
    const original = config.bulk.exportDir;
    const blocker = join(exportDir, 'not-a-dir');
    writeFileSync(blocker, 'x');
    (config.bulk as { exportDir: string }).exportDir = join(blocker, 'exports');
    try {
      const job = await runExport(res.json().id);
      expect(job).toMatchObject({ status: 'FAILED', error: 'The export stopped because of an internal error.' });
    } finally {
      (config.bulk as { exportDir: string }).exportDir = original;
    }
  });
});

describe('cleanup sweep', () => {
  it('fails interrupted jobs, deletes ended jobs and their ZIP after 24 h, and removes orphan files', async () => {
    const { sweepBulkJobs } = await import('../../src/services/bulk-cleanup.js');
    const imported = await importCsv('A', 'url\nhttps://example.com/1');
    const exported = await runExport((await call('A', 'POST', '/api/v1/bulk/exports', { selection: { importJobId: imported.id }, formats: ['svg'] })).json().id);
    expect(existsSync(exported.filePath!)).toBe(true);

    const dry = (await upload('B', 'url\nhttps://example.com/b')).json();
    const stuck = (await call('B', 'POST', `/api/v1/bulk/imports/dry-run/${dry.id}/commit`)).json();
    await db.bulkJob.update({ where: { id: stuck.id }, data: { status: 'RUNNING' } });
    await db.$executeRaw`UPDATE "bulk_jobs" SET "updatedAt" = now() - interval '20 minutes' WHERE "id" = ${stuck.id}`;

    const orphan = join(exportDir, 'zzzorphan1.zip');
    writeFileSync(orphan, 'x');
    utimesSync(orphan, new Date(Date.now() - 25 * 3600 * 1000), new Date(Date.now() - 25 * 3600 * 1000));

    // Now: the stuck job is failed; nothing has ended 24 h ago yet.
    expect(await sweepBulkJobs(db)).toEqual({ interrupted: 1, deleted: 0, orphanFiles: 1 });
    expect(existsSync(orphan)).toBe(false);
    expect(existsSync(exported.filePath!)).toBe(true);
    expect(await db.bulkJob.findUnique({ where: { id: stuck.id } })).toMatchObject({ status: 'FAILED', error: 'The job was interrupted; start it again.' });
    expect((await audits('B', 'bulk.finish'))[0].metadata).toMatchObject({ status: 'FAILED', interrupted: true });

    // A day later every ended job goes, with its ZIP; the audit trail stays.
    expect(await sweepBulkJobs(db, new Date(Date.now() + 25 * 3600 * 1000))).toEqual({ interrupted: 0, deleted: 3, orphanFiles: 0 });
    expect(existsSync(exported.filePath!)).toBe(false);
    expect(await db.bulkJob.count()).toBe(0);
    expect(await audits('A', 'bulk.start')).toHaveLength(2);
  });
});
