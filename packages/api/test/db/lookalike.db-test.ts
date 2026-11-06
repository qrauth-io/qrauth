/**
 * Lookalike detection against a real Postgres (ADR-0007): the protected set
 * is read from verified organizations, their active destinations and the
 * curated list; the daily re-scan records one HIGH fraud incident per code,
 * URL and protected domain (the JSON-path de-duplication runs in Postgres).
 * Run by scripts/ci-verify.sh `db`.
 */
import { PrismaClient } from '@prisma/client';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';

const url = process.env.TEST_DATABASE_URL;
if (!url) throw new Error('TEST_DATABASE_URL is not set');
if (!/test/i.test(new URL(url).pathname)) throw new Error('TEST_DATABASE_URL must name a test database (the suite truncates tables)');

process.env.DATABASE_URL ??= url;
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'db-test-only-throwaway-secret-0000000000';

vi.mock('../../src/lib/queue.js', () => ({ webRiskQueue: { add: vi.fn() }, createQueueConnection: vi.fn() }));
vi.mock('../../src/lib/cache.js', () => ({ redis: {}, cacheGet: vi.fn(), cacheSet: vi.fn(), cacheDel: vi.fn(async () => undefined) }));

const db = new PrismaClient({ datasources: { db: { url } } });
const log = { info: vi.fn(), warn: vi.fn() } as never;

afterAll(async () => {
  await db.$disconnect();
});

let issuer: { id: string; keyId: string };
let acme: { id: string; keyId: string };

async function code(org: { id: string; keyId: string }, token: string, data: Record<string, unknown>) {
  return db.qRCode.create({ data: { token, organizationId: org.id, signingKeyId: org.keyId, signature: 's', algVersion: 'test', destinationUrl: 'https://placeholder.example/', ...data } });
}

beforeEach(async () => {
  const { DomainService } = await import('../../src/services/domain.js');
  DomainService.clearCaches(db);
  await db.$executeRawUnsafe('TRUNCATE "organizations", "users" CASCADE');
  const make = async (name: string, extra: Record<string, unknown>) => {
    const o = await db.organization.create({ data: { name, slug: `${name.toLowerCase().replace(/\W+/g, '-')}-lookalike-test`, email: `${name.length}${Math.random()}@lookalike.test`, ...extra } });
    const key = await db.signingKey.create({ data: { organizationId: o.id, publicKey: 'pk', keyId: `key-${o.id}` } });
    return { id: o.id, keyId: key.id };
  };
  issuer = await make('Issuer', {});
  acme = await make('Acme Bank', { domain: 'acme-bank.gr', domainVerified: true });
});

describe('protected set from the database and the curated list', () => {
  it('flags confusables of a verified organization and of curated brands; not the organization itself', async () => {
    const { DomainService } = await import('../../src/services/domain.js');
    const svc = new DomainService(db);

    expect((await svc.checkUrlAgainstVerifiedDomains('https://acrne-bank.gr/login', issuer.id)).warnings[0]).toMatchObject({ domain: 'acme-bank.gr', verifiedOrgName: 'Acme Bank', reason: 'confusable' });
    expect((await svc.checkUrlAgainstVerifiedDomains('https://xn--80aa0cbo65f.com/', issuer.id)).warnings[0]).toMatchObject({ domain: 'paypal.com', verifiedOrgName: 'PayPal' });
    expect((await svc.checkUrlAgainstVerifiedDomains('https://acme-bank.gr/', acme.id)).isSuspicious).toBe(false);
    expect((await svc.checkUrlAgainstVerifiedDomains('https://ebank.acme-bank.gr/', issuer.id)).isSuspicious).toBe(false);
    expect((await svc.checkUrlAgainstVerifiedDomains('https://ουτοπία.δπθ.gr/', issuer.id)).isSuspicious).toBe(false);
  });

  it("a verified organization's active destination is protected too", async () => {
    await code(acme, 'acme1', { destinationUrl: 'https://acme-loyalty.example/card' });
    const { DomainService } = await import('../../src/services/domain.js');
    const check = await new DomainService(db).checkUrlAgainstVerifiedDomains('https://acrne-loyalty.example/', issuer.id);
    expect(check.warnings[0]).toMatchObject({ domain: 'acme-loyalty.example', verifiedOrgName: 'Acme Bank' });
  });
});

describe('daily re-scan', () => {
  it('records one HIGH incident per lookalike URL or link, and none on the next run', async () => {
    const bad = await code(issuer, 'bad1', { destinationUrl: 'https://acrne-bank.gr/login' });
    const idn = await code(issuer, 'idn1', { destinationUrl: 'https://xn--80aa0cbo65f.com/' });
    await code(issuer, 'ok1', { destinationUrl: 'https://example.com/menu' });
    await code(acme, 'own1', { destinationUrl: 'https://acme-bank.gr/' });
    const list = await code(issuer, 'list1', {
      contentType: 'link-list',
      content: { title: 'Links', links: [{ label: 'Menu', url: 'https://example.com/menu' }, { label: 'Sign in', url: 'https://xn--ggle-0nda.com/' }] },
    });

    const { runDailyScan } = await import('../../src/workers/web-risk.js');
    const { DomainService } = await import('../../src/services/domain.js');
    const domains = new DomainService(db);
    const deps = {
      lookup: async () => ({ verdict: 'clean' as const }),
      sleep: async () => undefined,
      now: () => new Date(),
      lookalike: (u: string, org: string) => domains.checkUrlAgainstVerifiedDomains(u, org),
    };

    const first = await runDailyScan(db, log, deps);
    const second = await runDailyScan(db, log, deps);

    expect(first.lookalikes).toBe(3);
    expect(second.lookalikes).toBe(0);
    const incidents = await db.fraudIncident.findMany({ orderBy: { createdAt: 'asc' } });
    expect(incidents.map((i) => i.qrCodeId).sort()).toEqual([bad.id, idn.id, list.id].sort());
    expect(incidents.every((i) => i.severity === 'HIGH' && i.type === 'MANUAL_REPORT')).toBe(true);
    expect(incidents.find((i) => i.qrCodeId === list.id)?.details).toMatchObject({
      reason: 'suspicious_domain',
      source: 'daily_rescan',
      url: 'https://xn--ggle-0nda.com/',
      // The brand match, not the mixed-script one, is the incident's warning (D11).
      similarTo: 'google.com',
      lookalikeReason: 'confusable',
    });
  });
});

describe('recordLookalikeIncident (re-review 7)', () => {
  const warning = { domain: 'acme-bank.gr', verifiedOrgName: 'Acme Bank', similarity: 95, reason: 'homoglyph_match', source: 'verified' as const };

  it('an earlier incident recorded by host, with or without www., is the same incident', async () => {
    const { recordLookalikeIncident } = await import('../../src/services/lookalike-incidents.js');
    const a = await code(issuer, 'old1', { destinationUrl: 'https://www.acrne-bank.gr/login' });
    const b = await code(issuer, 'old2', { destinationUrl: 'https://acrne-bank.gr/login' });
    // Written before url and dedupeKey existed.
    await db.fraudIncident.create({ data: { qrCodeId: a.id, type: 'MANUAL_REPORT', severity: 'HIGH', details: { reason: 'suspicious_domain', destinationDomain: 'acrne-bank.gr', similarTo: 'acme-bank.gr' } } });
    await db.fraudIncident.create({ data: { qrCodeId: b.id, type: 'MANUAL_REPORT', severity: 'HIGH', details: { reason: 'suspicious_domain', destinationDomain: 'www.acrne-bank.gr', similarTo: 'acme-bank.gr' } } });

    expect(await recordLookalikeIncident(db, a.id, 'https://www.acrne-bank.gr/login', warning, 'daily_rescan')).toBe(false);
    expect(await recordLookalikeIncident(db, b.id, 'https://acrne-bank.gr/login', warning, 'daily_rescan')).toBe(false);
    expect(await db.fraudIncident.count()).toBe(2);
  });

  it('concurrent writers record one incident (unique per code and dedupeKey)', async () => {
    const { recordLookalikeIncident } = await import('../../src/services/lookalike-incidents.js');
    const c = await code(issuer, 'race1', { destinationUrl: 'https://www.acrne-bank.gr/' });
    const results = await Promise.all(
      Array.from({ length: 5 }, () => recordLookalikeIncident(db, c.id, 'https://www.acrne-bank.gr/', warning, 'create')),
    );
    expect(results.filter(Boolean)).toHaveLength(1);
    const incidents = await db.fraudIncident.findMany({ where: { qrCodeId: c.id } });
    expect(incidents).toHaveLength(1);
    expect(incidents[0].details).toMatchObject({ destinationDomain: 'acrne-bank.gr', url: 'https://www.acrne-bank.gr/' });
  });
});
