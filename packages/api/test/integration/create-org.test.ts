import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomBytes } from 'node:crypto';
import { PrismaClient } from '@prisma/client';

/**
 * scripts/create-org.ts: an additional organization for an existing user.
 * Argument tests are pure. The rest run against a REAL migrated Postgres and
 * skip cleanly without one (CI's API unit-test job has no database).
 */

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

import {
  parseCliArgs,
  slugFromName,
  createOrganization,
  CreateOrgError,
  type CreateOrgDeps,
  type CreateOrgOptions,
} from '../../scripts/create-org.js';

describe('parseCliArgs', () => {
  it('lowercases the owner email and derives the slug like signup', () => {
    expect(parseCliArgs(['--name', 'PerforMax Pilot', '--owner-email', ' Aris@ProgressNet.gr '])).toEqual({
      name: 'PerforMax Pilot',
      ownerEmail: 'aris@progressnet.gr',
      orgEmail: 'aris@progressnet.gr',
      slug: 'performax-pilot',
      dryRun: false,
    });
  });

  it('accepts a separate org email (lowercased)', () => {
    expect(parseCliArgs(['--name', 'X Org', '--owner-email', 'a@b.co', '--org-email', 'A+Pilot@B.co']).orgEmail).toBe('a+pilot@b.co');
  });

  it('accepts an explicit slug and --dry-run', () => {
    const opts = parseCliArgs(['--name', 'X Org', '--owner-email', 'a@b.co', '--slug', 'x-org-2', '--dry-run']);
    expect(opts.slug).toBe('x-org-2');
    expect(opts.dryRun).toBe(true);
  });

  it.each([
    [['--owner-email', 'a@b.co'], /required/],
    [['--name', 'X Org'], /required/],
    [['--name', 'X', '--owner-email', 'a@b.co'], /organization name/],
    [['--name', 'X Org', '--owner-email', 'not-an-email'], /valid email/],
    [['--name', 'X Org', '--owner-email', 'a@b.co', '--slug', 'Bad Slug'], /--slug/],
    [['--name', 'X Org', '--owner-email', 'a@b.co', '--org-email', 'nope'], /--org-email/],
    [['--name', 'X Org', '--owner-email', 'a@b.co', '--bogus'], /bogus/],
  ])('rejects bad input %j', (argv, message) => {
    expect(() => parseCliArgs(argv as string[])).toThrow(CreateOrgError);
    expect(() => parseCliArgs(argv as string[])).toThrow(message);
  });

  it('derives slugs the same way as POST /signup', () => {
    expect(slugFromName('  PerforMax  Pilot!! ')).toBe('performax-pilot');
  });
});

const nonce = randomBytes(4).toString('hex');
let prisma: PrismaClient | null = null;
let dbAvailable = false;
let ownerEmail = '';

function fakeDeps(overrides: Partial<CreateOrgDeps> = {}) {
  const calls = { keyFor: [] as string[], audit: [] as unknown[] };
  const deps: CreateOrgDeps = {
    createKeyPair: async (organizationId) => {
      calls.keyFor.push(organizationId);
      return { keyId: `key-${nonce}` };
    },
    audit: async (entry) => {
      calls.audit.push(entry);
    },
    ...overrides,
  };
  return { deps, calls };
}

function opts(overrides: Partial<CreateOrgOptions> = {}): CreateOrgOptions {
  const suffix = randomBytes(2).toString('hex');
  const name = `Pilot ${nonce} ${suffix}`;
  return { name, ownerEmail, orgEmail: `owner-${nonce}+${suffix}@example.com`, slug: slugFromName(name), dryRun: false, ...overrides };
}

beforeAll(async () => {
  try {
    prisma = new PrismaClient();
    await prisma.$queryRaw`SELECT 1`;
    await prisma.user.count();
    dbAvailable = true;
  } catch {
    dbAvailable = false;
    return;
  }
  ownerEmail = `owner-${nonce}@example.com`;
  await prisma.user.create({ data: { name: 'Owner', email: ownerEmail, passwordHash: 'N:salt:key', emailVerified: true } });
  // A user whose address a `_` wildcard would match if the lookup used ILIKE alone.
  await prisma.user.create({ data: { name: 'Other', email: `jxhn-${nonce}@example.com`, passwordHash: 'N:salt:key' } });
});

afterAll(async () => {
  if (!prisma) return;
  if (dbAvailable) {
    const orgs = await prisma.organization.findMany({ where: { slug: { contains: nonce } }, select: { id: true } });
    await prisma.organization.deleteMany({ where: { id: { in: orgs.map((o) => o.id) } } });
    await prisma.user.deleteMany({ where: { email: { contains: nonce } } });
  }
  await prisma.$disconnect().catch(() => undefined);
});

describe('createOrganization (real DB)', () => {
  it('creates the org with the owner as OWNER, then the signing key and the audit row', async (ctx) => {
    if (!dbAvailable || !prisma) return ctx.skip();
    const { deps, calls } = fakeDeps();
    const o = opts();

    const result = await createOrganization(prisma, o, deps);

    expect(result).toMatchObject({ dryRun: false, name: o.name, slug: o.slug, signingKeyId: `key-${nonce}`, warnings: [] });
    const org = await prisma.organization.findUniqueOrThrow({
      where: { id: result.organizationId! },
      select: { name: true, slug: true, email: true, memberships: { select: { role: true, user: { select: { email: true } } } } },
    });
    expect(org).toEqual({ name: o.name, slug: o.slug, email: o.orgEmail, memberships: [{ role: 'OWNER', user: { email: ownerEmail } }] });
    expect(calls.keyFor).toEqual([result.organizationId]);
    expect(calls.audit).toEqual([
      expect.objectContaining({ action: 'organization.created_by_operator', resourceId: result.organizationId }),
    ]);
  });

  it('writes nothing on --dry-run', async (ctx) => {
    if (!dbAvailable || !prisma) return ctx.skip();
    const { deps, calls } = fakeDeps();
    const o = opts({ dryRun: true });

    const result = await createOrganization(prisma, o, deps);

    expect(result.dryRun).toBe(true);
    expect(result.organizationId).toBeNull();
    expect(await prisma.organization.count({ where: { slug: o.slug } })).toBe(0);
    expect(calls.keyFor).toEqual([]);
  });

  it('refuses an owner email that matches no user', async (ctx) => {
    if (!dbAvailable || !prisma) return ctx.skip();
    await expect(createOrganization(prisma, opts({ ownerEmail: `nobody-${nonce}@example.com` }), fakeDeps().deps))
      .rejects.toThrow(/No user with email/);
  });

  it('never lets a _ in the email match a different user', async (ctx) => {
    if (!dbAvailable || !prisma) return ctx.skip();
    await expect(createOrganization(prisma, opts({ ownerEmail: `j_hn-${nonce}@example.com` }), fakeDeps().deps))
      .rejects.toThrow(/No user with email/);
  });

  it('refuses a slug that is already taken', async (ctx) => {
    if (!dbAvailable || !prisma) return ctx.skip();
    const first = opts();
    await createOrganization(prisma, first, fakeDeps().deps);

    await expect(createOrganization(prisma, opts({ slug: first.slug }), fakeDeps().deps)).rejects.toThrow(/already taken/);
  });

  it('refuses an org email another organization already uses (organizations.email is unique)', async (ctx) => {
    if (!dbAvailable || !prisma) return ctx.skip();
    const first = opts();
    await createOrganization(prisma, first, fakeDeps().deps);

    await expect(createOrganization(prisma, opts({ orgEmail: first.orgEmail }), fakeDeps().deps))
      .rejects.toThrow(/already used by organization/);
  });

  it('refuses a second org with the same name for the same owner', async (ctx) => {
    if (!dbAvailable || !prisma) return ctx.skip();
    const first = opts();
    await createOrganization(prisma, first, fakeDeps().deps);

    await expect(
      createOrganization(prisma, opts({ name: first.name.toUpperCase(), slug: `${first.slug}-again` }), fakeDeps().deps),
    ).rejects.toThrow(/already owns an organization named/);
  });

  it('keeps the org and reports a warning when the signing key fails', async (ctx) => {
    if (!dbAvailable || !prisma) return ctx.skip();
    const { deps } = fakeDeps({
      createKeyPair: async () => {
        throw new Error('signer unreachable');
      },
    });

    const result = await createOrganization(prisma, opts(), deps);

    expect(result.organizationId).not.toBeNull();
    expect(result.signingKeyId).toBeNull();
    expect(result.warnings).toEqual([expect.stringContaining('signing key NOT created: signer unreachable')]);
  });
});
