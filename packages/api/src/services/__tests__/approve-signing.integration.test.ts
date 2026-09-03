import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { PrismaClient } from '@prisma/client';
import { randomBytes } from 'node:crypto';

// Keep the test hermetic to Postgres — stub the Redis-backed cache.
vi.mock('../../lib/cache.js', () => ({
  cacheGet: vi.fn(async () => null),
  cacheSet: vi.fn(async () => undefined),
  cacheDel: vi.fn(async () => undefined),
}));

import { AuthSessionService, SigningUnavailableError } from '../auth-session.js';

/**
 * Integration test against a REAL PrismaClient (not a fake) — this is the gap
 * that let the keyless-platform-org 503 through: PR2's fake never modelled the
 * `signingKey.findFirst` lookup. Here approveSession runs the actual lookup
 * against a real database.
 *
 * Skips cleanly when no migrated database is reachable (the API vitest suite is
 * local-only; CI does not provision Postgres for it). Run locally with
 * DATABASE_URL pointing at a `prisma migrate deploy`-ed database.
 */
const nonce = randomBytes(4).toString('hex');
let prisma: PrismaClient | null = null;
let dbAvailable = false;

// A signer that must never be invoked on the paths under test (CLI skips
// signing; the keyless federation case throws before signing).
const noSign = { signCanonical: vi.fn(async () => { throw new Error('signer must not be called'); }) };

const created = { sessions: [] as string[], apps: [] as string[], orgs: [] as string[], users: [] as string[] };

beforeAll(async () => {
  try {
    prisma = new PrismaClient();
    await prisma.$queryRaw`SELECT 1`;
    // The qrauth-cli app must be migration-provisioned for the CLI case.
    const cliApp = await prisma.app.findUnique({ where: { slug: 'qrauth-cli' } });
    dbAvailable = !!cliApp;
  } catch {
    dbAvailable = false;
  }
});

afterAll(async () => {
  if (!prisma) return;
  if (created.sessions.length) await prisma.authSession.deleteMany({ where: { id: { in: created.sessions } } });
  if (created.apps.length) await prisma.app.deleteMany({ where: { id: { in: created.apps } } });
  if (created.users.length) await prisma.user.deleteMany({ where: { id: { in: created.users } } });
  if (created.orgs.length) await prisma.organization.deleteMany({ where: { id: { in: created.orgs } } });
  await prisma.$disconnect();
});

async function makeUser(db: PrismaClient): Promise<string> {
  const user = await db.user.create({
    data: { name: 'IT User', email: `it-${nonce}-${created.users.length}@example.com`, passwordHash: 'x', provider: 'EMAIL' },
  });
  created.users.push(user.id);
  return user.id;
}

async function makeSession(db: PrismaClient, appId: string): Promise<string> {
  const session = await db.authSession.create({
    data: {
      appId,
      token: `it_${nonce}_${created.sessions.length}_${randomBytes(8).toString('hex')}`,
      status: 'PENDING',
      scopes: ['cli'],
      codeChallenge: 'challenge',
      expiresAt: new Date(Date.now() + 5 * 60_000),
    },
  });
  created.sessions.push(session.id);
  return session.id;
}

describe('approveSession (real DB) — ADR-0002 §7 keyless platform org', () => {
  it('CLI approve against the keyless QRAuth Platform org returns APPROVED with null signature (no 503)', async (ctx) => {
    if (!dbAvailable || !prisma) return ctx.skip();

    const cliApp = await prisma.app.findUniqueOrThrow({ where: { slug: 'qrauth-cli' } });
    // Prove the premise: the qrauth-cli app's owning org has no active key.
    const platformKey = await prisma.signingKey.findFirst({
      where: { organizationId: cliApp.organizationId, status: 'ACTIVE' },
    });
    expect(platformKey).toBeNull();

    const userId = await makeUser(prisma);
    const sessionId = await makeSession(prisma, cliApp.id);

    const service = new AuthSessionService(prisma, noSign as any);
    const result = await service.approveSession(sessionId, userId, undefined, undefined, cliApp.organizationId);

    expect(result.status).toBe('APPROVED');
    expect(result.signature).toBeNull();
    expect(noSign.signCanonical).not.toHaveBeenCalled();

    const persisted = await prisma.authSession.findUniqueOrThrow({ where: { id: sessionId } });
    expect(persisted.status).toBe('APPROVED');
    expect(persisted.signature).toBeNull();
    expect(persisted.targetOrganizationId).toBe(cliApp.organizationId);
  });

  it('a federation (non-cli) app with no active key still fails closed (503/SigningUnavailableError)', async (ctx) => {
    if (!dbAvailable || !prisma) return ctx.skip();

    const org = await prisma.organization.create({
      data: { name: `IT Fed ${nonce}`, slug: `it-fed-${nonce}`, email: `it-fed-${nonce}@example.com` },
    });
    created.orgs.push(org.id);
    const app = await prisma.app.create({
      data: {
        organizationId: org.id,
        name: 'IT Fed App',
        slug: `it-fed-app-${nonce}`,
        clientId: `it-fed-client-${nonce}`,
        clientSecretHash: 'x',
        redirectUrls: [],
        allowedScopes: ['identity'],
      },
    });
    created.apps.push(app.id);
    const userId = await makeUser(prisma);
    const sessionId = await makeSession(prisma, app.id);

    const service = new AuthSessionService(prisma, noSign as any);
    await expect(service.approveSession(sessionId, userId)).rejects.toBeInstanceOf(SigningUnavailableError);
  });
});
