import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * "Connected apps" (audit 2026-10 FINDING-002): a signed-in user lists the
 * OIDC clients they consented to and revokes one. Real route plugin, stubbed
 * authenticate, in-memory Prisma stand-in.
 */

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);

interface ConsentRow {
  id: string;
  userId: string;
  oidcClientId: string;
  grantedScopes: string[];
  grantedAt: Date;
  revokedAt: Date | null;
}
interface TokenRow { userId: string; oidcClientId: string; revokedAt: Date | null }

const CLIENTS: Record<string, { name: string; organization: { name: string } }> = {
  client_a: { name: 'Example Shop', organization: { name: 'Example Ltd' } },
  client_b: { name: 'Other App', organization: { name: 'Other Org' } },
};

let consents: ConsentRow[] = [];
let refreshTokens: TokenRow[] = [];
let accessTokens: TokenRow[] = [];
let authCodes: Array<{ userId: string; oidcClientId: string; usedAt: Date | null }> = [];
let auditLogs: Array<Record<string, any>> = [];
let principal = { id: 'user_1', orgId: 'org_1', role: 'MEMBER', email: 'person@example.com' };

const revokeMatching = (rows: TokenRow[]) => async ({ where, data }: any) => {
  const hit = rows.filter(
    (t) => t.userId === where.userId && t.oidcClientId === where.oidcClientId && t.revokedAt === null,
  );
  hit.forEach((t) => { t.revokedAt = data.revokedAt; });
  return { count: hit.length };
};

const prisma: Record<string, any> = {
  oidcConsent: {
    findMany: async ({ where }: any) =>
      consents
        .filter((c) => c.userId === where.userId && c.revokedAt === null)
        .map((c) => ({ ...c, client: CLIENTS[c.oidcClientId] })),
    findFirst: async ({ where }: any) =>
      consents.find((c) => c.id === where.id && c.userId === where.userId && c.revokedAt === null) ?? null,
    update: async ({ where, data }: any) => {
      const row = consents.find((c) => c.id === where.id)!;
      Object.assign(row, data);
      return row;
    },
  },
  oidcRefreshToken: { updateMany: (args: any) => revokeMatching(refreshTokens)(args) },
  oidcAccessToken: { updateMany: (args: any) => revokeMatching(accessTokens)(args) },
  oidcAuthCode: {
    updateMany: async ({ where, data }: any) => {
      const hit = authCodes.filter(
        (c) => c.userId === where.userId && c.oidcClientId === where.oidcClientId && c.usedAt === null,
      );
      hit.forEach((c) => { c.usedAt = data.usedAt; });
      return { count: hit.length };
    },
  },
  auditLog: {
    create: async ({ data }: any) => {
      auditLogs.push(data);
      return data;
    },
  },
  $transaction: async (fn: (tx: unknown) => Promise<unknown>) => fn(prisma),
};

let app: FastifyInstance;

beforeAll(async () => {
  app = Fastify({ logger: false });
  app.decorate('prisma', prisma as never);
  app.decorate('authenticate', async (request: any) => {
    request.user = principal;
  });
  const { default: oidcConsentRoutes } = await import('../oidc-consents.js');
  await app.register(oidcConsentRoutes, { prefix: '/api/v1/oidc/consents' });
  await app.ready();
});

afterAll(async () => {
  await app?.close();
});

beforeEach(() => {
  principal = { id: 'user_1', orgId: 'org_1', role: 'MEMBER', email: 'person@example.com' };
  consents = [
    { id: 'c1', userId: 'user_1', oidcClientId: 'client_a', grantedScopes: ['openid', 'email'], grantedAt: new Date('2026-10-01'), revokedAt: null },
    { id: 'c2', userId: 'user_1', oidcClientId: 'client_b', grantedScopes: ['openid'], grantedAt: new Date('2026-10-02'), revokedAt: new Date() },
    { id: 'c3', userId: 'user_2', oidcClientId: 'client_a', grantedScopes: ['openid'], grantedAt: new Date('2026-10-03'), revokedAt: null },
  ];
  refreshTokens = [
    { userId: 'user_1', oidcClientId: 'client_a', revokedAt: null },
    { userId: 'user_1', oidcClientId: 'client_b', revokedAt: null },
    { userId: 'user_2', oidcClientId: 'client_a', revokedAt: null },
  ];
  accessTokens = [
    { userId: 'user_1', oidcClientId: 'client_a', revokedAt: null },
    { userId: 'user_2', oidcClientId: 'client_a', revokedAt: null },
  ];
  authCodes = [
    { userId: 'user_1', oidcClientId: 'client_a', usedAt: null },
    { userId: 'user_2', oidcClientId: 'client_a', usedAt: null },
  ];
  auditLogs = [];
});

describe('GET /api/v1/oidc/consents', () => {
  it("lists only the caller's live consents, with app and organization names", async () => {
    const res = await app.inject({ method: 'GET', url: '/api/v1/oidc/consents' });

    expect(res.statusCode).toBe(200);
    expect(res.json().data).toEqual([
      {
        id: 'c1',
        clientName: 'Example Shop',
        organizationName: 'Example Ltd',
        grantedScopes: ['openid', 'email'],
        grantedAt: new Date('2026-10-01').toISOString(),
      },
    ]);
  });

  it('refuses an API key', async () => {
    principal = { id: 'api-key', orgId: 'org_1', role: 'OWNER', email: '' };

    const res = await app.inject({ method: 'GET', url: '/api/v1/oidc/consents' });

    expect(res.statusCode).toBe(403);
  });
});

describe('DELETE /api/v1/oidc/consents/:id', () => {
  it("revokes the consent and that client's tokens for the caller only", async () => {
    const res = await app.inject({ method: 'DELETE', url: '/api/v1/oidc/consents/c1' });

    expect(res.statusCode).toBe(204);
    expect(consents.find((c) => c.id === 'c1')!.revokedAt).toBeInstanceOf(Date);
    expect(refreshTokens.map((t) => t.revokedAt !== null)).toEqual([true, false, false]);
    expect(accessTokens.map((t) => t.revokedAt !== null)).toEqual([true, false]);
    // An unredeemed authorization code can no longer be exchanged.
    expect(authCodes.map((c) => c.usedAt !== null)).toEqual([true, false]);
    expect(auditLogs).toHaveLength(1);
    expect(auditLogs[0]).toMatchObject({
      action: 'oidc.consent_revoked',
      userId: 'user_1',
      organizationId: 'org_1',
      resource: 'OidcClient',
      resourceId: 'client_a',
    });
  });

  it("returns 404 for another user's consent and changes nothing", async () => {
    const res = await app.inject({ method: 'DELETE', url: '/api/v1/oidc/consents/c3' });

    expect(res.statusCode).toBe(404);
    expect(consents.find((c) => c.id === 'c3')!.revokedAt).toBeNull();
    expect(refreshTokens.every((t) => t.revokedAt === null)).toBe(true);
  });

  it('returns 404 for an already revoked consent', async () => {
    const res = await app.inject({ method: 'DELETE', url: '/api/v1/oidc/consents/c2' });

    expect(res.statusCode).toBe(404);
  });

  it('refuses an API key', async () => {
    principal = { id: 'api-key', orgId: 'org_1', role: 'OWNER', email: '' };

    const res = await app.inject({ method: 'DELETE', url: '/api/v1/oidc/consents/c1' });

    expect(res.statusCode).toBe(403);
    expect(consents.find((c) => c.id === 'c1')!.revokedAt).toBeNull();
  });
});
