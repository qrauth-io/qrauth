import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { hashString } from '../../lib/crypto.js';
import { constantTimeEqualString } from '../../lib/constant-time.js';

/**
 * /api/v1/api-keys audit entries (ADR-0008): written in the transaction of
 * the change, with the API key as actor when one authenticated the request,
 * and never on a refused or no-op request. Real routes, in-memory prisma.
 */

process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

vi.mock('../../lib/email.js', () => ({
  sendApiKeyCreatedEmail: vi.fn(async () => undefined),
  sendApiKeyRevokedEmail: vi.fn(async () => undefined),
}));

const ORG = 'org_1';
const RAW_KEY = 'qrauth_live_selfrevoke';

interface Key { id: string; organizationId: string; prefix: string; label: string | null; source: string; role: string | null; keyHash: string; revokedAt: Date | null }

let keys: Key[] = [];
let auditEntries: Array<Record<string, any>> = [];
let inTransaction = false;

const prisma: Record<string, any> = {
  apiKey: {
    create: async ({ data }: any) => ({ id: 'key_new', source: 'dashboard', role: null, createdAt: new Date(), ...data }),
    findUnique: async ({ where }: any) => keys.find((k) => constantTimeEqualString(k.keyHash, where.keyHash)) ?? null,
    findFirst: async ({ where }: any) =>
      keys.find((k) => k.id === where.id && k.organizationId === where.organizationId && k.revokedAt === null) ?? null,
    updateMany: async ({ where, data }: any) => {
      const hit = keys.filter((k) => k.id === where.id && k.revokedAt === null);
      hit.forEach((k) => { k.revokedAt = data.revokedAt; });
      return { count: hit.length };
    },
  },
  organization: { findUnique: async () => ({ email: null, name: 'Org' }) },
  // The creator's current role, read when a key is created (services/api-key-issue.ts).
  membership: { findUnique: async () => ({ role: 'OWNER' }) },
  auditLog: {
    create: async ({ data }: any) => {
      auditEntries.push({ ...data, inTransaction });
      return {};
    },
  },
  $transaction: async (fn: (tx: unknown) => Promise<unknown>) => {
    inTransaction = true;
    try {
      return await fn(prisma);
    } finally {
      inTransaction = false;
    }
  },
};

let app: FastifyInstance;

beforeAll(async () => {
  app = Fastify({ logger: false });
  app.decorate('prisma', prisma as never);
  app.decorate('authenticate', async (req: never) => {
    const request = req as unknown as { headers: Record<string, string>; user?: unknown };
    const apiKeyId = request.headers['x-test-api-key'];
    request.user = apiKeyId
      ? { id: 'api-key', apiKeyId, orgId: ORG, role: 'OWNER', email: '' }
      : { id: 'u_owner', orgId: ORG, role: 'OWNER', email: 'owner@example.com' };
  });
  const { default: apiKeyRoutes } = await import('../api-keys.js');
  await app.register(apiKeyRoutes, { prefix: '/api/v1/api-keys' });
  await app.ready();
});

afterAll(async () => {
  await app?.close();
});

beforeEach(() => {
  auditEntries = [];
  keys = [{ id: 'key_1', organizationId: ORG, prefix: 'qrauth_l', label: 'CLI', source: 'cli', role: 'ADMIN', keyHash: hashString(RAW_KEY), revokedAt: null }];
});

describe('api-keys audit entries', () => {
  it('records apiKey.create by the signed-in user, naming the creator, without the key', async () => {
    const res = await app.inject({ method: 'POST', url: '/api/v1/api-keys', payload: { label: 'Deploy' } });

    expect(res.statusCode).toBe(201);
    expect(auditEntries).toEqual([expect.objectContaining({
      organizationId: ORG,
      action: 'apiKey.create',
      resourceId: 'key_new',
      actorType: 'USER',
      actorId: 'u_owner',
      inTransaction: true,
      metadata: { prefix: expect.any(String), label: 'Deploy', source: 'dashboard', role: 'MEMBER', createdByUserId: 'u_owner' },
    })]);
    expect(JSON.stringify(auditEntries)).not.toContain(res.json().key);
  });

  it('records a revoke made with an API key as that key', async () => {
    const res = await app.inject({
      method: 'DELETE',
      url: '/api/v1/api-keys/key_1',
      headers: { 'x-test-api-key': 'key_other' },
    });

    expect(res.statusCode).toBe(200);
    expect(auditEntries).toEqual([expect.objectContaining({
      action: 'apiKey.revoke',
      resourceId: 'key_1',
      actorType: 'API_KEY',
      actorId: 'key_other',
      userId: null,
      inTransaction: true,
    })]);
  });

  it('self-revoke records the revoked key as actor', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/api-keys/self-revoke',
      headers: { 'x-api-key': RAW_KEY, 'x-test-api-key': 'key_1' },
    });

    expect(res.statusCode).toBe(200);
    expect(auditEntries).toEqual([expect.objectContaining({
      action: 'apiKey.revoke',
      resourceId: 'key_1',
      actorType: 'API_KEY',
      actorId: 'key_1',
      metadata: { prefix: 'qrauth_l', label: 'CLI', source: 'cli', role: 'ADMIN' },
    })]);
    expect(JSON.stringify(auditEntries)).not.toContain(RAW_KEY);
  });

  it('records nothing when the key is already revoked', async () => {
    keys[0].revokedAt = new Date();

    const res = await app.inject({ method: 'DELETE', url: '/api/v1/api-keys/key_1' });

    expect(res.statusCode).toBe(404);
    expect(auditEntries).toEqual([]);
  });
});
