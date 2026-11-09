import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * Security webhook audit entries (ADR-0008): the endpoint is recorded as
 * host plus a short hash of the URL, never the URL itself; the secret is
 * never recorded.
 */

process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);

const { default: routes, webhookAuditRef } = await import('../organizations/security-webhook.js');

const SECRET_URL = 'https://hooks.example.com/qrauth/s3cr3t-path?token=abc123';
let stored: string | null = null;
let audits: Array<Record<string, unknown>> = [];
let app: FastifyInstance;

const prisma = {
  organization: {
    findUnique: async () => ({ securityWebhookUrl: stored }),
    update: async ({ data }: { data: { securityWebhookUrl: string | null } }) => {
      stored = data.securityWebhookUrl;
      return { id: 'org_1', securityWebhookUrl: stored, updatedAt: new Date() };
    },
  },
  auditLog: { create: async ({ data }: { data: Record<string, unknown> }) => { audits.push(data); } },
  $transaction: async (fn: (tx: unknown) => unknown) => fn(prisma),
};

beforeAll(async () => {
  app = Fastify();
  app.decorate('prisma', prisma as never);
  app.decorateRequest('user', null);
  app.decorate('authenticate', async (request: { user: unknown }) => {
    request.user = { id: 'user_1', orgId: 'org_1', role: 'OWNER', email: 'o@example.com' };
  });
  await app.register(routes, { prefix: '/api/v1/organizations' });
  await app.ready();
});
afterAll(() => app.close());
beforeEach(() => {
  stored = null;
  audits = [];
});

describe('security webhook audit entries', () => {
  it('record host and URL hash on register, rotate and delete; never the URL or secret', async () => {
    const first = await app.inject({ method: 'POST', url: '/api/v1/organizations/org_1/security-webhook', payload: { url: SECRET_URL } });
    expect(first.statusCode).toBe(201);
    const secret = first.json().secret as string;
    await app.inject({ method: 'POST', url: '/api/v1/organizations/org_1/security-webhook', payload: { url: 'https://other.example.org/hook' } });
    await app.inject({ method: 'DELETE', url: '/api/v1/organizations/org_1/security-webhook' });

    expect(audits.map((a) => a.action)).toEqual(['securityWebhook.update', 'securityWebhook.update', 'securityWebhook.delete']);
    expect(audits[0].metadata).toEqual({ endpoint: { before: null, after: webhookAuditRef(SECRET_URL) }, secretRotated: true });
    expect(audits[1].metadata).toMatchObject({ endpoint: { before: { host: 'hooks.example.com' }, after: { host: 'other.example.org' } } });
    expect(audits[2].metadata).toEqual({ endpoint: webhookAuditRef('https://other.example.org/hook') });
    const serialized = JSON.stringify(audits);
    for (const leak of ['s3cr3t-path', 'abc123', '/qrauth/', secret]) expect(serialized).not.toContain(leak);
  });

  it('the hash tells two URLs on the same host apart', () => {
    const a = webhookAuditRef('https://hooks.example.com/a')!;
    const b = webhookAuditRef('https://hooks.example.com/b')!;
    expect(a.host).toBe(b.host);
    expect(a.urlHash).not.toBe(b.urlHash);
    expect(a.urlHash).toMatch(/^[0-9a-f]{12}$/);
  });
});
