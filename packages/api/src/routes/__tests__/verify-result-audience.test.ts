import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { createHash } from 'node:crypto';

/**
 * Audit 2026-10 FINDING-009: /verify-result is audience-bound. A caller that
 * identifies itself is told `valid` only for sessions of its own app (or,
 * with an API key, its own organization). A caller that does not identify
 * itself is still answered, and logged, until enforcement is decided.
 */

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

vi.mock('../../services/auth-session.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../services/auth-session.js')>()),
  // The signature check itself is covered elsewhere; here it always passes.
  verifyApprovalSignature: vi.fn(async () => true),
}));

const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');

const APP_A = { id: 'app_a', clientId: 'qrauth_app_a', organizationId: 'org_a', name: 'App A', status: 'ACTIVE', allowedScopes: ['identity'], redirectUrls: [] };
const APP_B = { id: 'app_b', clientId: 'qrauth_app_b', organizationId: 'org_b', name: 'App B', status: 'ACTIVE', allowedScopes: ['identity'], redirectUrls: [] };
const SECRETS: Record<string, string> = { qrauth_app_a: 'secret-a', qrauth_app_b: 'secret-b' };

const SESSION = {
  id: 'sess_a',
  appId: 'app_a',
  userId: 'user_1',
  status: 'APPROVED',
  scopes: ['identity', 'email'],
  signature: 'sig',
  resolvedAt: new Date(),
  app: { name: 'App A', clientId: 'qrauth_app_a', organizationId: 'org_a' },
  user: { id: 'user_1', name: 'Person', email: 'person@example.com' },
};

const API_KEYS: Record<string, { organizationId: string; revokedAt: Date | null }> = {
  [sha256('qrauth_key_org_a_000000')]: { organizationId: 'org_a', revokedAt: null },
  [sha256('qrauth_key_org_b_000000')]: { organizationId: 'org_b', revokedAt: null },
  [sha256('qrauth_key_revoked_0000')]: { organizationId: 'org_a', revokedAt: new Date() },
};

const prisma = {
  authSession: { findUnique: async ({ where }: { where: { id: string } }) => (where.id === SESSION.id ? SESSION : null) },
  app: {
    findUnique: async ({ where }: { where: { clientId: string } }) =>
      [APP_A, APP_B].find((a) => a.clientId === where.clientId) ?? null,
  },
  apiKey: { findUnique: async ({ where }: { where: { keyHash: string } }) => API_KEYS[where.keyHash] ?? null },
};

vi.mock('../../services/app.js', () => ({
  AppService: class {
    async authenticateApp(clientId: string, clientSecret: string) {
      const app = [APP_A, APP_B].find((a) => a.clientId === clientId);
      return app && SECRETS[clientId] === clientSecret ? app : null;
    }
    async findByClientId(clientId: string) {
      return [APP_A, APP_B].find((a) => a.clientId === clientId) ?? null;
    }
  },
}));

const logs: Array<Record<string, unknown>> = [];
let app: FastifyInstance;

const basic = (clientId: string, secret: string) => ({ authorization: `Basic ${Buffer.from(`${clientId}:${secret}`).toString('base64')}` });
const verify = (headers: Record<string, string> = {}) =>
  app.inject({
    method: 'POST',
    url: '/verify-result',
    headers: { 'content-type': 'application/json', ...headers },
    payload: JSON.stringify({ sessionId: 'sess_a', signature: 'sig' }),
  });

beforeAll(async () => {
  app = Fastify({ logger: { level: 'info', stream: { write: (line: string) => { logs.push(JSON.parse(line)); } } } });
  app.decorate('prisma', prisma as never);
  app.decorate('signingService', {} as never);
  app.decorate('authenticate', (async () => undefined) as never);
  const { default: authSessionRoutes } = await import('../auth-sessions.js');
  await app.register(authSessionRoutes);
  await app.ready();
});

afterAll(async () => {
  await app?.close();
});

beforeEach(() => {
  logs.length = 0;
});

describe('POST /verify-result with app credentials', () => {
  it('confirms a session of the caller`s own app', async () => {
    const res = await verify(basic('qrauth_app_a', 'secret-a'));

    expect(res.json()).toMatchObject({ valid: true, session: { user: { id: 'user_1' }, signature: 'sig' } });
  });

  it('answers valid: false, with nothing about the session, for another app`s session', async () => {
    const res = await verify(basic('qrauth_app_b', 'secret-b'));

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({
      valid: false,
      session: { id: 'sess_a', status: null, appName: null, scopes: [], user: null },
    });
    expect(res.body).not.toContain('App A');
    expect(res.body).not.toContain('person@example.com');
  });

  it('a Basic header wins over client headers naming another app', async () => {
    const res = await verify({ ...basic('qrauth_app_b', 'secret-b'), 'x-client-id': 'qrauth_app_a', 'x-client-secret': 'secret-a' });

    expect(res.json().valid).toBe(false);
  });

  it('refuses a wrong secret before saying whether the session exists', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/verify-result',
      headers: { 'content-type': 'application/json', ...basic('qrauth_app_a', 'wrong') },
      payload: JSON.stringify({ sessionId: 'no_such_session', signature: 'sig' }),
    });

    expect(res.statusCode).toBe(401);
  });

  it('accepts the X-Client-Id / X-Client-Secret form too', async () => {
    const own = await verify({ 'x-client-id': 'qrauth_app_a', 'x-client-secret': 'secret-a' });
    const other = await verify({ 'x-client-id': 'qrauth_app_b', 'x-client-secret': 'secret-b' });

    expect(own.json().valid).toBe(true);
    expect(other.json().valid).toBe(false);
  });

  it('refuses a wrong secret with 401', async () => {
    const res = await verify(basic('qrauth_app_a', 'wrong'));

    expect(res.statusCode).toBe(401);
  });

  it('a client id with no secret refuses another app`s result but counts as unauthenticated', async () => {
    const other = await verify({ 'x-client-id': 'qrauth_app_b' });
    logs.length = 0;
    const own = await verify({ 'x-client-id': 'qrauth_app_a' });
    const emptySecret = await verify(basic('qrauth_app_a', ''));

    expect(other.json().valid).toBe(false);
    expect(own.json().valid).toBe(true);
    expect(emptySecret.json().valid).toBe(true);
    const unauthenticated = logs.filter((l) => l.event === 'verify_result.unauthenticated');
    expect(unauthenticated).toHaveLength(2);
    expect(unauthenticated[0]).toMatchObject({ appId: 'app_a', sentClientId: true });
  });

  it('an unknown client id is refused', async () => {
    expect((await verify({ 'x-client-id': 'qrauth_app_nope' })).statusCode).toBe(401);
  });
});

describe('POST /verify-result with an API key', () => {
  it('confirms a session of an app in the key`s organization', async () => {
    expect((await verify({ 'x-api-key': 'qrauth_key_org_a_000000' })).json().valid).toBe(true);
  });

  it('answers valid: false for a session of another organization', async () => {
    expect((await verify({ 'x-api-key': 'qrauth_key_org_b_000000' })).json().valid).toBe(false);
  });

  it.each(['qrauth_key_revoked_0000', 'qrauth_no_such_key_0000'])('refuses %s with 401', async (key) => {
    expect((await verify({ 'x-api-key': key })).statusCode).toBe(401);
  });
});

describe('POST /verify-result with no credentials', () => {
  it('is still answered, and logged with the app it was for', async () => {
    const res = await verify();

    expect(res.json().valid).toBe(true);
    const line = logs.find((l) => l.event === 'verify_result.unauthenticated');
    expect(line).toMatchObject({ appId: 'app_a', clientId: 'qrauth_app_a', sentClientId: false });
    expect(JSON.stringify(logs)).not.toContain('person@example.com');
  });

  it('is not logged as unauthenticated when the caller identified itself', async () => {
    await verify(basic('qrauth_app_a', 'secret-a'));

    expect(logs.some((l) => l.event === 'verify_result.unauthenticated')).toBe(false);
  });
});
