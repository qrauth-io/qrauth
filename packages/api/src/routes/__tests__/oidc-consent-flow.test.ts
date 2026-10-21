import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { createHash } from 'node:crypto';

/**
 * Audit 2026-10 FINDING-002: the OP must not issue an authorization code to
 * a CUSTOMER client the signed-in user has not consented to. Drives the real
 * /authorize and /authorize/consent routes against an in-memory Prisma and
 * Redis stand-in — no database.
 */

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

const cache = new Map<string, unknown>();
vi.mock('../../lib/cache.js', () => ({
  redis: {},
  cacheGet: vi.fn(async (key: string) => cache.get(key) ?? null),
  cacheSet: vi.fn(async (key: string, value: unknown) => { cache.set(key, value); }),
  cacheDel: vi.fn(async (key: string) => { cache.delete(key); }),
  cacheTake: vi.fn(async (key: string) => {
    const value = cache.get(key) ?? null;
    cache.delete(key);
    return value;
  }),
  disconnectCache: vi.fn(async () => undefined),
}));

const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');

// ---------------------------------------------------------------------------
// In-memory Prisma stand-in: only the calls these routes make.
// ---------------------------------------------------------------------------

interface ClientRow {
  id: string;
  clientId: string;
  name: string;
  tier: 'CUSTOMER' | 'FIRST_PARTY' | 'PUBLIC';
  clientSecretHash: string | null;
  redirectUris: string[];
  allowedScopes: string[];
  consentRequired: boolean;
  organizationId: string;
  organization: { name: string };
}
interface ConsentRow {
  id: string;
  userId: string;
  oidcClientId: string;
  grantedScopes: string[];
  grantedAt: Date;
  revokedAt: Date | null;
}

const REDIRECT_URI = 'https://rp.example/callback';
const USER_ID = 'user_1';
const SESSION = 'op-session-token-1';
const OTHER_SESSION = 'op-session-token-2';

let clients: ClientRow[] = [];
let consents: ConsentRow[] = [];
// Keyed by the cookie's hash, like the unique index the real lookup uses.
let sessions = new Map<string, { userId: string; createdAt: Date; expiresAt: Date; revokedAt: Date | null }>();
let authCodes: Array<Record<string, any>> = [];
let auditLogs: Array<Record<string, any>> = [];

const prisma: Record<string, any> = {
  oidcClient: {
    findUnique: async ({ where }: any) =>
      clients.find((c) => (where.clientId ? c.clientId === where.clientId : c.id === where.id)) ?? null,
  },
  oidcSession: {
    findUnique: async ({ where }: any) => sessions.get(where.sessionTokenHash) ?? null,
  },
  oidcConsent: {
    findUnique: async ({ where }: any) => {
      const key = where.userId_oidcClientId;
      return consents.find((c) => c.userId === key.userId && c.oidcClientId === key.oidcClientId) ?? null;
    },
    upsert: async ({ where, create, update }: any) => {
      const key = where.userId_oidcClientId;
      const existing = consents.find((c) => c.userId === key.userId && c.oidcClientId === key.oidcClientId);
      if (existing) {
        Object.assign(existing, update);
        return existing;
      }
      const row = { id: `consent_${consents.length + 1}`, grantedAt: new Date(), revokedAt: null, ...create };
      consents.push(row);
      return row;
    },
  },
  oidcAuthCode: {
    create: async ({ data }: any) => {
      authCodes.push(data);
      return data;
    },
  },
  user: {
    findUnique: async () => ({ email: 'person@example.com' }),
  },
  membership: {
    findFirst: async ({ where }: any) => ({ userId: where.userId, organizationId: 'org_user' }),
  },
  auditLog: {
    create: async ({ data }: any) => {
      auditLogs.push(data);
      return data;
    },
  },
  $transaction: async (fn: (tx: unknown) => Promise<unknown>) => fn(prisma),
};

function seedClient(overrides: Partial<ClientRow> = {}): ClientRow {
  const row: ClientRow = {
    id: 'client_db_1',
    clientId: 'qrauth_oidc_test',
    name: 'Example Shop',
    tier: 'CUSTOMER',
    clientSecretHash: 'confidential',
    redirectUris: [REDIRECT_URI],
    allowedScopes: ['openid', 'email', 'profile'],
    consentRequired: true,
    organizationId: 'org_client',
    organization: { name: 'Example Ltd' },
    ...overrides,
  };
  clients.push(row);
  return row;
}

function seedSession(token: string, userId = USER_ID): void {
  sessions.set(sha256(token), {
    userId,
    createdAt: new Date(Date.now() - 60_000),
    expiresAt: new Date(Date.now() + 3_600_000),
    revokedAt: null,
  });
}

function seedConsent(grantedScopes: string[], revokedAt: Date | null = null): ConsentRow {
  const row: ConsentRow = {
    id: `consent_${consents.length + 1}`,
    userId: USER_ID,
    oidcClientId: 'client_db_1',
    grantedScopes,
    grantedAt: new Date(),
    revokedAt,
  };
  consents.push(row);
  return row;
}

// ---------------------------------------------------------------------------

let app: FastifyInstance;

// /authorize reuses an existing OP session only when asked to (see
// oidc-interactive-login.test.ts). These tests are about what happens once a
// session counts, so every request carries a max_age the seeded session meets.
function authorize(params: Record<string, string> = {}, sessionToken: string | null = SESSION) {
  const query = new URLSearchParams({
    response_type: 'code',
    client_id: 'qrauth_oidc_test',
    redirect_uri: REDIRECT_URI,
    scope: 'openid email',
    state: 'state-1',
    max_age: '3600',
    ...params,
  });
  return app.inject({
    method: 'GET',
    url: `/authorize?${query.toString()}`,
    headers: { accept: 'text/html' },
    cookies: sessionToken ? { qrauth_op_session: sessionToken } : {},
  });
}

function consentToken(html: string): string {
  const match = html.match(/name="consent_token" value="([^"]+)"/);
  if (!match) throw new Error('consent page has no consent_token field');
  return match[1];
}

function submitConsent(token: string, decision: 'approve' | 'deny', sessionToken: string | null = SESSION) {
  return app.inject({
    method: 'POST',
    url: '/authorize/consent',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams({ consent_token: token, decision }).toString(),
    cookies: sessionToken ? { qrauth_op_session: sessionToken } : {},
  });
}

const location = (res: { headers: Record<string, unknown> }) => new URL(String(res.headers.location));

/** Where the script-free return page sends the browser (its meta refresh). */
function returnTarget(res: { statusCode: number; body: string; headers: Record<string, unknown> }): URL {
  expect(res.statusCode).toBe(200);
  expect(res.headers.location).toBeUndefined();
  const match = res.body.match(/<meta http-equiv="refresh" content="0;url=([^"]+)">/);
  if (!match) throw new Error('no meta refresh on the return page');
  return new URL(match[1].replace(/&amp;/g, '&'));
}

beforeAll(async () => {
  app = Fastify({ logger: false });
  await app.register((await import('@fastify/cookie')).default);
  // Same form parser server.ts installs.
  app.addContentTypeParser('application/x-www-form-urlencoded', { parseAs: 'string' }, (_req, body, done) => {
    done(null, Object.fromEntries(new URLSearchParams(body as string)));
  });
  app.decorate('prisma', prisma as never);
  app.decorate('signingService', {} as never);
  // server.ts rewrites the CSP header on every response and honours only
  // request.cspOverride; reproduce that so the header asserted below is the
  // one a browser would receive.
  app.addHook('onSend', (request, reply, _payload, done) => {
    const override = (request as unknown as { cspOverride?: string }).cspOverride;
    reply.header('Content-Security-Policy', override ?? "default-src 'self'; form-action 'self'");
    done();
  });
  const { default: oidcFlowRoutes } = await import('../oidc-flow.js');
  await app.register(oidcFlowRoutes);
  await app.ready();
});

afterAll(async () => {
  await app?.close();
});

beforeEach(() => {
  cache.clear();
  clients = [];
  consents = [];
  sessions = new Map();
  authCodes = [];
  auditLogs = [];
  seedSession(SESSION);
});

describe('/authorize for a CUSTOMER client (FINDING-002)', () => {
  it('shows a consent page and issues no code when there is no consent', async () => {
    seedClient();

    const res = await authorize();

    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('text/html');
    expect(res.headers.location).toBeUndefined();
    expect(authCodes).toHaveLength(0);
    expect(res.body).toContain('Example Shop');
    expect(res.body).toContain('Example Ltd');
    expect(res.body).toContain('rp.example');
    expect(res.body).toContain('Your email address');
    expect(res.body).toContain('has not checked this app');
  });

  it('the consent page cannot be framed and carries no script', async () => {
    seedClient();

    const res = await authorize();

    const csp = String(res.headers['content-security-policy']);
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("script-src 'none'");
    expect(csp).toContain("form-action 'self'");
    expect(csp).not.toContain('rp.example');
    expect(csp).toMatch(/style-src 'nonce-[A-Za-z0-9+/=]+'/);
    expect(res.headers['x-frame-options']).toBe('DENY');
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.body).not.toContain('<script');
  });

  it('escapes the client and organization names', async () => {
    seedClient({ name: '<img src=x onerror=1>', organization: { name: '"><b>Org</b>' } });

    const res = await authorize();

    expect(res.body).not.toContain('<img src=x');
    expect(res.body).not.toContain('<b>Org</b>');
  });

  it('returns consent_required for prompt=none without consent', async () => {
    seedClient();

    const res = await authorize({ prompt: 'none' });

    expect(res.statusCode).toBe(302);
    expect(location(res).origin + location(res).pathname).toBe(REDIRECT_URI);
    expect(location(res).searchParams.get('error')).toBe('consent_required');
    expect(location(res).searchParams.get('state')).toBe('state-1');
    expect(authCodes).toHaveLength(0);
  });

  it('issues a code straight away when a live consent covers the scopes', async () => {
    seedClient();
    seedConsent(['openid', 'email', 'profile']);

    const res = await authorize();

    expect(res.statusCode).toBe(302);
    expect(location(res).searchParams.get('code')).toBeTruthy();
    expect(authCodes).toHaveLength(1);
    expect(authCodes[0].scope).toBe('openid email');
  });

  it('asks again when the request needs a scope the consent does not cover', async () => {
    seedClient();
    seedConsent(['openid']);

    const res = await authorize({ scope: 'openid email' });

    expect(res.statusCode).toBe(200);
    expect(authCodes).toHaveLength(0);
  });

  it('asks again when the consent was revoked', async () => {
    seedClient();
    seedConsent(['openid', 'email'], new Date());

    const res = await authorize();

    expect(res.statusCode).toBe(200);
    expect(authCodes).toHaveLength(0);
  });

  it('prompt=consent always shows the page, even with a covering consent', async () => {
    seedClient();
    seedConsent(['openid', 'email']);

    const res = await authorize({ prompt: 'consent' });

    expect(res.statusCode).toBe(200);
    expect(authCodes).toHaveLength(0);
  });

  it('keeps prompt=consent across the login redirect', async () => {
    seedClient();

    const res = await authorize({ prompt: 'consent' }, null);

    expect(res.statusCode).toBe(302);
    const returnTo = new URL(String(res.headers.location), 'https://id.example').searchParams.get('returnTo')!;
    expect(new URLSearchParams(returnTo.split('?')[1]).get('prompt')).toBe('consent');
  });
});

describe('any tier other than FIRST_PARTY', () => {
  it('is asked for consent too', async () => {
    seedClient({ tier: 'PUBLIC' });

    const res = await authorize();

    expect(res.statusCode).toBe(200);
    expect(authCodes).toHaveLength(0);
  });
});

describe('operator-vetted clients (consentRequired = false)', () => {
  it('skip consent: a code is issued with no consent row and no consent lookup', async () => {
    seedClient({ consentRequired: false });
    const lookups = vi.spyOn(prisma.oidcConsent, 'findUnique');

    const res = await authorize();

    expect(res.statusCode).toBe(302);
    expect(location(res).searchParams.get('code')).toBeTruthy();
    expect(consents).toHaveLength(0);
    expect(lookups).not.toHaveBeenCalled();
    lookups.mockRestore();
  });

  it('ignore prompt=consent, like FIRST_PARTY', async () => {
    seedClient({ consentRequired: false });

    const res = await authorize({ prompt: 'consent' });

    expect(res.statusCode).toBe(302);
    expect(location(res).searchParams.get('code')).toBeTruthy();
  });

  it('prompt=none succeeds without consent', async () => {
    seedClient({ consentRequired: false });

    const res = await authorize({ prompt: 'none' });

    expect(location(res).searchParams.get('code')).toBeTruthy();
    expect(location(res).searchParams.get('error')).toBeNull();
  });

  it('the same client is asked again once it is no longer vetted', async () => {
    const client = seedClient({ consentRequired: false });
    await authorize();
    client.consentRequired = true;

    const res = await authorize();

    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('Example Shop');
  });
});

describe('FIRST_PARTY clients', () => {
  it('skip consent: a code is issued with no consent row', async () => {
    seedClient({ tier: 'FIRST_PARTY' });

    const res = await authorize({ prompt: 'consent' });

    expect(res.statusCode).toBe(302);
    expect(location(res).searchParams.get('code')).toBeTruthy();
    expect(consents).toHaveLength(0);
  });
});

describe('POST /authorize/consent', () => {
  it('Approve records the consent, writes an audit row and issues the code', async () => {
    seedClient();
    const token = consentToken((await authorize({ nonce: 'n-1' })).body);

    const res = await submitConsent(token, 'approve');

    const target = returnTarget(res);
    expect(target.origin + target.pathname).toBe(REDIRECT_URI);
    expect(target.searchParams.get('code')).toBeTruthy();
    expect(target.searchParams.get('state')).toBe('state-1');
    expect(String(res.headers['content-security-policy'])).toContain("form-action 'self'");
    expect(res.body).not.toContain('<script');
    expect(consents).toHaveLength(1);
    expect(consents[0]).toMatchObject({ userId: USER_ID, oidcClientId: 'client_db_1', revokedAt: null });
    expect([...consents[0].grantedScopes].sort()).toEqual(['email', 'openid']);
    expect(authCodes).toHaveLength(1);
    expect(authCodes[0]).toMatchObject({ userId: USER_ID, scope: 'openid email', nonce: 'n-1', redirectUri: REDIRECT_URI });
    expect(auditLogs).toHaveLength(1);
    expect(auditLogs[0]).toMatchObject({
      action: 'oidc.consent_granted',
      userId: USER_ID,
      organizationId: 'org_user',
      resource: 'OidcClient',
      resourceId: 'client_db_1',
    });
  });

  it('Approve widens an existing consent to the union of scopes', async () => {
    seedClient();
    seedConsent(['openid', 'profile']);
    const token = consentToken((await authorize({ scope: 'openid email' })).body);

    await submitConsent(token, 'approve');

    expect(consents).toHaveLength(1);
    expect([...consents[0].grantedScopes].sort()).toEqual(['email', 'openid', 'profile']);
  });

  it('Approve after a revoked consent grants only what was just requested', async () => {
    seedClient();
    seedConsent(['openid', 'profile'], new Date());
    const token = consentToken((await authorize({ scope: 'openid email' })).body);

    await submitConsent(token, 'approve');

    expect(consents[0].revokedAt).toBeNull();
    expect([...consents[0].grantedScopes].sort()).toEqual(['email', 'openid']);
  });

  it('Deny returns access_denied and records nothing', async () => {
    seedClient();
    const token = consentToken((await authorize()).body);

    const res = await submitConsent(token, 'deny');

    const target = returnTarget(res);
    expect(target.origin + target.pathname).toBe(REDIRECT_URI);
    expect(target.searchParams.get('error')).toBe('access_denied');
    expect(target.searchParams.get('state')).toBe('state-1');
    expect(consents).toHaveLength(0);
    expect(authCodes).toHaveLength(0);
  });

  it('rejects a replayed consent token', async () => {
    seedClient();
    const token = consentToken((await authorize()).body);
    await submitConsent(token, 'approve');

    const replay = await submitConsent(token, 'approve');

    expect(replay.statusCode).toBe(400);
    expect(replay.headers.location).toBeUndefined();
    expect(authCodes).toHaveLength(1);
  });

  it('rejects a consent token presented with another OP session', async () => {
    seedClient();
    seedSession(OTHER_SESSION, 'user_2');
    const token = consentToken((await authorize()).body);

    const res = await submitConsent(token, 'approve', OTHER_SESSION);

    expect(res.statusCode).toBe(400);
    expect(consents).toHaveLength(0);
    expect(authCodes).toHaveLength(0);
  });

  it('rejects a consent token presented with no OP session', async () => {
    seedClient();
    const token = consentToken((await authorize()).body);

    const res = await submitConsent(token, 'approve', null);

    expect(res.statusCode).toBe(400);
    expect(authCodes).toHaveLength(0);
  });

  it('rejects a token whose secret half was altered', async () => {
    seedClient();
    const token = consentToken((await authorize()).body);
    const [id] = token.split('.');

    const res = await submitConsent(`${id}.not-the-secret`, 'approve');

    expect(res.statusCode).toBe(400);
    expect(authCodes).toHaveLength(0);
  });

  it('rejects a consent token that is not a string', async () => {
    seedClient();
    await authorize();

    const res = await app.inject({
      method: 'POST',
      url: '/authorize/consent',
      headers: { 'content-type': 'application/json' },
      payload: { consent_token: { id: 'x' }, decision: 'approve' },
      cookies: { qrauth_op_session: SESSION },
    });

    expect(res.statusCode).toBe(400);
    expect(authCodes).toHaveLength(0);
  });

  it('rejects an unknown decision value', async () => {
    seedClient();
    const token = consentToken((await authorize()).body);

    const res = await app.inject({
      method: 'POST',
      url: '/authorize/consent',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: new URLSearchParams({ consent_token: token, decision: 'maybe' }).toString(),
      cookies: { qrauth_op_session: SESSION },
    });

    expect(res.statusCode).toBe(400);
    expect(authCodes).toHaveLength(0);
  });

  it('refuses to approve when the redirect URI was removed from the client meanwhile', async () => {
    const client = seedClient();
    const token = consentToken((await authorize()).body);
    client.redirectUris = ['https://rp.example/other'];

    const res = await submitConsent(token, 'approve');

    expect(res.statusCode).toBe(400);
    expect(res.headers.location).toBeUndefined();
    expect(authCodes).toHaveLength(0);
  });
});
