import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * Audit 2026-10 FINDING-001: an OAuth sign-in that proves ownership of an
 * email must not inherit credentials created on that account before the
 * email was verified (pre-registered password, sessions, API keys). Also
 * covers the email-case normalisation that closes the case-variant route to
 * the same problem. In-memory Prisma stand-in — no database.
 */

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);
process.env.WEBAUTHN_ORIGIN = 'https://qrauth.test';

vi.mock('../../lib/cache.js', () => ({
  redis: {},
  cacheGet: vi.fn(async () => ({ valid: true, codeVerifier: 'test-code-verifier' })),
  cacheSet: vi.fn(async () => undefined),
  cacheDel: vi.fn(async () => undefined),
  disconnectCache: vi.fn(async () => undefined),
}));

let providerIdentity: Record<string, unknown> = {};
vi.mock('../../lib/oauth.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../lib/oauth.js')>()),
  exchangeCodeForUser: async () => providerIdentity,
}));

vi.mock('../../lib/metadata.js', () => ({
  collectRequestMetadata: async () => ({}),
}));

vi.mock('../../lib/email.js', () => ({
  sendPasswordResetEmail: vi.fn(async () => undefined),
  sendWelcomeVerificationEmail: vi.fn(async () => undefined),
  sendPasswordChangedEmail: vi.fn(async () => undefined),
  sendSuspiciousLoginEmail: vi.fn(async () => undefined),
}));

const failedAttempts: string[] = [];
vi.mock('../../services/login-event.js', () => ({
  LoginEventService: class {
    async record() {}
    async recordFailedAttempt(userId: string) {
      failedAttempts.push(userId);
      return { locked: false };
    }
    async checkLockout() {
      return null;
    }
    async resetFailedAttempts() {}
    async isSuspiciousLogin() {
      return false;
    }
  },
}));

vi.mock('../../services/device.js', () => ({
  DeviceService: class {
    async identifyDevice() {
      return { device: null, isNew: false };
    }
  },
}));

const { hashPassword } = await import('../../lib/password.js');

// ---------------------------------------------------------------------------
// In-memory Prisma stand-in: only the calls these routes make.
// ---------------------------------------------------------------------------

interface UserRow {
  id: string;
  name: string;
  email: string;
  passwordHash: string;
  emailVerified: boolean;
  emailVerifyToken: string | null;
  passwordResetToken: string | null;
  passwordResetExpires: Date | null;
  provider: string;
  providerId: string | null;
  avatarUrl: string | null;
  lockedUntil: Date | null;
  createdAt: Date;
}

const ORG = { id: 'org_1', name: 'Org', slug: 'org' };

let users: UserRow[] = [];
// `origin` tells a token seeded by the test from one the route issued.
let refreshTokens: Array<{ userId: string; revokedAt: Date | null; origin: 'seeded' | 'issued' }> = [];
let apiKeys: Array<{ id: string; createdByUserId: string | null; revokedAt: Date | null }> = [];
let auditLogs: Array<Record<string, unknown>> = [];
let passkeys: Array<{ id: string; userId: string; revokedAt: Date | null }> = [];
let membershipWrites = 0;

function seedUser(overrides: Partial<UserRow> = {}): UserRow {
  const row: UserRow = {
    id: `user_${users.length + 1}`,
    name: 'Someone',
    email: 'victim@example.com',
    passwordHash: '',
    emailVerified: false,
    emailVerifyToken: null,
    passwordResetToken: null,
    passwordResetExpires: null,
    provider: 'EMAIL',
    providerId: null,
    avatarUrl: null,
    lockedUntil: null,
    createdAt: new Date(),
    ...overrides,
  };
  users.push(row);
  return row;
}

function matchesUserWhere(user: UserRow, where: Record<string, any>): boolean {
  if (where.id !== undefined && user.id !== where.id) return false;
  if (where.provider !== undefined && user.provider !== where.provider) return false;
  if (where.providerId !== undefined && user.providerId !== where.providerId) return false;
  if (typeof where.email === 'string' && user.email !== where.email) return false;
  if (where.email && typeof where.email === 'object') {
    const wanted = String(where.email.equals).replace(/\\([\\%_])/g, '$1');
    const same = where.email.mode === 'insensitive'
      ? user.email.toLowerCase() === wanted.toLowerCase()
      : user.email === wanted;
    if (!same) return false;
  }
  return true;
}

function withMemberships(user: UserRow) {
  return {
    ...user,
    memberships: [{ userId: user.id, organizationId: ORG.id, role: 'OWNER', organization: ORG }],
  };
}

const prisma: Record<string, any> = {
  user: {
    findUnique: async ({ where, include }: any) => {
      const user = users.find((u) => matchesUserWhere(u, where));
      if (!user) return null;
      return include?.memberships ? withMemberships(user) : { ...user };
    },
    findFirst: async ({ where }: any) => users.find((u) => matchesUserWhere(u, where)) ?? null,
    findMany: async ({ where }: any) => users.filter((u) => matchesUserWhere(u, where)),
    update: async ({ where, data }: any) => {
      const user = users.find((u) => u.id === where.id)!;
      for (const [key, value] of Object.entries(data)) {
        if (value !== undefined) (user as any)[key] = value;
      }
      return { ...user };
    },
    create: async ({ data }: any) => seedUser({ ...data, id: `user_new_${users.length + 1}` }),
  },
  membership: {
    findMany: async ({ where }: any) =>
      // The claim's "other members of organizations this account owns" query.
      where.organizationId
        ? []
        : [{ userId: where.userId, organizationId: ORG.id, role: 'OWNER', organization: ORG }],
    findFirst: async ({ where }: any) => ({ userId: where.userId, organizationId: ORG.id, role: 'OWNER' }),
    create: async () => {
      membershipWrites += 1;
      return {};
    },
  },
  organization: {
    findUnique: async () => null,
    create: async ({ data }: any) => ({ id: 'org_new', ...data }),
  },
  refreshToken: {
    create: async ({ data }: any) => {
      refreshTokens.push({ userId: data.userId, revokedAt: null, origin: 'issued' });
      return data;
    },
    updateMany: async ({ where, data }: any) => {
      const hit = refreshTokens.filter((t) => t.userId === where.userId && t.revokedAt === null);
      hit.forEach((t) => { t.revokedAt = data.revokedAt; });
      return { count: hit.length };
    },
  },
  apiKey: {
    updateMany: async ({ where, data }: any) => {
      const creator = where.OR[0].createdByUserId;
      const hit = apiKeys.filter((k) => k.createdByUserId === creator && k.revokedAt === null);
      hit.forEach((k) => { k.revokedAt = data.revokedAt; });
      return { count: hit.length };
    },
  },
  trustedDevice: { deleteMany: async () => ({ count: 0 }) },
  oidcSession: { updateMany: async () => ({ count: 0 }) },
  oidcRefreshToken: { updateMany: async () => ({ count: 0 }) },
  oidcAccessToken: { updateMany: async () => ({ count: 0 }) },
  oidcAuthCode: { updateMany: async () => ({ count: 0 }) },
  oidcConsent: { updateMany: async () => ({ count: 0 }) },
  invitation: { deleteMany: async () => ({ count: 0 }) },
  authSession: { updateMany: async () => ({ count: 0 }) },
  // Any passkey write the callback made would show up in `passkeys`.
  passkey: {
    updateMany: async ({ where, data }: any) => {
      const hit = passkeys.filter((p) => p.userId === where.userId);
      hit.forEach((p) => Object.assign(p, data));
      return { count: hit.length };
    },
    deleteMany: async ({ where }: any) => {
      const before = passkeys.length;
      passkeys = passkeys.filter((p) => p.userId !== where.userId);
      return { count: before - passkeys.length };
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

// ---------------------------------------------------------------------------

const BASE = 'https://qrauth.test';
const ATTACKER_PASSWORD = 'attacker-chosen-password-1';
let app: FastifyInstance;

async function oauthCallback(extra: Record<string, unknown> = {}) {
  const state = Buffer.from(
    JSON.stringify({ csrf: 'x', returnTo: '', authSessionToken: '', ...extra }),
  ).toString('base64url');
  // The browser that started the flow carries the state-binding cookie.
  const { OAUTH_STATE_COOKIE, hashOAuthState } = await import('../../lib/oauth-state-binding.js');
  return app.inject({
    method: 'GET',
    url: `/api/v1/auth/oauth/google/callback?code=abc&state=${state}`,
    cookies: { [OAUTH_STATE_COOKIE]: hashOAuthState(state) },
  });
}

function login(email: string, password: string) {
  return app.inject({ method: 'POST', url: '/api/v1/auth/login', payload: { email, password } });
}

function signup(email: string) {
  return app.inject({
    method: 'POST',
    url: '/api/v1/auth/signup',
    payload: { name: 'New Person', email, password: 'a-long-enough-password-1', organizationName: 'New Org' },
  });
}

beforeAll(async () => {
  app = Fastify({ logger: false });
  await app.register((await import('@fastify/cookie')).default);
  await app.register((await import('@fastify/jwt')).default, { secret: 'b'.repeat(32) });
  app.decorate('prisma', prisma as never);
  app.decorate('signingService', { createKeyPair: async () => ({}) } as never);
  app.decorate('authenticate', async () => undefined);
  const { default: authRoutes } = await import('../auth.js');
  await app.register(authRoutes, { prefix: '/api/v1/auth' });
  await app.ready();
});

afterAll(async () => {
  await app?.close();
});

beforeEach(() => {
  users = [];
  refreshTokens = [];
  apiKeys = [];
  auditLogs = [];
  passkeys = [];
  membershipWrites = 0;
  failedAttempts.length = 0;
  providerIdentity = {
    providerId: 'google-sub-1',
    email: 'victim@example.com',
    emailVerified: true,
    name: 'Real Owner',
    avatarUrl: null,
  };
});

describe('OAuth sign-in onto an unverified account (FINDING-001)', () => {
  it('drops the pre-registered password, tokens, sessions and API keys', async () => {
    // Arrange: an account someone else registered for the victim's address.
    const account = seedUser({
      passwordHash: await hashPassword(ATTACKER_PASSWORD),
      emailVerifyToken: 'verify-token',
      passwordResetToken: 'reset-token-hash',
      passwordResetExpires: new Date(Date.now() + 3_600_000),
    });
    refreshTokens.push({ userId: account.id, revokedAt: null, origin: 'seeded' });
    apiKeys.push({ id: 'key_1', createdByUserId: account.id, revokedAt: null });

    // Act: the real owner signs in with a provider-verified email.
    const res = await oauthCallback();

    // Assert
    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toContain(`${BASE}/dashboard#jwt=`);
    expect(account.emailVerified).toBe(true);
    expect(account.providerId).toBe('google-sub-1');
    expect(account.passwordHash).toBe('');
    expect(account.emailVerifyToken).toBeNull();
    expect(account.passwordResetToken).toBeNull();
    expect(account.passwordResetExpires).toBeNull();
    expect(refreshTokens.find((t) => t.origin === 'seeded')!.revokedAt).toBeInstanceOf(Date);
    expect(apiKeys[0].revokedAt).toBeInstanceOf(Date);
    expect(auditLogs).toHaveLength(1);
    expect(auditLogs[0]).toMatchObject({
      action: 'auth.unverified_account_claimed',
      userId: account.id,
      organizationId: ORG.id,
    });
    expect(auditLogs[0].metadata).toMatchObject({ via: 'oauth', refreshTokensRevoked: 1, apiKeysRevoked: 1 });
  });

  it('the pre-registered password no longer signs in after the claim', async () => {
    const account = seedUser({ passwordHash: await hashPassword(ATTACKER_PASSWORD) });
    await oauthCallback();

    const res = await login('victim@example.com', ATTACKER_PASSWORD);

    expect(res.statusCode).toBe(401);
    expect(res.json().message).toBe('Invalid credentials.');
    expect(failedAttempts).toEqual([account.id]);
  });

  it('the session issued by the claiming sign-in itself stays valid', async () => {
    const account = seedUser({ passwordHash: await hashPassword(ATTACKER_PASSWORD) });

    await oauthCallback();

    const live = refreshTokens.filter((t) => t.userId === account.id && t.revokedAt === null);
    expect(live).toHaveLength(1);
  });

  it('leaves an already-verified account and its password untouched', async () => {
    const passwordHash = await hashPassword('owner-password-1');
    const account = seedUser({ passwordHash, emailVerified: true });
    refreshTokens.push({ userId: account.id, revokedAt: null, origin: 'seeded' });
    apiKeys.push({ id: 'key_1', createdByUserId: account.id, revokedAt: null });

    const res = await oauthCallback();

    expect(res.statusCode).toBe(302);
    expect(account.passwordHash).toBe(passwordHash);
    expect(account.providerId).toBe('google-sub-1');
    expect(refreshTokens.find((t) => t.origin === 'seeded')!.revokedAt).toBeNull();
    expect(apiKeys[0].revokedAt).toBeNull();
    expect(auditLogs).toHaveLength(0);
  });
});

describe('OAuth sign-in onto an unverified account that already has a provider link', () => {
  it('is refused and leaves the account, its passkeys and memberships unchanged', async () => {
    // Arrange: created through the Microsoft sign-in-name path, so the email
    // was never proven, and it has since registered a passkey.
    const account = seedUser({
      provider: 'MICROSOFT',
      providerId: 'ms-oid-1',
      emailVerified: false,
    });
    passkeys.push({ id: 'pk_1', userId: account.id, revokedAt: null });
    refreshTokens.push({ userId: account.id, revokedAt: null, origin: 'seeded' });
    const accountBefore = structuredClone(account);
    const passkeysBefore = structuredClone(passkeys);

    // Act: Google proves the same address for someone else.
    const res = await oauthCallback();

    // Assert: generic failure page, nothing merged, nothing issued.
    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toContain('error=failed');
    expect(res.headers.location).not.toContain('jwt=');
    expect(account).toEqual(accountBefore);
    expect(passkeys).toEqual(passkeysBefore);
    expect(membershipWrites).toBe(0);
    expect(users).toHaveLength(1);
    expect(refreshTokens).toEqual([{ userId: account.id, revokedAt: null, origin: 'seeded' }]);
    expect(auditLogs).toHaveLength(0);
  });
});

describe('password login for an account with no password', () => {
  it('fails exactly like a wrong password', async () => {
    const account = seedUser({ passwordHash: '', emailVerified: true });
    const wrong = seedUser({
      email: 'other@example.com',
      passwordHash: await hashPassword('the-right-password-1'),
      emailVerified: true,
    });

    const noPassword = await login('victim@example.com', '');
    const emptyHash = await login('victim@example.com', 'anything-at-all');
    const wrongPassword = await login('other@example.com', 'not-the-right-one');

    expect(noPassword.statusCode).toBe(400); // schema: password is required
    expect(emptyHash.statusCode).toBe(401);
    expect(emptyHash.json()).toEqual(wrongPassword.json());
    expect(failedAttempts).toEqual([account.id, wrong.id]);
  });
});

describe('email case normalisation', () => {
  it('refuses signup with a case variant of an existing address', async () => {
    seedUser({ email: 'victim@example.com', emailVerified: true });

    const res = await signup('Victim@Example.COM');

    expect(res.statusCode).toBe(400);
    expect(users).toHaveLength(1);
  });

  it('refuses a lowercase signup when a mixed-case row already exists', async () => {
    seedUser({ email: 'Victim@Example.com', emailVerified: true });

    const res = await signup('victim@example.com');

    expect(res.statusCode).toBe(400);
    expect(users).toHaveLength(1);
  });

  it('stores a new signup lowercased and trimmed', async () => {
    const res = await signup('  New.Person@Example.COM ');

    expect(res.statusCode).toBe(202);
    expect(users[0].email).toBe('new.person@example.com');
  });

  it('stores an account created by OAuth sign-in lowercased', async () => {
    providerIdentity = { ...providerIdentity, email: 'New.Owner@Example.COM' };

    const res = await oauthCallback();

    expect(res.statusCode).toBe(302);
    expect(users[0].email).toBe('new.owner@example.com');
  });

  it('password login finds the account whatever case is typed', async () => {
    seedUser({ passwordHash: await hashPassword('owner-password-1'), emailVerified: true });

    const res = await login('VICTIM@example.com', 'owner-password-1');

    expect(res.statusCode).toBe(200);
  });

  it('password login looks up the lowercased address only', async () => {
    // Existing rows are lowercased by migration 20261012130000, so no row is
    // ever looked up by the address exactly as typed.
    seedUser({
      email: 'Legacy@Example.com',
      passwordHash: await hashPassword('owner-password-1'),
      emailVerified: true,
    });

    const res = await login('Legacy@Example.com', 'owner-password-1');

    expect(res.statusCode).toBe(401);
  });
});

describe('OAuth sign-in from the hosted approval page', () => {
  const TOKEN = `as_${'B'.repeat(32)}`;

  it('returns to the approval page with the same-device flag kept', async () => {
    seedUser({ emailVerified: true, provider: 'GOOGLE', providerId: 'google-sub-1' });

    const res = await oauthCallback({ authSessionToken: TOKEN, sameDevice: true });

    expect(res.headers.location).toMatch(new RegExp(`^${BASE}/a/${TOKEN}\\?dr=1#jwt=`));
  });

  it('returns without the flag for a scanned (cross-device) approval', async () => {
    seedUser({ emailVerified: true, provider: 'GOOGLE', providerId: 'google-sub-1' });

    const res = await oauthCallback({ authSessionToken: TOKEN });

    expect(res.headers.location).toMatch(new RegExp(`^${BASE}/a/${TOKEN}#jwt=`));
  });

  it('drops a malformed approval token from the state instead of building a URL from it', async () => {
    seedUser({ emailVerified: true, provider: 'GOOGLE', providerId: 'google-sub-1' });

    const res = await oauthCallback({ authSessionToken: 'as_x?next=//evil.example#', sameDevice: true });

    expect(res.headers.location).not.toContain('/a/');
    expect(res.headers.location).toMatch(new RegExp(`^${BASE}/dashboard#jwt=`));
  });
});
