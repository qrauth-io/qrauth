import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { createHash } from 'node:crypto';

/**
 * Audit 2026-10 FINDING-001 follow-up: the first proof of email ownership on
 * an unverified account claims it, whatever the path — OAuth verified-email
 * sign-in, the verify-email link, or completing a password reset. Whatever
 * was attached to the account before that proof is removed. Real auth routes
 * and the real claim service over an in-memory Prisma stand-in.
 */

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);
process.env.WEBAUTHN_ORIGIN = 'https://qrauth.test';

vi.mock('../../lib/cache.js', () => ({
  redis: {},
  cacheGet: vi.fn(async () => null),
  cacheSet: vi.fn(async () => undefined),
  cacheDel: vi.fn(async () => undefined),
  disconnectCache: vi.fn(async () => undefined),
}));

const sentVerification: Array<{ to: string; token: string }> = [];
vi.mock('../../lib/email.js', () => ({
  sendPasswordResetEmail: vi.fn(async () => undefined),
  sendWelcomeVerificationEmail: vi.fn(async (to: string, _name: string, _org: string, token: string) => {
    sentVerification.push({ to, token });
  }),
  sendPasswordChangedEmail: vi.fn(async () => undefined),
  sendSuspiciousLoginEmail: vi.fn(async () => undefined),
}));

const { hashPassword, verifyPassword } = await import('../../lib/password.js');
const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');

// ---------------------------------------------------------------------------
// In-memory Prisma stand-in: only the calls these paths make.
// ---------------------------------------------------------------------------

interface UserRow {
  id: string;
  name: string;
  email: string;
  passwordHash: string;
  emailVerified: boolean;
  emailVerifyToken: string | null;
  emailVerifyExpires: Date | null;
  passwordResetToken: string | null;
  passwordResetExpires: Date | null;
  provider: string;
  providerId: string | null;
  avatarUrl: string | null;
  lastLoginAt: Date | null;
}
interface Owned { userId: string; revokedAt: Date | null }

const USER = 'user_1';
const BYSTANDER = 'user_2';
const VERIFY_TOKEN = 'verify-token';
const RESET_TOKEN = 'reset-token';
const CREATOR_PASSWORD = 'creator-chosen-password-1';

let users: UserRow[] = [];
let passkeys: Array<{ id: string; userId: string }> = [];
let devices: Array<{ id: string; userId: string }> = [];
let refreshTokens: Owned[] = [];
let apiKeys: Array<{ createdByUserId: string | null; organizationId: string; source: string; revokedAt: Date | null }> = [];
let oidcConsents: Owned[] = [];
let invitations: Array<{ id: string; invitedBy: string; acceptedAt: Date | null }> = [];
let approvals: Array<{ userId: string; status: string; exchangedAt: Date | null }> = [];
let oidcSessions: Owned[] = [];
let oidcRefreshTokens: Owned[] = [];
let oidcAccessTokens: Owned[] = [];
let oidcAuthCodes: Array<{ userId: string; usedAt: Date | null }> = [];
let memberships: Array<{ id: string; userId: string; organizationId: string; role: string; joinedAt: Date }> = [];
let auditLogs: Array<Record<string, any>> = [];

const deleteForUser = <T extends { userId: string }>(get: () => T[], set: (rows: T[]) => void) =>
  async ({ where }: any) => {
    const before = get().length;
    set(get().filter((row) => row.userId !== where.userId));
    return { count: before - get().length };
  };
const revokeForUser = (get: () => Owned[]) => async ({ where, data }: any) => {
  const hit = get().filter((row) => row.userId === where.userId && row.revokedAt === null);
  hit.forEach((row) => { row.revokedAt = data.revokedAt; });
  return { count: hit.length };
};

function matchesUser(user: UserRow, where: Record<string, any>): boolean {
  if (where.id !== undefined && user.id !== where.id) return false;
  if (where.email !== undefined && user.email !== where.email) return false;
  if (where.emailVerifyToken !== undefined && user.emailVerifyToken !== where.emailVerifyToken) return false;
  if (where.passwordResetToken !== undefined && user.passwordResetToken !== where.passwordResetToken) return false;
  if (where.passwordResetExpires?.gt && !(user.passwordResetExpires && user.passwordResetExpires > where.passwordResetExpires.gt)) {
    return false;
  }
  return true;
}

const prisma: Record<string, any> = {
  user: {
    findUnique: async ({ where, include }: any) => {
      const user = users.find((u) => matchesUser(u, where));
      if (!user) return null;
      return include?.memberships
        ? { ...user, memberships: memberships.filter((m) => m.userId === user.id).map((m) => ({ ...m, organization: { name: 'Org' } })) }
        : { ...user };
    },
    findFirst: async ({ where }: any) => {
      const user = users.find((u) => matchesUser(u, where));
      return user ? { ...user } : null;
    },
    update: async ({ where, data }: any) => {
      const user = users.find((u) => u.id === where.id)!;
      for (const [key, value] of Object.entries(data)) {
        if (value !== undefined) (user as any)[key] = value;
      }
      return { ...user };
    },
  },
  passkey: { deleteMany: deleteForUser(() => passkeys, (rows) => { passkeys = rows; }) },
  trustedDevice: { deleteMany: deleteForUser(() => devices, (rows) => { devices = rows; }) },
  refreshToken: { updateMany: revokeForUser(() => refreshTokens) },
  apiKey: {
    updateMany: async ({ where, data }: any) => {
      const [byCreator, byOwnedOrg] = where.OR;
      const hit = apiKeys.filter(
        (k) =>
          k.revokedAt === null &&
          (k.createdByUserId === byCreator.createdByUserId ||
            (k.createdByUserId === null && byOwnedOrg.organizationId.in.includes(k.organizationId))),
      );
      hit.forEach((k) => { k.revokedAt = data.revokedAt; });
      return { count: hit.length };
    },
  },
  oidcConsent: { updateMany: revokeForUser(() => oidcConsents) },
  invitation: {
    deleteMany: async ({ where }: any) => {
      const before = invitations.length;
      invitations = invitations.filter((i) => !(i.invitedBy === where.invitedBy && i.acceptedAt === null));
      return { count: before - invitations.length };
    },
  },
  authSession: {
    updateMany: async ({ where, data }: any) => {
      const hit = approvals.filter((a) => a.userId === where.userId && a.status === where.status && a.exchangedAt === null);
      hit.forEach((a) => { a.status = data.status; });
      return { count: hit.length };
    },
  },
  oidcSession: { updateMany: revokeForUser(() => oidcSessions) },
  oidcRefreshToken: { updateMany: revokeForUser(() => oidcRefreshTokens) },
  oidcAccessToken: { updateMany: revokeForUser(() => oidcAccessTokens) },
  oidcAuthCode: {
    updateMany: async ({ where, data }: any) => {
      const hit = oidcAuthCodes.filter((c) => c.userId === where.userId && c.usedAt === null);
      hit.forEach((c) => { c.usedAt = data.usedAt; });
      return { count: hit.length };
    },
  },
  membership: {
    findFirst: async ({ where }: any) => memberships.find((m) => m.userId === where.userId) ?? null,
    findMany: async ({ where }: any) =>
      memberships.filter((m) => {
        if (where.userId !== undefined && typeof where.userId === 'string' && m.userId !== where.userId) return false;
        if (where.userId?.not !== undefined && m.userId === where.userId.not) return false;
        if (where.role !== undefined && m.role !== where.role) return false;
        if (where.organizationId?.in && !where.organizationId.in.includes(m.organizationId)) return false;
        return true;
      }),
  },
  auditLog: {
    create: async ({ data }: any) => {
      auditLogs.push(data);
      return data;
    },
  },
  $transaction: async (fn: (tx: unknown) => Promise<unknown>) => fn(prisma),
};

/** An unverified account with everything a creator could have attached to it. */
async function seedUnverifiedAccount(overrides: Partial<UserRow> = {}): Promise<UserRow> {
  const user: UserRow = {
    id: USER,
    name: 'Someone',
    email: 'owner@example.com',
    passwordHash: await hashPassword(CREATOR_PASSWORD),
    emailVerified: false,
    emailVerifyToken: VERIFY_TOKEN,
    emailVerifyExpires: new Date(Date.now() + 3_600_000),
    passwordResetToken: sha256(RESET_TOKEN),
    passwordResetExpires: new Date(Date.now() + 3_600_000),
    provider: 'MICROSOFT',
    providerId: 'ms-oid-1',
    avatarUrl: null,
    lastLoginAt: null,
    ...overrides,
  };
  users = [user, { ...user, id: BYSTANDER, email: 'bystander@example.com', emailVerified: true, emailVerifyToken: null, passwordResetToken: null, providerId: null, provider: 'EMAIL' }];
  passkeys = [{ id: 'pk_1', userId: USER }, { id: 'pk_other', userId: BYSTANDER }];
  devices = [{ id: 'dev_1', userId: USER }, { id: 'dev_other', userId: BYSTANDER }];
  refreshTokens = [{ userId: USER, revokedAt: null }, { userId: BYSTANDER, revokedAt: null }];
  apiKeys = [
    { createdByUserId: USER, organizationId: 'org_1', source: 'dashboard', revokedAt: null },
    { createdByUserId: USER, organizationId: 'org_1', source: 'cli', revokedAt: null },
    // Organization-level key (no creator) in the organization the account owns.
    { createdByUserId: null, organizationId: 'org_1', source: 'dashboard', revokedAt: null },
    { createdByUserId: BYSTANDER, organizationId: 'org_1', source: 'cli', revokedAt: null },
    { createdByUserId: null, organizationId: 'org_elsewhere', source: 'dashboard', revokedAt: null },
  ];
  oidcConsents = [{ userId: USER, revokedAt: null }, { userId: BYSTANDER, revokedAt: null }];
  invitations = [
    { id: 'inv_pending', invitedBy: USER, acceptedAt: null },
    { id: 'inv_accepted', invitedBy: USER, acceptedAt: new Date() },
    { id: 'inv_other', invitedBy: BYSTANDER, acceptedAt: null },
  ];
  approvals = [
    { userId: USER, status: 'APPROVED', exchangedAt: null },
    { userId: USER, status: 'APPROVED', exchangedAt: new Date() },
    { userId: BYSTANDER, status: 'APPROVED', exchangedAt: null },
  ];
  oidcSessions = [{ userId: USER, revokedAt: null }, { userId: BYSTANDER, revokedAt: null }];
  oidcRefreshTokens = [{ userId: USER, revokedAt: null }];
  oidcAccessTokens = [{ userId: USER, revokedAt: null }];
  oidcAuthCodes = [{ userId: USER, usedAt: null }];
  memberships = [
    { id: 'm_owner', userId: USER, organizationId: 'org_1', role: 'OWNER', joinedAt: new Date('2026-01-01') },
    { id: 'm_invited', userId: BYSTANDER, organizationId: 'org_1', role: 'ADMIN', joinedAt: new Date('2026-01-02') },
  ];
  return user;
}

function expectClaimed(user: UserRow, via: string) {
  expect(user.emailVerified).toBe(true);
  expect(user.emailVerifyToken).toBeNull();
  expect(user.emailVerifyExpires).toBeNull();
  expect(user.passwordResetToken).toBeNull();
  expect(user.passwordResetExpires).toBeNull();
  // Everything attached before the proof is gone, and only this user's.
  expect(passkeys).toEqual([{ id: 'pk_other', userId: BYSTANDER }]);
  expect(devices).toEqual([{ id: 'dev_other', userId: BYSTANDER }]);
  expect(refreshTokens.map((t) => t.revokedAt !== null)).toEqual([true, false]);
  expect(apiKeys.map((k) => k.revokedAt !== null)).toEqual([true, true, true, false, false]);
  expect(oidcConsents.map((c) => c.revokedAt !== null)).toEqual([true, false]);
  expect(invitations.map((i) => i.id)).toEqual(['inv_accepted', 'inv_other']);
  expect(approvals.map((a) => a.status)).toEqual(['EXPIRED', 'APPROVED', 'APPROVED']);
  expect(oidcSessions.map((s) => s.revokedAt !== null)).toEqual([true, false]);
  expect(oidcRefreshTokens[0].revokedAt).toBeInstanceOf(Date);
  expect(oidcAccessTokens[0].revokedAt).toBeInstanceOf(Date);
  expect(oidcAuthCodes[0].usedAt).toBeInstanceOf(Date);
  // Other people's memberships in organizations the account owns stay, and
  // are listed for the owner to review.
  expect(memberships).toHaveLength(2);
  const claims = auditLogs.filter((row) => row.action === 'auth.unverified_account_claimed');
  expect(claims).toHaveLength(1);
  expect(claims[0]).toMatchObject({
    organizationId: 'org_1',
    userId: USER,
    resource: 'User',
    resourceId: USER,
  });
  expect(claims[0].metadata).toMatchObject({
    via,
    passkeysDeleted: 1,
    devicesDeleted: 1,
    refreshTokensRevoked: 1,
    apiKeysRevoked: 3,
    oidcConsentsRevoked: 1,
    invitationsCancelled: 1,
    pendingApprovalsExpired: 1,
    oidcSessionsRevoked: 1,
    oidcRefreshTokensRevoked: 1,
    oidcAccessTokensRevoked: 1,
    membershipsToReview: ['m_invited'],
  });
}

function expectNothingRemoved() {
  expect(passkeys).toHaveLength(2);
  expect(devices).toHaveLength(2);
  expect(apiKeys.every((k) => k.revokedAt === null)).toBe(true);
  expect(oidcSessions.every((s) => s.revokedAt === null)).toBe(true);
  expect(auditLogs.filter((a) => a.action === 'auth.unverified_account_claimed')).toHaveLength(0);
}

// ---------------------------------------------------------------------------

let app: FastifyInstance;

const verifyEmail = (token: string) =>
  app.inject({ method: 'GET', url: `/api/v1/auth/verify-email/${token}`, headers: { accept: 'application/json' } });
const resetPassword = (token: string, password: string) =>
  app.inject({ method: 'POST', url: '/api/v1/auth/reset-password', payload: { token, password } });

beforeAll(async () => {
  app = Fastify({ logger: false });
  await app.register((await import('@fastify/cookie')).default);
  await app.register((await import('@fastify/jwt')).default, { secret: 'b'.repeat(32) });
  app.decorate('prisma', prisma as never);
  app.decorate('signingService', {} as never);
  app.decorate('authenticate', async () => undefined);
  const { default: authRoutes } = await import('../auth.js');
  await app.register(authRoutes, { prefix: '/api/v1/auth' });
  await app.ready();
});

afterAll(async () => {
  await app?.close();
});

beforeEach(() => {
  auditLogs = [];
  sentVerification.length = 0;
});

describe('verify-email link on an unverified account', () => {
  it('claims the account: provider link, passkeys, devices, keys and sessions go; the password stays', async () => {
    const user = await seedUnverifiedAccount();
    const live = users[0];

    const res = await verifyEmail(VERIFY_TOKEN);

    expect(res.statusCode).toBe(200);
    expect(live.provider).toBe('EMAIL');
    expect(live.providerId).toBeNull();
    // A normal signup keeps the password it chose.
    expect(live.passwordHash).toBe(user.passwordHash);
    expect(await verifyPassword(CREATOR_PASSWORD, live.passwordHash)).toBe(true);
    expectClaimed(live, 'verify_email');
  });

  it('changes nothing but the verified flag for an ordinary signup with nothing attached', async () => {
    await seedUnverifiedAccount({ provider: 'EMAIL', providerId: null, passwordResetToken: null, passwordResetExpires: null });
    passkeys = []; devices = []; refreshTokens = []; apiKeys = []; oidcSessions = []; oidcRefreshTokens = []; oidcAccessTokens = []; oidcAuthCodes = [];
  oidcConsents = []; invitations = []; approvals = [];
    memberships = [memberships[0]];
    const live = users[0];
    const passwordBefore = live.passwordHash;

    const res = await verifyEmail(VERIFY_TOKEN);

    expect(res.statusCode).toBe(200);
    expect(live.emailVerified).toBe(true);
    expect(live.passwordHash).toBe(passwordBefore);
    expect(live.provider).toBe('EMAIL');
  });

  it('refuses an expired link and leaves the account as it was', async () => {
    await seedUnverifiedAccount({ emailVerifyExpires: new Date(Date.now() - 1000) });

    const res = await verifyEmail(VERIFY_TOKEN);

    expect(res.statusCode).toBe(400);
    expect(users[0].emailVerified).toBe(false);
    expect(users[0].providerId).toBe('ms-oid-1');
    expectNothingRemoved();
  });

  it('refuses a link with no recorded expiry', async () => {
    await seedUnverifiedAccount({ emailVerifyExpires: null });

    const res = await verifyEmail(VERIFY_TOKEN);

    expect(res.statusCode).toBe(400);
    expect(users[0].emailVerified).toBe(false);
  });

  it('leaves an already verified account untouched', async () => {
    await seedUnverifiedAccount({ emailVerified: true });
    const before = structuredClone(users[0]);

    const res = await verifyEmail(VERIFY_TOKEN);

    expect(res.statusCode).toBe(200);
    expect(users[0].provider).toBe(before.provider);
    expect(users[0].providerId).toBe(before.providerId);
    expect(users[0].passwordHash).toBe(before.passwordHash);
    expectNothingRemoved();
  });
});

describe('password reset on an unverified account', () => {
  const NEW_PASSWORD = 'the-owners-new-password-1';

  it('claims the account and keeps only the password just set', async () => {
    await seedUnverifiedAccount();
    const live = users[0];

    const res = await resetPassword(RESET_TOKEN, NEW_PASSWORD);

    expect(res.statusCode).toBe(200);
    expect(live.provider).toBe('EMAIL');
    expect(live.providerId).toBeNull();
    expect(await verifyPassword(NEW_PASSWORD, live.passwordHash)).toBe(true);
    expect(await verifyPassword(CREATOR_PASSWORD, live.passwordHash)).toBe(false);
    expectClaimed(live, 'password_reset');
  });

  it('leaves an already verified account untouched apart from the new password and its sessions', async () => {
    await seedUnverifiedAccount({ emailVerified: true });
    const live = users[0];

    const res = await resetPassword(RESET_TOKEN, NEW_PASSWORD);

    expect(res.statusCode).toBe(200);
    expect(await verifyPassword(NEW_PASSWORD, live.passwordHash)).toBe(true);
    expect(live.provider).toBe('MICROSOFT');
    expect(live.providerId).toBe('ms-oid-1');
    expect(passkeys).toHaveLength(2);
    expect(devices).toHaveLength(2);
    expect(apiKeys.every((k) => k.revokedAt === null)).toBe(true);
    expect(auditLogs.filter((a) => a.action === 'auth.unverified_account_claimed')).toHaveLength(0);
  });
});

describe('OAuth verified-email sign-in (the path from #231), through the shared claim', () => {
  it('claims the account, drops the password and links the proven provider', async () => {
    await seedUnverifiedAccount({ provider: 'EMAIL', providerId: null });
    const live = users[0];
    const { applyVerifiedEmailSignIn } = await import('../../services/oauth-account-link.js');

    const result = await applyVerifiedEmailSignIn(prisma as never, {
      userId: USER,
      update: { lastLoginAt: new Date(), provider: 'GOOGLE', providerId: 'google-sub-1' },
    });

    expect(result.claimed).toBe(true);
    expect(live.passwordHash).toBe('');
    expect(live.provider).toBe('GOOGLE');
    expect(live.providerId).toBe('google-sub-1');
    expectClaimed(live, 'oauth');
  });
});

describe('the claim service on a provider-linked account, whatever the path', () => {
  it.each(['oauth', 'verify_email', 'password_reset'] as const)('via %s: everything attached is removed', async (via) => {
    await seedUnverifiedAccount();
    const live = users[0];
    const { claimUnverifiedAccount } = await import('../../services/account-claim.js');

    const result = await claimUnverifiedAccount(prisma as never, { userId: USER, via });

    expect(result.claimed).toBe(true);
    expect(live.provider).toBe('EMAIL');
    expect(live.providerId).toBeNull();
    expectClaimed(live, via);
  });
});

describe('verification links expire after 48 hours', () => {
  const HOURS_48 = 48 * 60 * 60 * 1000;

  it('resend-verification issues a new token with a 48 hour expiry', async () => {
    await seedUnverifiedAccount({ emailVerifyExpires: new Date(Date.now() - 1000) });
    const before = Date.now();

    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/resend-verification',
      payload: { email: 'owner@example.com' },
    });

    expect(res.statusCode).toBe(200);
    const live = users[0];
    expect(live.emailVerifyToken).not.toBe(VERIFY_TOKEN);
    expect(live.emailVerifyExpires!.getTime()).toBeGreaterThanOrEqual(before + HOURS_48 - 1000);
    expect(live.emailVerifyExpires!.getTime()).toBeLessThanOrEqual(Date.now() + HOURS_48 + 1000);
    expect(sentVerification).toEqual([{ to: 'owner@example.com', token: live.emailVerifyToken }]);

    // ...and the fresh link works.
    expect((await verifyEmail(live.emailVerifyToken!)).statusCode).toBe(200);
  });
});
