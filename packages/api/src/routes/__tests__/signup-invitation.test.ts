import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { Prisma } from '@prisma/client';

/**
 * POST /auth/signup with an invitation token: the account joins the inviting
 * organization (no new organization, no signing key), counts as verified
 * because the token reached the invited mailbox, and records invitation.accept
 * in the same transaction. A bad token, another address, a taken address or a
 * lost race is a 400 that creates nothing.
 */

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);
delete process.env.TURNSTILE_SECRET_KEY;
delete process.env.TURNSTILE_SITE_KEY;

vi.mock('../../lib/cache.js', () => ({
  redis: {},
  cacheGet: vi.fn(async () => null),
  cacheSet: vi.fn(async () => undefined),
  cacheDel: vi.fn(async () => undefined),
  disconnectCache: vi.fn(async () => undefined),
}));

const sendWelcomeVerificationEmail = vi.fn(async () => undefined);
vi.mock('../../lib/email.js', () => ({
  sendPasswordResetEmail: vi.fn(async () => undefined),
  sendWelcomeVerificationEmail,
  sendPasswordChangedEmail: vi.fn(async () => undefined),
  sendSuspiciousLoginEmail: vi.fn(async () => undefined),
}));

const INVITED = 'invitee@corp.example';
const TOKEN = 'a1'.repeat(32);

interface State {
  invitation: Record<string, unknown> | null;
  existingUsers: unknown[];
  claimCount: number;
  userCreateError: unknown;
}

let state: State;
let userCreates: Array<Record<string, any>>;
let orgCreates: number;
let membershipCreates: Array<Record<string, any>>;
let auditLogs: Array<Record<string, any>>;
let committed: boolean;
const createKeyPair = vi.fn(async () => ({}));

function pendingInvitation(overrides: Record<string, unknown> = {}) {
  return {
    id: 'inv_1', token: TOKEN, email: INVITED, role: 'ADMIN', organizationId: 'org_target',
    invitedBy: 'user_owner', acceptedAt: null, expiresAt: new Date(Date.now() + 86_400_000),
    ...overrides,
  };
}

const prisma: Record<string, any> = {
  user: {
    findMany: async () => state.existingUsers,
    create: async ({ data }: any) => {
      if (state.userCreateError) throw state.userCreateError;
      userCreates.push(data);
      return { id: 'user_new', ...data };
    },
  },
  invitation: {
    findUnique: async () => state.invitation,
    updateMany: async () => ({ count: state.claimCount }),
  },
  organization: {
    findUnique: async () => null,
    create: async ({ data }: any) => {
      orgCreates += 1;
      return { id: 'org_new', ...data };
    },
  },
  membership: {
    findUnique: async () => null,
    create: async ({ data }: any) => {
      membershipCreates.push(data);
      return { id: 'm_new', ...data };
    },
  },
  auditLog: {
    create: async ({ data }: any) => {
      auditLogs.push(data);
      return data;
    },
  },
  // Writes count only when the transaction commits (no throw).
  $transaction: async (fn: (tx: unknown) => Promise<unknown>) => {
    const snapshot = { users: userCreates.length, members: membershipCreates.length, audits: auditLogs.length };
    try {
      const result = await fn(prisma);
      committed = true;
      return result;
    } catch (err) {
      userCreates.length = snapshot.users;
      membershipCreates.length = snapshot.members;
      auditLogs.length = snapshot.audits;
      throw err;
    }
  },
};

let app: FastifyInstance;

beforeAll(async () => {
  app = Fastify({ logger: false });
  await app.register((await import('@fastify/cookie')).default);
  await app.register((await import('@fastify/jwt')).default, { secret: 'b'.repeat(32) });
  app.decorate('prisma', prisma as never);
  app.decorate('signingService', { createKeyPair } as never);
  app.decorate('authenticate', async () => undefined);
  const { default: authRoutes } = await import('../auth.js');
  await app.register(authRoutes, { prefix: '/api/v1/auth' });
  await app.ready();
});

afterAll(async () => {
  await app.close();
});

beforeEach(() => {
  state = { invitation: pendingInvitation(), existingUsers: [], claimCount: 1, userCreateError: null };
  userCreates = [];
  orgCreates = 0;
  membershipCreates = [];
  auditLogs = [];
  committed = false;
  vi.clearAllMocks();
});

function signup(payload: Record<string, unknown>) {
  return app.inject({
    method: 'POST',
    url: '/api/v1/auth/signup',
    payload: { name: 'Invited Person', email: INVITED, password: 'SecurePass123!', ...payload },
  });
}

describe('POST /auth/signup with an invitation', () => {
  it('joins the inviting organization with the invited role, verified, without a new organization', async () => {
    const res = await signup({ inviteToken: TOKEN });

    expect(res.statusCode).toBe(201);
    expect(res.json()).toMatchObject({ email: INVITED, requiresVerification: false });
    expect(userCreates).toEqual([expect.objectContaining({
      email: INVITED, emailVerified: true, onboardedAt: expect.any(Date),
    })]);
    expect(userCreates[0]).not.toHaveProperty('emailVerifyToken');
    expect(membershipCreates).toEqual([expect.objectContaining({
      userId: 'user_new', organizationId: 'org_target', role: 'ADMIN', invitedBy: 'user_owner',
    })]);
    expect(orgCreates).toBe(0);
    expect(createKeyPair).not.toHaveBeenCalled();
    expect(sendWelcomeVerificationEmail).not.toHaveBeenCalled();
    expect(auditLogs).toEqual([expect.objectContaining({
      organizationId: 'org_target',
      action: 'invitation.accept',
      resourceId: 'inv_1',
      actorType: 'USER',
      actorId: 'user_new',
    })]);
    expect(committed).toBe(true);
  });

  it('does not need an organization name, and ignores one if sent', async () => {
    const res = await signup({ inviteToken: TOKEN, organizationName: 'Should Not Exist' });

    expect(res.statusCode).toBe(201);
    expect(orgCreates).toBe(0);
  });

  it('matches the invited address case-insensitively', async () => {
    const res = await signup({ inviteToken: TOKEN, email: 'Invitee@Corp.Example' });

    expect(res.statusCode).toBe(201);
    expect(userCreates[0].email).toBe(INVITED);
  });

  it.each([
    ['unknown', null],
    ['already accepted', pendingInvitation({ acceptedAt: new Date() })],
    ['expired', pendingInvitation({ expiresAt: new Date(Date.now() - 1000) })],
  ])('refuses an %s invitation and creates nothing', async (_label, invitation) => {
    state.invitation = invitation;

    const res = await signup({ inviteToken: TOKEN });

    expect(res.statusCode).toBe(400);
    expect(res.json().message).toMatch(/invalid, expired, or has already been accepted/);
    expect(userCreates).toHaveLength(0);
    expect(orgCreates).toBe(0);
  });

  it('refuses an address other than the invited one', async () => {
    const res = await signup({ inviteToken: TOKEN, email: 'someone-else@corp.example' });

    expect(res.statusCode).toBe(400);
    expect(res.json().message).toBe('This invitation was sent to a different email address.');
    expect(userCreates).toHaveLength(0);
  });

  it('gives the usual generic refusal when the address already has an account', async () => {
    state.existingUsers = [{ id: 'user_existing', email: INVITED }];

    const res = await signup({ inviteToken: TOKEN });

    expect(res.statusCode).toBe(400);
    expect(res.json().message).toBe('Unable to create account. Please try a different email or sign in.');
    expect(userCreates).toHaveLength(0);
  });

  it('rolls the account back when a concurrent request used the invitation first', async () => {
    state.claimCount = 0;

    const res = await signup({ inviteToken: TOKEN });

    expect(res.statusCode).toBe(400);
    expect(userCreates).toHaveLength(0);
    expect(membershipCreates).toHaveLength(0);
    expect(auditLogs).toHaveLength(0);
  });

  it('turns a concurrent sign-up of the same address into the generic refusal, not a 500', async () => {
    state.userCreateError = new Prisma.PrismaClientKnownRequestError('Unique constraint failed', {
      code: 'P2002', clientVersion: 'test',
    });

    const res = await signup({ inviteToken: TOKEN });

    expect(res.statusCode).toBe(400);
    expect(res.json().message).toBe('Unable to create account. Please try a different email or sign in.');
  });
});

describe('POST /auth/signup without an invitation', () => {
  it('still requires an organization name', async () => {
    const res = await signup({});

    expect(res.statusCode).toBe(400);
    expect(userCreates).toHaveLength(0);
  });

  it('turns a unique-constraint race into the generic refusal, not a 500', async () => {
    state.userCreateError = new Prisma.PrismaClientKnownRequestError('Unique constraint failed', {
      code: 'P2002', clientVersion: 'test',
    });

    const res = await signup({ organizationName: 'New Org' });

    expect(res.statusCode).toBe(400);
    expect(res.json().message).toBe('Unable to create account. Please try a different email or sign in.');
    expect(createKeyPair).not.toHaveBeenCalled();
  });
});
