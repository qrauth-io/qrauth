import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * POST /organizations/invitations/:token/accept — the invitation address must
 * match the signed-in user AND that user must have verified the address. Real
 * route, stubbed `authenticate` (x-test-email) and `prisma`.
 */

beforeAll(() => {
  process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
  process.env.REDIS_URL = 'redis://localhost:6379';
  process.env.JWT_SECRET = 'a'.repeat(32);
  process.env.ANIMATED_QR_SECRET = 'a'.repeat(64);
});

const INVITED = 'invitee@corp.example';
const TOKEN = 'inv_token_1';

interface Harness {
  app: FastifyInstance;
  membershipCreates: Array<Record<string, unknown>>;
  invitationUpdates: Array<Record<string, unknown>>;
  auditEntries: Array<Record<string, unknown>>;
}

interface Options {
  /** The user already belongs to the invitation's organization. */
  alreadyMember?: boolean;
  /** Another request used the invitation first (the conditional claim matches nothing). */
  claimLost?: boolean;
}

async function buildApp(emailVerified: boolean | null, options: Options = {}): Promise<Harness> {
  const membershipCreates: Array<Record<string, unknown>> = [];
  const invitationUpdates: Array<Record<string, unknown>> = [];
  const auditEntries: Array<Record<string, unknown>> = [];
  const invitation = {
    id: 'inv_1', token: TOKEN, email: INVITED, role: 'MEMBER', organizationId: 'o_target',
    invitedBy: 'u_owner', acceptedAt: null, expiresAt: new Date(Date.now() + 86_400_000),
  };

  const prisma: Record<string, unknown> = {
    invitation: {
      findUnique: async () => invitation,
      updateMany: ({ where, data }: { where: Record<string, unknown>; data: Record<string, unknown> }) => {
        // Claimed only while still pending.
        expect(where).toMatchObject({ id: 'inv_1', acceptedAt: null });
        if (options.claimLost) return Promise.resolve({ count: 0 });
        invitationUpdates.push(data);
        return Promise.resolve({ count: 1 });
      },
    },
    user: {
      findUnique: async () => (emailVerified === null ? null : { emailVerified }),
    },
    organization: {
      findUnique: async () => ({ name: 'Target Org' }),
    },
    membership: {
      findUnique: async () => (options.alreadyMember ? { id: 'm_existing' } : null),
      create: ({ data }: { data: Record<string, unknown> }) => {
        membershipCreates.push(data);
        return Promise.resolve({ id: 'm_1', joinedAt: new Date(), ...data });
      },
    },
    auditLog: {
      create: async ({ data }: { data: Record<string, unknown> }) => {
        auditEntries.push(data);
        return data;
      },
    },
  };
  prisma.$transaction = async (fn: (tx: unknown) => Promise<unknown>) => fn(prisma);

  const app = Fastify({ logger: false });
  app.decorate('prisma', prisma as never);
  app.decorate('signingService', {} as never);
  app.decorate('authenticate', async (req: never) => {
    const request = req as unknown as { headers: Record<string, string>; user?: unknown };
    request.user = { id: 'u_invitee', orgId: 'o_own', role: 'OWNER', email: request.headers['x-test-email'] };
  });

  const { default: organizationRoutes } = await import('../organizations.js');
  await app.register(organizationRoutes, { prefix: '/api/v1/organizations' });
  await app.ready();
  return { app, membershipCreates, invitationUpdates, auditEntries };
}

function accept(app: FastifyInstance, email: string) {
  return app.inject({
    method: 'POST',
    url: `/api/v1/organizations/invitations/${TOKEN}/accept`,
    headers: { 'x-test-email': email },
  });
}

describe('POST /organizations/invitations/:token/accept', () => {
  let current: Harness | null = null;

  afterEach(async () => {
    await current?.app.close();
    current = null;
  });

  it('a verified user whose address matches accepts the invitation', async () => {
    current = await buildApp(true);

    const res = await accept(current.app, INVITED);

    expect(res.statusCode).toBe(201);
    expect(res.json()).toMatchObject({ userId: 'u_invitee', organizationId: 'o_target', role: 'MEMBER' });
    expect(current.membershipCreates).toHaveLength(1);
    expect(current.invitationUpdates).toEqual([{ acceptedAt: expect.any(Date) }]);
    // Logged in the organization joined, with the accepting user as actor.
    expect(current.auditEntries).toEqual([expect.objectContaining({
      organizationId: 'o_target',
      action: 'invitation.accept',
      resource: 'Invitation',
      resourceId: 'inv_1',
      actorType: 'USER',
      actorId: 'u_invitee',
      metadata: { invitationId: expect.any(String), role: 'MEMBER', invitedBy: 'u_owner' },
    })]);
  });

  it('an existing member gets a 409 and nothing changes', async () => {
    current = await buildApp(true, { alreadyMember: true });

    const res = await accept(current.app, INVITED);

    expect(res.statusCode).toBe(409);
    expect(current.membershipCreates).toHaveLength(0);
    expect(current.invitationUpdates).toHaveLength(0);
    expect(current.auditEntries).toHaveLength(0);
  });

  it('an invitation used by a concurrent request is refused without a membership', async () => {
    current = await buildApp(true, { claimLost: true });

    const res = await accept(current.app, INVITED);

    expect(res.statusCode).toBe(400);
    expect(current.membershipCreates).toHaveLength(0);
    expect(current.auditEntries).toHaveLength(0);
  });

  it('GET /invitations/:token shows the organization, address and role without signing in', async () => {
    current = await buildApp(true);

    const res = await current.app.inject({ method: 'GET', url: `/api/v1/organizations/invitations/${TOKEN}` });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({
      organizationName: 'Target Org',
      email: INVITED,
      role: 'MEMBER',
      expiresAt: expect.any(String),
    });
    // The token itself is never echoed back.
    expect(res.body).not.toContain(TOKEN);
  });

  it('an UNVERIFIED user whose address matches gets a clear 403 and the invitation stays pending', async () => {
    current = await buildApp(false);

    const res = await accept(current.app, INVITED);

    expect(res.statusCode).toBe(403);
    expect(res.json()).toMatchObject({ message: 'Verify your email address to accept this invitation' });
    expect(current.membershipCreates).toHaveLength(0);
    expect(current.invitationUpdates).toHaveLength(0);
    expect(current.auditEntries).toHaveLength(0);
  });

  it('fails closed when the account row cannot be found', async () => {
    current = await buildApp(null);

    const res = await accept(current.app, INVITED);

    expect(res.statusCode).toBe(403);
    expect(current.membershipCreates).toHaveLength(0);
    expect(current.invitationUpdates).toHaveLength(0);
    expect(current.auditEntries).toHaveLength(0);
  });

  it('a different address is still refused with the existing message, verified or not', async () => {
    current = await buildApp(true);

    const res = await accept(current.app, 'someone-else@corp.example');

    expect(res.statusCode).toBe(403);
    expect(res.json()).toMatchObject({ message: 'This invitation was issued to a different email address.' });
    expect(current.membershipCreates).toHaveLength(0);
  });
});
