import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import {
  AuthSessionService,
  CliExchangeError,
  verifyCodeChallenge,
} from '../auth-session.js';
import { deriveCliVerificationCode } from '@qrauth/shared';
import { revokeCliKeysForMember } from '../cli-keys.js';

// S256 PKCE challenge for a given verifier (matches verifyCodeChallenge).
function challengeFor(verifier: string): string {
  return createHash('sha256').update(verifier, 'ascii').digest('base64url');
}

interface FakeSession {
  id: string;
  appId: string;
  status: string;
  userId: string | null;
  codeChallenge: string | null;
  targetOrganizationId: string | null;
  exchangedAt: Date | null;
}
interface FakeMembership { userId: string; organizationId: string; role: string }
interface FakeApiKey {
  id: string;
  organizationId: string;
  createdByUserId: string | null;
  source: string | null;
  revokedAt: Date | null;
}

/**
 * Minimal stateful in-memory Prisma double — only the methods the CLI-auth
 * paths touch. Mirrors the repo convention of hand-rolled fakes over a live DB.
 */
function makeFakePrisma(opts: {
  session?: FakeSession | null;
  memberships?: FakeMembership[];
  apiKeys?: FakeApiKey[];
  orgs?: Record<string, { slug: string }>;
}) {
  const state = {
    session: opts.session ?? null,
    memberships: opts.memberships ?? [],
    apiKeys: opts.apiKeys ?? [],
    orgs: opts.orgs ?? {},
    created: [] as Array<Record<string, unknown>>,
  };
  const prisma = {
    authSession: {
      findUnique: async ({ where }: any) =>
        state.session && state.session.id === where.id ? { ...state.session } : null,
      updateMany: async ({ where, data }: any) => {
        const s = state.session;
        if (!s || s.id !== where.id) return { count: 0 };
        if (where.status && s.status !== where.status) return { count: 0 };
        if ('exchangedAt' in where && where.exchangedAt === null && s.exchangedAt !== null) {
          return { count: 0 };
        }
        Object.assign(s, data);
        return { count: 1 };
      },
    },
    membership: {
      findUnique: async ({ where }: any) => {
        const { userId, organizationId } = where.userId_organizationId;
        const m = state.memberships.find((x) => x.userId === userId && x.organizationId === organizationId);
        return m ? { role: m.role } : null;
      },
      findMany: async ({ where }: any) =>
        state.memberships
          .filter((m) => m.userId === where.userId)
          .map((m) => ({ organizationId: m.organizationId, role: m.role })),
    },
    apiKey: {
      create: async ({ data }: any) => {
        const key = { id: `key_${state.created.length + 1}`, ...data };
        state.created.push(key);
        state.apiKeys.push({ ...(key as any), revokedAt: null });
        return key;
      },
      updateMany: async ({ where, data }: any) => {
        let count = 0;
        for (const k of state.apiKeys) {
          if (where.organizationId && k.organizationId !== where.organizationId) continue;
          if (where.createdByUserId && k.createdByUserId !== where.createdByUserId) continue;
          if (where.source && k.source !== where.source) continue;
          if ('revokedAt' in where && where.revokedAt === null && k.revokedAt !== null) continue;
          Object.assign(k, data);
          count++;
        }
        return { count };
      },
    },
    organization: {
      findUnique: async ({ where }: any) =>
        state.orgs[where.id] ? { slug: state.orgs[where.id].slug } : null,
    },
    $transaction: async (cb: any) => cb(prisma),
  };
  return { prisma, state };
}

function makeService(prisma: unknown): AuthSessionService {
  // signingService is unused on the CLI-auth paths under test.
  return new AuthSessionService(prisma as any, {} as any);
}

const CLI_APP_ID = 'app_qrauth_cli';
const VERIFIER = 'verifier-abc-123-this-is-long-enough';

function approvedSession(overrides: Partial<FakeSession> = {}): FakeSession {
  return {
    id: 's1',
    appId: CLI_APP_ID,
    status: 'APPROVED',
    userId: 'u1',
    codeChallenge: challengeFor(VERIFIER),
    targetOrganizationId: 'org1',
    exchangedAt: null,
    ...overrides,
  };
}

describe('deriveCliVerificationCode', () => {
  it('formats as XXXX-XXXX uppercase hex', async () => {
    expect(await deriveCliVerificationCode('sess_abc')).toMatch(/^[0-9A-F]{4}-[0-9A-F]{4}$/);
  });

  it('is deterministic for the same session id', async () => {
    expect(await deriveCliVerificationCode('sess_abc')).toBe(await deriveCliVerificationCode('sess_abc'));
  });

  it('differs across session ids', async () => {
    expect(await deriveCliVerificationCode('sess_abc')).not.toBe(await deriveCliVerificationCode('sess_xyz'));
  });
});

describe('verifyCodeChallenge', () => {
  it('accepts the matching verifier and rejects others', () => {
    const challenge = challengeFor(VERIFIER);
    expect(verifyCodeChallenge(VERIFIER, challenge)).toBe(true);
    expect(verifyCodeChallenge('wrong-verifier', challenge)).toBe(false);
  });
});

describe('AuthSessionService.resolveSoleCliMembership', () => {
  it('returns the sole membership', async () => {
    const { prisma } = makeFakePrisma({ memberships: [{ userId: 'u1', organizationId: 'org1', role: 'ADMIN' }] });
    const result = await makeService(prisma).resolveSoleCliMembership('u1');
    expect(result).toEqual({ organizationId: 'org1', role: 'ADMIN' });
  });

  it('rejects an approver with more than one membership (multi-org not supported)', async () => {
    const { prisma } = makeFakePrisma({
      memberships: [
        { userId: 'u1', organizationId: 'org1', role: 'ADMIN' },
        { userId: 'u1', organizationId: 'org2', role: 'MEMBER' },
      ],
    });
    await expect(makeService(prisma).resolveSoleCliMembership('u1')).rejects.toMatchObject({
      code: 'CLI_MULTI_ORG',
      statusCode: 409,
    });
  });

  it('rejects an approver with no membership', async () => {
    const { prisma } = makeFakePrisma({ memberships: [] });
    await expect(makeService(prisma).resolveSoleCliMembership('u1')).rejects.toMatchObject({
      code: 'CLI_NO_MEMBERSHIP',
      statusCode: 403,
    });
  });
});

describe('AuthSessionService.exchangeForApiKey', () => {
  const baseOpts = () => ({
    session: approvedSession(),
    memberships: [{ userId: 'u1', organizationId: 'org1', role: 'ADMIN' }],
    orgs: { org1: { slug: 'acme' } },
  });

  it('mints an org-scoped, role-mirrored, source=cli key on the happy path', async () => {
    const { prisma, state } = makeFakePrisma(baseOpts());
    const result = await makeService(prisma).exchangeForApiKey({
      sessionId: 's1',
      cliAppId: CLI_APP_ID,
      codeVerifier: VERIFIER,
      hostLabel: 'mybox',
    });

    expect(result.apiKey).toMatch(/^qrauth_[0-9a-f]{64}$/);
    expect(result.organizationId).toBe('org1');
    expect(result.orgSlug).toBe('acme');
    expect(result.role).toBe('ADMIN');

    expect(state.created).toHaveLength(1);
    expect(state.created[0]).toMatchObject({
      organizationId: 'org1',
      role: 'ADMIN',
      source: 'cli',
      createdByUserId: 'u1',
    });
    expect(state.created[0].label).toMatch(/^cli:mybox:\d{4}-\d{2}-\d{2}$/);
    // single-use guard consumed
    expect(state.session!.exchangedAt).not.toBeNull();
  });

  it('rejects a replayed exchange once exchangedAt is set', async () => {
    const { prisma } = makeFakePrisma(baseOpts());
    const svc = makeService(prisma);
    await svc.exchangeForApiKey({ sessionId: 's1', cliAppId: CLI_APP_ID, codeVerifier: VERIFIER });
    await expect(
      svc.exchangeForApiKey({ sessionId: 's1', cliAppId: CLI_APP_ID, codeVerifier: VERIFIER }),
    ).rejects.toMatchObject({ code: 'ALREADY_EXCHANGED', statusCode: 409 });
  });

  it('rejects a mismatched code_verifier with 403', async () => {
    const { prisma } = makeFakePrisma(baseOpts());
    await expect(
      makeService(prisma).exchangeForApiKey({ sessionId: 's1', cliAppId: CLI_APP_ID, codeVerifier: 'wrong' }),
    ).rejects.toMatchObject({ code: 'INVALID_VERIFIER', statusCode: 403 });
  });

  it('rejects a session that is not APPROVED', async () => {
    const { prisma } = makeFakePrisma({ ...baseOpts(), session: approvedSession({ status: 'PENDING' }) });
    await expect(
      makeService(prisma).exchangeForApiKey({ sessionId: 's1', cliAppId: CLI_APP_ID, codeVerifier: VERIFIER }),
    ).rejects.toMatchObject({ code: 'NOT_APPROVED', statusCode: 409 });
  });

  it('treats a session owned by a different app as not found', async () => {
    const { prisma } = makeFakePrisma({ ...baseOpts(), session: approvedSession({ appId: 'app_other' }) });
    await expect(
      makeService(prisma).exchangeForApiKey({ sessionId: 's1', cliAppId: CLI_APP_ID, codeVerifier: VERIFIER }),
    ).rejects.toMatchObject({ code: 'SESSION_NOT_FOUND', statusCode: 404 });
  });

  it('refuses to mint when the approver membership is gone', async () => {
    const { prisma } = makeFakePrisma({ ...baseOpts(), memberships: [] });
    await expect(
      makeService(prisma).exchangeForApiKey({ sessionId: 's1', cliAppId: CLI_APP_ID, codeVerifier: VERIFIER }),
    ).rejects.toMatchObject({ code: 'MEMBERSHIP_REVOKED', statusCode: 403 });
  });

  it('throws CliExchangeError instances (route maps statusCode/code)', async () => {
    const { prisma } = makeFakePrisma({ ...baseOpts(), memberships: [] });
    await expect(
      makeService(prisma).exchangeForApiKey({ sessionId: 's1', cliAppId: CLI_APP_ID, codeVerifier: VERIFIER }),
    ).rejects.toBeInstanceOf(CliExchangeError);
  });
});

describe('revokeCliKeysForMember (membership-removal cascade)', () => {
  it('revokes only the active cli keys minted by that user for that org', async () => {
    const { prisma, state } = makeFakePrisma({
      apiKeys: [
        { id: 'k1', organizationId: 'org1', createdByUserId: 'u1', source: 'cli', revokedAt: null }, // revoke
        { id: 'k2', organizationId: 'org1', createdByUserId: 'u1', source: 'dashboard', revokedAt: null }, // keep (source)
        { id: 'k3', organizationId: 'org2', createdByUserId: 'u1', source: 'cli', revokedAt: null }, // keep (org)
        { id: 'k4', organizationId: 'org1', createdByUserId: 'u2', source: 'cli', revokedAt: null }, // keep (user)
        { id: 'k5', organizationId: 'org1', createdByUserId: 'u1', source: 'cli', revokedAt: new Date() }, // keep (already)
      ],
    });

    const count = await revokeCliKeysForMember(prisma as any, 'org1', 'u1');
    expect(count).toBe(1);

    const byId = Object.fromEntries(state.apiKeys.map((k) => [k.id, k]));
    expect(byId.k1.revokedAt).not.toBeNull();
    expect(byId.k2.revokedAt).toBeNull();
    expect(byId.k3.revokedAt).toBeNull();
    expect(byId.k4.revokedAt).toBeNull();
  });
});
