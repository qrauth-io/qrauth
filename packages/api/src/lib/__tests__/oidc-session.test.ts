import { describe, it, expect, beforeEach, beforeAll } from 'vitest';
import { createHash } from 'node:crypto';
import type { PrismaClient } from '@prisma/client';

beforeAll(() => {
  process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
  process.env.REDIS_URL ??= 'redis://localhost:6379';
  process.env.JWT_SECRET ??= 'a'.repeat(32);
  process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);
});

const sha256 = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');

interface FakeRow {
  sessionTokenHash: string;
  userId: string;
  expiresAt: Date;
  revokedAt: Date | null;
}

/**
 * Minimal in-memory fake of the prisma.oidcSession delegate. Rows are keyed
 * by their token hash in a Map so lookups never use `===` on the
 * crypto-named `sessionTokenHash` (AUDIT-FINDING-012 forbids `===` on
 * cryptographic strings; the production code uses a unique-index lookup, not
 * a comparison).
 */
function makeFakePrisma() {
  const byHash = new Map<string, FakeRow>();
  return {
    get rows(): FakeRow[] {
      return [...byHash.values()];
    },
    oidcSession: {
      async create({ data }: { data: { sessionTokenHash: string; userId: string; expiresAt: Date } }) {
        const row: FakeRow = { ...data, revokedAt: null };
        byHash.set(data.sessionTokenHash, row);
        return row;
      },
      async findUnique({ where }: { where: { sessionTokenHash: string } }) {
        return byHash.get(where.sessionTokenHash) ?? null;
      },
      async updateMany({
        where,
        data,
      }: {
        where: { sessionTokenHash: string; revokedAt: null };
        data: { revokedAt: Date };
      }) {
        const row = byHash.get(where.sessionTokenHash);
        if (row && row.revokedAt === null) {
          row.revokedAt = data.revokedAt;
          return { count: 1 };
        }
        return { count: 0 };
      },
    },
  };
}

describe('OP session helpers (ADR-0003 Slice 3b)', () => {
  let createOpSession: typeof import('../oidc-session.js').createOpSession;
  let readOpSession: typeof import('../oidc-session.js').readOpSession;
  let revokeOpSession: typeof import('../oidc-session.js').revokeOpSession;
  let OP_SESSION_COOKIE_NAME: string;
  let opSessionCookieOptions: typeof import('../oidc-session.js').opSessionCookieOptions;

  beforeAll(async () => {
    const mod = await import('../oidc-session.js');
    createOpSession = mod.createOpSession;
    readOpSession = mod.readOpSession;
    revokeOpSession = mod.revokeOpSession;
    OP_SESSION_COOKIE_NAME = mod.OP_SESSION_COOKIE_NAME;
    opSessionCookieOptions = mod.opSessionCookieOptions;
  });

  let fake: ReturnType<typeof makeFakePrisma>;
  beforeEach(() => {
    fake = makeFakePrisma();
  });

  it('createOpSession stores only the hash, never the plaintext token', async () => {
    const { token } = await createOpSession(fake as unknown as PrismaClient, 'user-1');
    expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(fake.rows).toHaveLength(1);
    expect(fake.rows[0].sessionTokenHash).toBe(sha256(token));
    expect(fake.rows[0].sessionTokenHash).not.toBe(token);
    expect(fake.rows[0].userId).toBe('user-1');
  });

  it('readOpSession round-trips a freshly minted token to its userId', async () => {
    const { token } = await createOpSession(fake as unknown as PrismaClient, 'user-7');
    expect(await readOpSession(fake as unknown as PrismaClient, token)).toEqual({ userId: 'user-7' });
  });

  it('readOpSession returns null for unknown / empty tokens', async () => {
    expect(await readOpSession(fake as unknown as PrismaClient, 'nope')).toBeNull();
    expect(await readOpSession(fake as unknown as PrismaClient, undefined)).toBeNull();
    expect(await readOpSession(fake as unknown as PrismaClient, null)).toBeNull();
  });

  it('readOpSession returns null once the session is revoked', async () => {
    const { token } = await createOpSession(fake as unknown as PrismaClient, 'user-9');
    await revokeOpSession(fake as unknown as PrismaClient, token);
    expect(await readOpSession(fake as unknown as PrismaClient, token)).toBeNull();
  });

  it('readOpSession returns null once the session is expired', async () => {
    const { token } = await createOpSession(fake as unknown as PrismaClient, 'user-x');
    fake.rows[0].expiresAt = new Date(Date.now() - 1000); // force-expire
    expect(await readOpSession(fake as unknown as PrismaClient, token)).toBeNull();
  });

  it('cookie is isolated from the dashboard: distinct name, host-only, path=/, HttpOnly, Lax, 24h', () => {
    expect(OP_SESSION_COOKIE_NAME).toBe('qrauth_op_session');
    expect(OP_SESSION_COOKIE_NAME).not.toBe('qrauth_refresh');
    const opts = opSessionCookieOptions();
    expect(opts.httpOnly).toBe(true);
    expect(opts.sameSite).toBe('lax');
    expect(opts.path).toBe('/');
    expect(opts.maxAge).toBe(86_400);
    expect('domain' in opts).toBe(false); // host-only — never .qrauth.io
  });
});
