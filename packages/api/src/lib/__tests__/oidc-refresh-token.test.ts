import { describe, it, expect, beforeEach } from 'vitest';
import { createHash } from 'node:crypto';
import type { PrismaClient } from '@prisma/client';
import {
  mintRefreshToken,
  claimRefreshToken,
  invalidateFamily,
  DEFAULT_REFRESH_TTL_SECONDS,
} from '../oidc-refresh-token.js';

/**
 * Unit coverage for the refresh-token helpers (ADR-0003 Slice 5) over an
 * in-memory fake of the prisma.oidcRefreshToken delegate. Rows are keyed by id
 * in a Map; lookups by tokenHash scan the values (production uses a unique
 * index — never a `===` on the hash).
 */

const sha256 = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');

interface Row {
  id: string;
  tokenHash: string;
  familyId: string;
  oidcClientId: string;
  userId: string;
  scope: string;
  expiresAt: Date;
  rotatedAt: Date | null;
  revokedAt: Date | null;
  replacedById: string | null;
  createdAt: Date;
}

function makeFakePrisma() {
  const byId = new Map<string, Row>();
  // tokenHash -> id. Map lookup so findUnique never uses === on the crypto-named
  // hash (AUDIT-FINDING-012); production uses a unique index, also not a compare.
  const tokenIndex = new Map<string, string>();
  let seq = 0;

  const matches = (row: Row, where: Record<string, unknown>): boolean =>
    Object.entries(where).every(([k, v]) => {
      if (v === null) return (row as Record<string, unknown>)[k] === null;
      return (row as Record<string, unknown>)[k] === v;
    });

  const prisma = {
    oidcRefreshToken: {
      async create({ data, select }: { data: Omit<Row, 'id' | 'rotatedAt' | 'revokedAt' | 'replacedById' | 'createdAt'>; select?: Record<string, boolean> }) {
        const id = `rt_${++seq}`;
        const row: Row = {
          id,
          rotatedAt: null,
          revokedAt: null,
          replacedById: null,
          createdAt: new Date(),
          ...data,
        };
        byId.set(id, row);
        tokenIndex.set(row.tokenHash, id);
        return select?.id ? { id } : row;
      },
      async findUnique({ where }: { where: { tokenHash?: string; id?: string } }) {
        if (typeof where.tokenHash === 'string') {
          const id = tokenIndex.get(where.tokenHash);
          return id !== undefined ? (byId.get(id) ?? null) : null;
        }
        if (typeof where.id === 'string') {
          return byId.get(where.id) ?? null;
        }
        return null;
      },
      async updateMany({ where, data }: { where: Record<string, unknown>; data: Partial<Row> }) {
        let count = 0;
        for (const row of byId.values()) {
          if (matches(row, where)) {
            Object.assign(row, data);
            count++;
          }
        }
        return { count };
      },
    },
    // test-only accessor
    _rows: byId,
  };
  return prisma as unknown as PrismaClient & { _rows: Map<string, Row> };
}

describe('mintRefreshToken', () => {
  let prisma: ReturnType<typeof makeFakePrisma>;
  beforeEach(() => {
    prisma = makeFakePrisma();
  });

  it('generates a familyId when none is provided and inserts a hashed row', async () => {
    const r = await mintRefreshToken({ prisma, oidcClientId: 'c1', userId: 'u1', scope: 'openid offline_access' });
    expect(typeof r.token).toBe('string');
    expect(r.token.length).toBeGreaterThan(0);
    expect(r.familyId).toMatch(/^[0-9a-f]{32}$/); // randomBytes(16).hex
    const row = prisma._rows.get(r.rowId)!;
    expect(row.tokenHash).toBe(sha256(r.token)); // stored hashed, never raw
    expect(row.scope).toBe('openid offline_access');
    // default 14-day TTL
    const ttlMs = row.expiresAt.getTime() - row.createdAt.getTime();
    expect(Math.round(ttlMs / 1000)).toBeCloseTo(DEFAULT_REFRESH_TTL_SECONDS, -1);
  });

  it('uses the provided familyId on rotation', async () => {
    const r = await mintRefreshToken({ prisma, familyId: 'fam-xyz', oidcClientId: 'c1', userId: 'u1', scope: 'openid' });
    expect(r.familyId).toBe('fam-xyz');
    expect(prisma._rows.get(r.rowId)!.familyId).toBe('fam-xyz');
  });
});

describe('claimRefreshToken', () => {
  let prisma: ReturnType<typeof makeFakePrisma>;
  beforeEach(() => {
    prisma = makeFakePrisma();
  });

  it('claims an un-rotated token: sets rotatedAt + replacedById, returns the row', async () => {
    const parent = await mintRefreshToken({ prisma, oidcClientId: 'c1', userId: 'u1', scope: 'openid' });
    const successor = await mintRefreshToken({ prisma, familyId: parent.familyId, oidcClientId: 'c1', userId: 'u1', scope: 'openid' });

    const claimed = await claimRefreshToken({ prisma, tokenHash: sha256(parent.token), successorRowId: successor.rowId });
    expect(claimed).not.toBeNull();
    expect(claimed!.rotatedAt).not.toBeNull();
    expect(claimed!.replacedById).toBe(successor.rowId);
  });

  it('returns null on an already-rotated token and does not mutate again', async () => {
    const parent = await mintRefreshToken({ prisma, oidcClientId: 'c1', userId: 'u1', scope: 'openid' });
    const succ1 = await mintRefreshToken({ prisma, familyId: parent.familyId, oidcClientId: 'c1', userId: 'u1', scope: 'openid' });
    const first = await claimRefreshToken({ prisma, tokenHash: sha256(parent.token), successorRowId: succ1.rowId });
    const firstRotatedAt = first!.rotatedAt;

    const succ2 = await mintRefreshToken({ prisma, familyId: parent.familyId, oidcClientId: 'c1', userId: 'u1', scope: 'openid' });
    const second = await claimRefreshToken({ prisma, tokenHash: sha256(parent.token), successorRowId: succ2.rowId });

    expect(second).toBeNull();
    // The original rotation is untouched — replacedById still points at succ1.
    expect(prisma._rows.get(parent.rowId)!.replacedById).toBe(succ1.rowId);
    expect(prisma._rows.get(parent.rowId)!.rotatedAt).toBe(firstRotatedAt);
  });
});

describe('invalidateFamily', () => {
  let prisma: ReturnType<typeof makeFakePrisma>;
  beforeEach(() => {
    prisma = makeFakePrisma();
  });

  it('revokes every active token in the family and returns the count', async () => {
    const a = await mintRefreshToken({ prisma, oidcClientId: 'c1', userId: 'u1', scope: 'openid' });
    await mintRefreshToken({ prisma, familyId: a.familyId, oidcClientId: 'c1', userId: 'u1', scope: 'openid' });
    await mintRefreshToken({ prisma, familyId: a.familyId, oidcClientId: 'c1', userId: 'u1', scope: 'openid' });
    // an unrelated family must be untouched
    const other = await mintRefreshToken({ prisma, oidcClientId: 'c1', userId: 'u1', scope: 'openid' });

    const count = await invalidateFamily({ prisma, familyId: a.familyId });
    expect(count).toBe(3);
    for (const row of prisma._rows.values()) {
      if (row.familyId === a.familyId) expect(row.revokedAt).not.toBeNull();
    }
    expect(prisma._rows.get(other.rowId)!.revokedAt).toBeNull();
  });

  it('is idempotent: a second invalidation revokes nothing new (count 0)', async () => {
    const a = await mintRefreshToken({ prisma, oidcClientId: 'c1', userId: 'u1', scope: 'openid' });
    await invalidateFamily({ prisma, familyId: a.familyId });
    const second = await invalidateFamily({ prisma, familyId: a.familyId });
    expect(second).toBe(0);
  });
});
