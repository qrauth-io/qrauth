import { describe, it, expect, beforeEach, vi } from 'vitest';

const cacheDel = vi.hoisted(() => vi.fn(async (_key: string) => undefined));
vi.mock('../../lib/cache.js', () => ({ cacheDel }));

import { revokeAllActiveForOrg, revokeTokensForOrg } from '../qr-revocation.js';

type Row = { token: string; organizationId: string; status: 'ACTIVE' | 'EXPIRED' | 'REVOKED' };

// A tiny in-memory qRCode table that honours the where clauses the service uses.
function makeDb(rows: Row[]) {
  const table = rows.map((r) => ({ ...r }));
  const matches = (r: Row, where: Record<string, any>) =>
    r.organizationId === where.organizationId &&
    (!where.token?.in || where.token.in.includes(r.token)) &&
    (where.status === undefined ||
      (typeof where.status === 'string' ? r.status === where.status : r.status !== where.status.not));
  return {
    table,
    qRCode: {
      findMany: vi.fn(async ({ where }: { where: Record<string, any> }) =>
        table.filter((r) => matches(r, where)).map((r) => ({ token: r.token, status: r.status }))),
      updateMany: vi.fn(async ({ where, data }: { where: Record<string, any>; data: { status: Row['status'] } }) => {
        const hit = table.filter((r) => matches(r, where));
        hit.forEach((r) => { r.status = data.status; });
        return { count: hit.length };
      }),
    },
  };
}

const log = { warn: vi.fn() } as never;

beforeEach(() => {
  cacheDel.mockReset();
  cacheDel.mockResolvedValue(undefined);
});

describe('revokeTokensForOrg', () => {
  it('revokes, reports already revoked and unknown, in request order without duplicates', async () => {
    const db = makeDb([
      { token: 'a', organizationId: 'org_1', status: 'ACTIVE' },
      { token: 'b', organizationId: 'org_1', status: 'REVOKED' },
      { token: 'c', organizationId: 'org_1', status: 'EXPIRED' },
    ]);

    const results = await revokeTokensForOrg(db as never, log, 'org_1', ['c', 'a', 'zzz', 'b', 'a']);

    expect(results).toEqual([
      { token: 'c', status: 'revoked' },
      { token: 'a', status: 'revoked' },
      { token: 'zzz', status: 'not_found' },
      { token: 'b', status: 'already_revoked' },
    ]);
    expect(db.table.map((r) => r.status)).toEqual(['REVOKED', 'REVOKED', 'REVOKED']);
    expect(cacheDel.mock.calls.map((c) => c[0]).sort()).toEqual(['verify:a', 'verify:c']);
  });

  it("reports another organization's token as not_found and leaves it untouched", async () => {
    const db = makeDb([
      { token: 'mine', organizationId: 'org_1', status: 'ACTIVE' },
      { token: 'theirs', organizationId: 'org_2', status: 'ACTIVE' },
    ]);

    const results = await revokeTokensForOrg(db as never, log, 'org_1', ['mine', 'theirs']);

    expect(results).toEqual([
      { token: 'mine', status: 'revoked' },
      { token: 'theirs', status: 'not_found' },
    ]);
    expect(db.table.find((r) => r.token === 'theirs')!.status).toBe('ACTIVE');
    expect(cacheDel).not.toHaveBeenCalledWith('verify:theirs');
  });

  it('does not fail when the cache cannot be cleared (the database is the source of truth)', async () => {
    const db = makeDb([{ token: 'a', organizationId: 'org_1', status: 'ACTIVE' }]);
    cacheDel.mockRejectedValue(new Error('redis down'));

    await expect(revokeTokensForOrg(db as never, log, 'org_1', ['a'])).resolves.toEqual([
      { token: 'a', status: 'revoked' },
    ]);
    expect(db.table[0].status).toBe('REVOKED');
  });

  it('writes nothing when nothing needs revoking', async () => {
    const db = makeDb([{ token: 'b', organizationId: 'org_1', status: 'REVOKED' }]);

    await revokeTokensForOrg(db as never, log, 'org_1', ['b', 'x']);

    expect(db.qRCode.updateMany).not.toHaveBeenCalled();
    expect(cacheDel).not.toHaveBeenCalled();
  });
});

describe('revokeAllActiveForOrg', () => {
  it('revokes only ACTIVE codes of that organization and clears their cache entries', async () => {
    const db = makeDb([
      { token: 'a', organizationId: 'org_1', status: 'ACTIVE' },
      { token: 'b', organizationId: 'org_1', status: 'ACTIVE' },
      { token: 'e', organizationId: 'org_1', status: 'EXPIRED' },
      { token: 'x', organizationId: 'org_2', status: 'ACTIVE' },
    ]);

    const count = await revokeAllActiveForOrg(db as never, log, 'org_1');

    expect(count).toBe(2);
    expect(db.table.map((r) => `${r.token}:${r.status}`)).toEqual(['a:REVOKED', 'b:REVOKED', 'e:EXPIRED', 'x:ACTIVE']);
    expect(cacheDel.mock.calls.map((c) => c[0]).sort()).toEqual(['verify:a', 'verify:b']);
  });

  it('returns 0 for an organization with no active codes', async () => {
    const db = makeDb([]);

    expect(await revokeAllActiveForOrg(db as never, log, 'org_1')).toBe(0);
  });
});
