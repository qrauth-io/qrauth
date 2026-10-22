import { describe, it, expect, vi } from 'vitest';
import { purgeExpiredOidcRows } from '../oidc-cleanup.js';
import { REFRESH_FAMILY_MAX_AGE_SECONDS } from '../../lib/oidc-refresh-policy.js';

/**
 * Audit 2026-10 FINDING-020: the cleanup worker removes OIDC rows that can
 * no longer matter, and keeps the ones replay detection still needs.
 */

const NOW = new Date('2026-10-13T12:00:00.000Z');
const HOUR = 3_600_000;
const DAY = 24 * HOUR;

function fakeDb() {
  const calls: Record<string, { where: Record<string, { lt: Date }> }> = {};
  const model = (name: string, count: number) => ({
    deleteMany: vi.fn(async (args: { where: Record<string, { lt: Date }> }) => {
      calls[name] = args;
      return { count };
    }),
  });
  return {
    calls,
    db: {
      oidcAuthCode: model('codes', 3),
      oidcAccessToken: model('access', 5),
      oidcSession: model('sessions', 2),
      oidcRefreshToken: model('refresh', 1),
    },
  };
}

describe('purgeExpiredOidcRows', () => {
  it('reports how many rows of each kind were removed', async () => {
    const { db } = fakeDb();

    expect(await purgeExpiredOidcRows(db as never, NOW)).toEqual({
      authCodes: 3,
      accessTokens: 5,
      sessions: 2,
      refreshTokens: 1,
    });
  });

  it('removes expired access tokens and sessions', async () => {
    const { db, calls } = fakeDb();

    await purgeExpiredOidcRows(db as never, NOW);

    expect(calls.access.where).toEqual({ expiresAt: { lt: NOW } });
    expect(calls.sessions.where).toEqual({ expiresAt: { lt: NOW } });
  });

  it('keeps a used code for an hour after it expires, so a replay can still revoke its tokens', async () => {
    const { db, calls } = fakeDb();

    await purgeExpiredOidcRows(db as never, NOW);

    expect(calls.codes.where).toEqual({ expiresAt: { lt: new Date(NOW.getTime() - HOUR) } });
  });

  it('keeps refresh tokens for the family lifetime plus 7 days, so a rotated token is still recognised as reuse', async () => {
    const { db, calls } = fakeDb();

    await purgeExpiredOidcRows(db as never, NOW);

    const cutoff = new Date(NOW.getTime() - REFRESH_FAMILY_MAX_AGE_SECONDS * 1000 - 7 * DAY);
    expect(calls.refresh.where).toEqual({ createdAt: { lt: cutoff } });
    // A token rotated 30 days ago is well inside that window.
    expect(new Date(NOW.getTime() - 30 * DAY).getTime()).toBeGreaterThan(cutoff.getTime());
  });
});
