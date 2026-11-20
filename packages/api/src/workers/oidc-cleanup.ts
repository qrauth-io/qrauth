import type { PrismaClient } from '@prisma/client';
import { REFRESH_FAMILY_MAX_AGE_SECONDS } from '../lib/oidc-refresh-policy.js';

/**
 * Retention for the OpenID Provider's tables (audit 2026-10 FINDING-020).
 * Nothing here is needed once it can no longer be presented, with two
 * deliberate delays:
 *
 *   - Authorization codes stay for an hour after they expire. A code that is
 *     presented twice revokes the tokens issued from it, and those tokens
 *     live for an hour; the row has to outlast them.
 *   - Refresh tokens stay for the family lifetime plus 7 days. A rotated
 *     token presented again is how a stolen token is detected, and that can
 *     happen at any point while the family is alive.
 */

const HOUR_MS = 60 * 60 * 1000;
const AUTH_CODE_GRACE_MS = HOUR_MS;
const REFRESH_TOKEN_GRACE_MS = 7 * 24 * HOUR_MS;

export interface OidcPurgeCounts {
  authCodes: number;
  accessTokens: number;
  sessions: number;
  refreshTokens: number;
}

type OidcTables = Pick<PrismaClient, 'oidcAuthCode' | 'oidcAccessToken' | 'oidcSession' | 'oidcRefreshToken'>;

export async function purgeExpiredOidcRows(db: OidcTables, now: Date = new Date()): Promise<OidcPurgeCounts> {
  const authCodes = await db.oidcAuthCode.deleteMany({
    where: { expiresAt: { lt: new Date(now.getTime() - AUTH_CODE_GRACE_MS) } },
  });
  const accessTokens = await db.oidcAccessToken.deleteMany({ where: { expiresAt: { lt: now } } });
  const sessions = await db.oidcSession.deleteMany({ where: { expiresAt: { lt: now } } });
  const refreshTokens = await db.oidcRefreshToken.deleteMany({
    where: {
      createdAt: { lt: new Date(now.getTime() - REFRESH_FAMILY_MAX_AGE_SECONDS * 1000 - REFRESH_TOKEN_GRACE_MS) },
    },
  });
  return {
    authCodes: authCodes.count,
    accessTokens: accessTokens.count,
    sessions: sessions.count,
    refreshTokens: refreshTokens.count,
  };
}
