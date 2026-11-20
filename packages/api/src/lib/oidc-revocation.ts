import type { PrismaClient } from '@prisma/client';

/**
 * End everything the OP has issued for a user (audit 2026-10 FINDING-011):
 * OP sessions, refresh-token families, access tokens, and authorization codes
 * not yet redeemed. Called when the account's standing changes — password
 * reset, device revocation, "sign out everywhere", an unverified account
 * being claimed — so a relying party cannot keep a session alive past that
 * point. NOT called on account lockout: anyone who knows an address can
 * trigger one, so it proves nothing about the account.
 *
 * Idempotent: only rows that are still live are touched. Pass a TRANSACTION
 * client, the one that also makes the change this accompanies (new password,
 * revoked device, account claim): the revocation and that change then
 * succeed or fail together, so a failure leaves nothing half-done and the
 * request can simply be retried.
 */
type RevocationDb = Pick<
  PrismaClient,
  'oidcSession' | 'oidcRefreshToken' | 'oidcAccessToken' | 'oidcAuthCode'
>;

export interface OidcRevocationCounts {
  sessions: number;
  refreshTokens: number;
  accessTokens: number;
  authCodes: number;
}

export async function revokeOidcAccessForUser(
  prisma: RevocationDb,
  userId: string,
): Promise<OidcRevocationCounts> {
  const now = new Date();
  const live = { userId, revokedAt: null };
  const sessions = await prisma.oidcSession.updateMany({ where: live, data: { revokedAt: now } });
  const refreshTokens = await prisma.oidcRefreshToken.updateMany({ where: live, data: { revokedAt: now } });
  const accessTokens = await prisma.oidcAccessToken.updateMany({ where: live, data: { revokedAt: now } });
  // Marking a code used makes /token refuse it.
  const authCodes = await prisma.oidcAuthCode.updateMany({ where: { userId, usedAt: null }, data: { usedAt: now } });
  return {
    sessions: sessions.count,
    refreshTokens: refreshTokens.count,
    accessTokens: accessTokens.count,
    authCodes: authCodes.count,
  };
}
