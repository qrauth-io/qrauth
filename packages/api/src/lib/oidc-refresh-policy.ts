import type { OidcClient, OidcRefreshToken, PrismaClient } from '@prisma/client';
import { DEFAULT_REFRESH_TTL_SECONDS } from './oidc-refresh-token.js';
import { clientSkipsConsent } from './oidc-consent.js';

/**
 * What a refresh grant is still allowed to do (audit 2026-10 FINDING-011).
 * Rotation alone let a relying party keep access for as long as it refreshed
 * at least every 14 days, whatever happened to the client registration or
 * the user's consent in the meantime. Each refresh is now re-checked:
 *
 *   - Absolute family lifetime: 90 days from the original grant. After that
 *     the user signs in again.
 *   - The scope is cut to what the client is still allowed to request.
 *   - For every client that asks for consent (not FIRST_PARTY, not
 *     operator-vetted), a live consent is required and the scope is cut to
 *     what it still covers.
 *   - If `openid` does not survive, the grant is dead.
 */

/** Longest a refresh-token family may live, counted from the original grant. */
export const REFRESH_FAMILY_MAX_AGE_SECONDS = 90 * 24 * 60 * 60;

export type RefreshPolicyResult =
  | {
      ok: true;
      /** Space-separated scope the successor token and the new tokens carry. */
      scope: string;
      /** Lifetime for the successor: never past the end of the family. */
      ttlSeconds: number;
      /** When the family's first token was issued (the original grant). */
      familyStartedAt: Date;
    }
  | { ok: false; description: string };

type PolicyDb = Pick<PrismaClient, 'oidcRefreshToken' | 'oidcConsent'>;

export async function resolveRefreshGrant(
  prisma: PolicyDb,
  params: {
    client: Pick<OidcClient, 'id' | 'tier' | 'allowedScopes' | 'consentRequired'>;
    presented: Pick<OidcRefreshToken, 'familyId' | 'userId' | 'createdAt'>;
    /** Scope after the RFC 6749 §6 narrowing the client asked for. */
    scope: string;
    now?: Date;
  },
): Promise<RefreshPolicyResult> {
  const { client, presented } = params;
  const now = params.now ?? new Date();

  const familyRoot = await prisma.oidcRefreshToken.findFirst({
    where: { familyId: presented.familyId },
    orderBy: { createdAt: 'asc' },
    select: { createdAt: true },
  });
  const familyStartedAt = familyRoot?.createdAt ?? presented.createdAt;
  const remainingSeconds = Math.floor(
    (familyStartedAt.getTime() + REFRESH_FAMILY_MAX_AGE_SECONDS * 1000 - now.getTime()) / 1000,
  );
  if (remainingSeconds <= 0) {
    return { ok: false, description: 'refresh token family reached its maximum lifetime; sign in again' };
  }

  let scopes = params.scope.split(/\s+/).filter(Boolean);
  scopes = scopes.filter((scope) => client.allowedScopes.includes(scope));

  if (!clientSkipsConsent(client)) {
    const consent = await prisma.oidcConsent.findUnique({
      where: { userId_oidcClientId: { userId: presented.userId, oidcClientId: client.id } },
      select: { grantedScopes: true, revokedAt: true },
    });
    if (!consent || consent.revokedAt !== null) {
      return { ok: false, description: 'the user no longer consents to this client' };
    }
    scopes = scopes.filter((scope) => consent.grantedScopes.includes(scope));
  }

  if (!scopes.includes('openid')) {
    return { ok: false, description: 'the openid scope is no longer granted to this client' };
  }

  return {
    ok: true,
    scope: scopes.join(' '),
    ttlSeconds: Math.min(DEFAULT_REFRESH_TTL_SECONDS, remainingSeconds),
    familyStartedAt,
  };
}
