import type { OidcClient } from '@prisma/client';
import { computePairwiseSub } from './oidc-pairwise.js';

/**
 * Pairwise `sub` derivation, sourced from the OidcClient (ADR-0003 Slice 4).
 *
 * Single source of truth shared by /token (ID-token `sub`) and /userinfo
 * (`sub` claim). The two endpoints MUST emit a byte-identical `sub` for the
 * same (client, user) pair — an RP correlates its returning users by `sub`,
 * and a stock OIDC client checks the /userinfo `sub` equals the ID token's.
 *
 * The sector identifier is derived from the *client*, not a per-request
 * `redirect_uri`: /userinfo only has the access token (which records
 * `oidcClientId`, never the redirect_uri that minted it), so the client is
 * the only data both endpoints share. Per OIDC Core §8.1 the sector is the
 * host of `sector_identifier_uri` when registered, else the host of the
 * client's redirect URI. For every Phase-1 client (a single redirect URI,
 * no `sector_identifier_uri`) this is byte-identical to the old
 * `new URL(redirect_uri).host` derivation; for a hypothetical multi-host
 * client it is *more* correct (one stable sub per client sector).
 */

/**
 * Resolve the pairwise sector identifier for an OIDC client: the host of the
 * registered `sector_identifier_uri` when set, otherwise the host of the
 * client's first redirect URI. Throws when the client has neither (an
 * unregistrable state — `/authorize` requires a matching redirect URI).
 */
export function deriveSectorIdentifier(
  client: Pick<OidcClient, 'sectorIdentifierUri' | 'redirectUris'>,
): string {
  if (client.sectorIdentifierUri) {
    return new URL(client.sectorIdentifierUri).host;
  }
  const first = client.redirectUris[0];
  if (!first) {
    throw new Error('OIDC client has no redirect URIs to derive a sector identifier from');
  }
  return new URL(first).host;
}

/**
 * Compute the pairwise `sub` for a (client, user) pair. Thin wrapper over
 * {@link computePairwiseSub} that pins the sector-identifier derivation so
 * /token and /userinfo cannot drift. Propagates
 * {@link OidcPairwiseSecretMissingError} when the secret is unset — callers
 * surface it as a 503-class `temporarily_unavailable`.
 */
export function computeSubForClient(args: {
  userId: string;
  client: Pick<OidcClient, 'sectorIdentifierUri' | 'redirectUris'>;
  pairwiseSecret: Buffer | undefined | null;
}): string {
  return computePairwiseSub({
    userId: args.userId,
    sectorIdentifier: deriveSectorIdentifier(args.client),
    pairwiseSecret: args.pairwiseSecret,
  });
}
