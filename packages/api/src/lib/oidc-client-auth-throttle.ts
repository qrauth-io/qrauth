import type { PrismaClient } from '@prisma/client';
import { cacheGet, cacheIncr } from './cache.js';
import { hashString } from './crypto.js';
import { networkKey } from './rate-limit-key.js';
import { authenticateOidcClient, readClientCredentials, type ClientAuthResult } from './oidc-client-auth.js';

/**
 * Limit on failed OIDC client authentication at /token and /revoke (audit
 * 2026-10 FINDING-012).
 *
 * Failures are counted per client id AND caller network. Counting per client
 * id alone would let anyone who knows a client id (they are not secret) lock
 * that relying party out by sending wrong secrets; with the network in the
 * key, only the caller who is guessing is slowed down.
 *
 * The count is read before the secret is checked and raised after a failure,
 * so a burst of parallel wrong guesses can each be answered before the count
 * catches up. Reserving a slot before every check would close that, but it
 * would also turn a busy relying party's concurrent, correct requests into
 * refusals. Client secrets are 256 random bits issued by this server, and
 * the per-network /token tier bounds the burst, so the simpler form is kept.
 *
 * Redis failure: a correct secret is still accepted, because the success
 * path never needs the counter. A wrong secret is answered as limited,
 * because the failure cannot be counted.
 */

export const CLIENT_AUTH_MAX_FAILURES = 10;
export const CLIENT_AUTH_FAILURE_WINDOW_SECONDS = 300;

export type ThrottledClientAuthResult =
  | Extract<ClientAuthResult, { ok: true }>
  | { ok: false; description: string; throttled: boolean };

const LIMITED = {
  ok: false,
  throttled: true,
  description: 'too many failed client authentication attempts; retry later',
} as const;

// The client id is caller-supplied text of any length: hash it into the key.
const failureKey = (clientId: string, ip: string): string =>
  `oidc_client_auth_fail:${hashString(clientId)}:${networkKey(ip)}`;

export async function authenticateOidcClientThrottled(
  prisma: Pick<PrismaClient, 'oidcClient'>,
  authorizationHeader: string | undefined,
  body: Record<string, unknown>,
  ip: string,
): Promise<ThrottledClientAuthResult> {
  const presented = readClientCredentials(authorizationHeader, body);
  // Nothing to count against when the request names no client.
  if (!presented.ok || !presented.clientId) {
    const result = await authenticateOidcClient(prisma, authorizationHeader, body);
    return result.ok ? result : { ...result, throttled: false };
  }
  const key = failureKey(presented.clientId, ip);

  // Unknown (Redis down) is treated as "not blocked" here and settled below.
  const failures = await cacheGet<number>(key).catch(() => null);
  if (typeof failures === 'number' && failures >= CLIENT_AUTH_MAX_FAILURES) return LIMITED;

  const result = await authenticateOidcClient(prisma, authorizationHeader, body);
  if (result.ok) return result;

  try {
    await cacheIncr(key, CLIENT_AUTH_FAILURE_WINDOW_SECONDS);
  } catch {
    return LIMITED;
  }
  return { ...result, throttled: false };
}
