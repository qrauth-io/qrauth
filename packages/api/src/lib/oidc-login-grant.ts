import { hashString } from './crypto.js';
import { cacheSet, cacheTake } from './cache.js';

/**
 * The one interactive /authorize request a fresh QR sign-in may complete.
 *
 * /authorize does not reuse an OP session for an ordinary request: pressing
 * "Sign in with QRAuth" always starts a scan. But the scan itself ends with
 * the browser returning to /authorize, and that return has to be let through
 * or the person would be asked to scan forever. /login/status records which
 * request the new session was created for; /authorize takes that record
 * (atomically, so it works once) and compares it with the request in hand.
 *
 * Keyed by the session token's SHA-256, so Redis never holds a usable cookie.
 */

/** Long enough for the redirect back from /login, short enough to be useless later. */
export const LOGIN_GRANT_TTL_SECONDS = 120;

interface LoginGrant {
  /** The request's parameters, in a canonical order. */
  request: string;
}

/** As a route sees them: a repeated query parameter arrives as an array. */
type AuthorizeParams = Record<string, unknown>;

const grantKey = (sessionToken: string): string => `oidc_login_grant:${hashString(sessionToken)}`;

/**
 * Order-independent form of an authorization request's parameters, or null
 * when one of them is not a single string (a repeated parameter): such a
 * request is never the one a sign-in was started for.
 */
function canonicalRequest(params: AuthorizeParams): string | null {
  const entries = Object.entries(params).filter(([, value]) => value !== undefined);
  if (entries.some(([, value]) => typeof value !== 'string')) return null;
  const sorted = [...entries].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return JSON.stringify(sorted);
}

/**
 * Parameters of a `/authorize?...` path, as /login received it in `returnTo`.
 * A repeated parameter is kept as an array so it can never match.
 */
function paramsOfReturnTo(returnTo: string): AuthorizeParams {
  const queryStart = returnTo.indexOf('?');
  if (queryStart === -1) return {};
  const query = new URLSearchParams(returnTo.slice(queryStart + 1));
  return Object.fromEntries(
    [...new Set(query.keys())].map((key) => {
      const values = query.getAll(key);
      return [key, values.length === 1 ? values[0] : values];
    }),
  );
}

/** Record that `sessionToken` was just created to answer the request in `returnTo`. */
export async function recordLoginGrant(sessionToken: string, returnTo: string): Promise<void> {
  const request = canonicalRequest(paramsOfReturnTo(returnTo));
  if (request === null) return;
  const grant: LoginGrant = { request };
  await cacheSet(grantKey(sessionToken), grant, LOGIN_GRANT_TTL_SECONDS);
}

/**
 * True when `sessionToken` was created for exactly this request and has not
 * been used for one yet. The record is consumed either way.
 */
export async function takeLoginGrant(sessionToken: string, params: AuthorizeParams): Promise<boolean> {
  const grant = await cacheTake<LoginGrant>(grantKey(sessionToken));
  // Request parameters are not secrets; plain comparison is fine here.
  const request = canonicalRequest(params);
  return request !== null && typeof grant?.request === 'string' && grant.request === request;
}
