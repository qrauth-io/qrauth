/**
 * Binds a social sign-in's OAuth `state` to the browser that started it, and
 * adds PKCE (RFC 7636, S256) to the authorization code exchange.
 *
 * Without the cookie, a valid state minted by anyone (e.g. an attacker who
 * starts a flow and keeps the callback URL) is accepted from any browser:
 * login CSRF. The cookie holds only SHA-256(state), so it reveals nothing
 * that could be replayed elsewhere; the PKCE verifier stays server-side in
 * the Redis state record.
 */
import { createHash, randomBytes } from 'node:crypto';
import type { CookieSerializeOptions } from '@fastify/cookie';
import { constantTimeEqualString } from './constant-time.js';

export const OAUTH_STATE_COOKIE = '__Host-qrauth_oauth_state';

/** Matches the Redis `oauth_state:<state>` TTL. */
export const OAUTH_STATE_TTL_SECONDS = 300;

/**
 * Providers that return to the callback with a cross-site POST
 * (response_mode=form_post). A SameSite=Lax cookie is not sent on that
 * request, so their cookie must be SameSite=None.
 */
const FORM_POST_PROVIDERS: ReadonlySet<string> = new Set(['apple']);

/**
 * Providers whose authorization code flow accepts PKCE S256. Apple is left
 * out: Sign in with Apple documents no code_challenge parameter for web.
 */
const PKCE_PROVIDERS: ReadonlySet<string> = new Set(['google', 'microsoft', 'github']);

export function usesPkce(provider: string): boolean {
  return PKCE_PROVIDERS.has(provider);
}

function sha256Base64url(value: string): string {
  return createHash('sha256').update(value).digest('base64url');
}

export function hashOAuthState(state: string): string {
  return sha256Base64url(state);
}

/** True only when the cookie carries the hash of exactly this state. */
export function stateMatchesCookie(state: string, cookieValue: string | undefined): boolean {
  if (!cookieValue) return false;
  return constantTimeEqualString(hashOAuthState(state), cookieValue);
}

/** `__Host-` requires Secure, Path=/ and no Domain. */
export function oauthStateCookieOptions(provider: string): CookieSerializeOptions {
  return {
    path: '/',
    secure: true,
    httpOnly: true,
    sameSite: FORM_POST_PROVIDERS.has(provider) ? 'none' : 'lax',
    maxAge: OAUTH_STATE_TTL_SECONDS,
  };
}

/** Clearing must repeat Secure + Path=/, or the browser rejects the `__Host-` Set-Cookie. */
export const OAUTH_STATE_CLEAR_OPTIONS: CookieSerializeOptions = { path: '/', secure: true, httpOnly: true };

export interface PkcePair {
  codeVerifier: string;
  codeChallenge: string;
}

/** 32 random bytes -> 43-char verifier (RFC 7636 §4.1); challenge = BASE64URL(SHA256(verifier)). */
export function generatePkcePair(): PkcePair {
  const codeVerifier = randomBytes(32).toString('base64url');
  return { codeVerifier, codeChallenge: sha256Base64url(codeVerifier) };
}
