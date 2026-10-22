import { randomBytes } from 'node:crypto';
import type { PrismaClient } from '@prisma/client';
import { hashString } from './crypto.js';
import { config } from './config.js';

/**
 * OP-hosted login session helpers (ADR-0003 Slice 3b).
 *
 * The OP is its own auth surface (ADR Q4): /login resolves the QRAuth user
 * via the auth-sessions scan-approval mechanism and mints one of these
 * sessions; /authorize reads it from the OP session cookie.
 *
 * This cookie is deliberately ISOLATED from the dashboard session:
 *   - different name (`qrauth_op_session` vs `qrauth_refresh`)
 *   - host-only to id.qrauth.io (NO `domain` attribute — never `.qrauth.io`)
 *   - Path `/` (the dashboard refresh cookie is path-scoped to /api/v1/auth)
 * so the OP login can never read, write, or collide with the dashboard
 * session, and vice versa.
 *
 * The token is a 32-byte opaque random value; only its SHA-256 hash is
 * stored (same hashing posture as App.clientSecretHash / API keys).
 */

/**
 * Cookie names (audit 2026-10 FINDING-003). In production both OP cookies
 * carry the `__Host-` prefix, which makes the browser itself enforce what the
 * options below already ask for: Secure, Path=/, and no Domain attribute, so
 * no sibling subdomain can set or shadow them. Browsers refuse a `__Host-`
 * cookie that is not Secure, and the cookies are only Secure in production
 * (local dev and E2E run over plain http), so outside production the bare
 * names are used.
 */
const HOST_PREFIX = '__Host-';
const SESSION_COOKIE_BASE = 'qrauth_op_session';
const PRE_LOGIN_COOKIE_BASE = 'qrauth_op_pre';

export function opCookieName(base: string, isProd: boolean = config.server.isProd): string {
  return isProd ? `${HOST_PREFIX}${base}` : base;
}

/** OP session cookie — distinct from the dashboard's `qrauth_refresh`. */
export const OP_SESSION_COOKIE_NAME = opCookieName(SESSION_COOKIE_BASE);

/** Pre-login cookie: ties a /login attempt to the browser that started it. */
export const OP_PRE_LOGIN_COOKIE_NAME = opCookieName(PRE_LOGIN_COOKIE_BASE);

/** Pre-login cookie lifetime: the same 10 minutes as the login attempt. */
export const OP_PRE_LOGIN_TTL_SECONDS = 600;

/**
 * The OP session token this request carries. Only the current cookie name is
 * read: in production that is the `__Host-` name, which no sibling
 * `*.qrauth.io` host can set. The pre-rename name `qrauth_op_session` is
 * deliberately NOT accepted as a fallback — a browser without a `__Host-`
 * cookie would otherwise take a session planted under the old name. Sessions
 * issued before the rename simply sign in again.
 */
export function readOpSessionCookie(cookies: Record<string, string | undefined>): string | undefined {
  return cookies[OP_SESSION_COOKIE_NAME];
}

/**
 * OP session lifetime: 15 minutes. /authorize reuses a session only for
 * prompt=none and max_age requests (and once, right after the scan), so this
 * is how long a relying party can re-check a sign-in silently, not how long
 * anyone stays signed in.
 */
export const OP_SESSION_TTL_SECONDS = 900;

/**
 * Cookie serialize options (`@fastify/cookie` shape). `secure` follows the
 * existing dashboard-cookie convention (`config.server.isProd`) so the
 * cookie is `Secure` in production but still settable over http on local
 * dev / E2E. `domain` is intentionally omitted → host-only to the issuing
 * host (id.qrauth.io in prod).
 */
export interface OpSessionCookieOptions {
  httpOnly: true;
  secure: boolean;
  sameSite: 'lax';
  path: '/';
  maxAge: number;
}

export function opSessionCookieOptions(): OpSessionCookieOptions {
  return {
    httpOnly: true,
    secure: config.server.isProd,
    sameSite: 'lax',
    path: '/',
    maxAge: OP_SESSION_TTL_SECONDS,
  };
}

/** Options for the pre-login cookie: same scope as the session, short-lived. */
export function preLoginCookieOptions(): OpSessionCookieOptions {
  return { ...opSessionCookieOptions(), maxAge: OP_PRE_LOGIN_TTL_SECONDS };
}

/** Options to clear the OP session cookie (same scope, no value). */
export function clearOpSessionCookieOptions(): Omit<OpSessionCookieOptions, 'maxAge'> {
  return {
    httpOnly: true,
    secure: config.server.isProd,
    sameSite: 'lax',
    path: '/',
  };
}

/**
 * Mint a new OP session for `userId`. Inserts an OidcSession row keyed by
 * the token's SHA-256 hash with a 15-minute TTL, and returns the plaintext token
 * (to set as the cookie value) plus the cookie options.
 */
export async function createOpSession(
  prisma: PrismaClient,
  userId: string,
): Promise<{ token: string; cookieOptions: OpSessionCookieOptions }> {
  const token = randomBytes(32).toString('base64url');
  const expiresAt = new Date(Date.now() + OP_SESSION_TTL_SECONDS * 1000);

  await prisma.oidcSession.create({
    data: {
      sessionTokenHash: hashString(token),
      userId,
      expiresAt,
    },
  });

  return { token, cookieOptions: opSessionCookieOptions() };
}

/**
 * A session is live until it is revoked, its stored expiry passes, or it is
 * older than the current lifetime. The age check is what retires sessions
 * created under a longer lifetime, whose stored expiry is still far off.
 */
function isLive(row: { createdAt: Date; expiresAt: Date; revokedAt: Date | null }): boolean {
  const now = Date.now();
  if (row.revokedAt !== null) return false;
  if (row.expiresAt.getTime() <= now) return false;
  return now - row.createdAt.getTime() < OP_SESSION_TTL_SECONDS * 1000;
}

/**
 * Resolve an OP session token to its `userId`, or null when the token is
 * unknown, expired, or revoked. Never throws.
 */
export async function readOpSession(
  prisma: PrismaClient,
  token: string | undefined | null,
): Promise<{ userId: string } | null> {
  if (!token) return null;
  const row = await prisma.oidcSession.findUnique({
    where: { sessionTokenHash: hashString(token) },
    select: { userId: true, createdAt: true, expiresAt: true, revokedAt: true },
  });
  if (!row || !isLive(row)) return null;
  return { userId: row.userId };
}

/**
 * Like {@link readOpSession} but also returns the session's `authTime`
 * (the OidcSession.createdAt — when the user authenticated to the OP), which
 * /authorize stamps onto the auth code and the ID token's `auth_time` claim.
 * Returns null on unknown/expired/revoked. Never throws.
 */
export async function readOpSessionWithMeta(
  prisma: PrismaClient,
  token: string | undefined | null,
): Promise<{ userId: string; authTime: Date } | null> {
  if (!token) return null;
  const row = await prisma.oidcSession.findUnique({
    where: { sessionTokenHash: hashString(token) },
    select: { userId: true, createdAt: true, expiresAt: true, revokedAt: true },
  });
  if (!row || !isLive(row)) return null;
  return { userId: row.userId, authTime: row.createdAt };
}

/**
 * Revoke an OP session by token. Idempotent — no error if the token is
 * unknown or already revoked.
 */
export async function revokeOpSession(
  prisma: PrismaClient,
  token: string,
): Promise<void> {
  await prisma.oidcSession.updateMany({
    where: { sessionTokenHash: hashString(token), revokedAt: null },
    data: { revokedAt: new Date() },
  });
}
