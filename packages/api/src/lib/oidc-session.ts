import { randomBytes } from 'node:crypto';
import type { PrismaClient } from '@prisma/client';
import { hashString } from './crypto.js';
import { config } from './config.js';

/**
 * OP-hosted login session helpers (ADR-0003 Slice 3b).
 *
 * The OP is its own auth surface (ADR Q4): /login resolves the QRAuth user
 * via the auth-sessions scan-approval mechanism and mints one of these
 * sessions; /authorize reads it from the `qrauth_op_session` cookie.
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

/** Cookie name — distinct from the dashboard's `qrauth_refresh`. */
export const OP_SESSION_COOKIE_NAME = 'qrauth_op_session';

/** OP session lifetime: 24 hours. */
export const OP_SESSION_TTL_SECONDS = 86_400;

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
 * the token's SHA-256 hash with a 24h TTL, and returns the plaintext token
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
    select: { userId: true, expiresAt: true, revokedAt: true },
  });
  if (!row) return null;
  if (row.revokedAt !== null) return null;
  if (row.expiresAt.getTime() <= Date.now()) return null;
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
  if (!row) return null;
  if (row.revokedAt !== null) return null;
  if (row.expiresAt.getTime() <= Date.now()) return null;
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
