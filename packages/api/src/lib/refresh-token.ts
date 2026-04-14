import { randomBytes } from 'node:crypto';
import type { PrismaClient } from '@prisma/client';
import { hashString } from './crypto.js';
import { config } from './config.js';

const REFRESH_TOKEN_BYTES = 32;
const COOKIE_NAME = 'qrauth_refresh';

export { COOKIE_NAME as REFRESH_COOKIE_NAME };

/**
 * Generate a cryptographically random refresh token, store its hash in the DB,
 * and return the raw token (to be sent to the client as a cookie).
 */
export async function createRefreshToken(
  prisma: PrismaClient,
  userId: string,
  family?: string,
): Promise<{ rawToken: string; expiresAt: Date }> {
  const rawToken = randomBytes(REFRESH_TOKEN_BYTES).toString('hex');
  const tokenHash = hashString(rawToken);
  const tokenFamily = family || randomBytes(16).toString('hex');
  const expiresAt = new Date(
    Date.now() + config.auth.refreshTokenExpiresDays * 24 * 60 * 60 * 1000,
  );

  await prisma.refreshToken.create({
    data: {
      tokenHash,
      userId,
      family: tokenFamily,
      expiresAt,
    },
  });

  return { rawToken, expiresAt };
}

/**
 * Validate a refresh token:
 *  - Look up by hash
 *  - Check not expired or revoked
 *  - Rotate: revoke old token, issue new one in same family
 *  - If token was already revoked (replay attack), revoke entire family
 *
 * Returns the new raw token + user info, or null if invalid.
 */
export async function rotateRefreshToken(
  prisma: PrismaClient,
  rawToken: string,
): Promise<{
  rawToken: string;
  expiresAt: Date;
  userId: string;
} | null> {
  const tokenHash = hashString(rawToken);

  const existing = await prisma.refreshToken.findUnique({
    where: { tokenHash },
  });

  if (!existing) {
    return null;
  }

  // If the token was already revoked, this is a replay attack.
  // Revoke the entire family to protect the user.
  if (existing.revokedAt) {
    await prisma.refreshToken.updateMany({
      where: { family: existing.family, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    return null;
  }

  // Check expiry
  if (existing.expiresAt < new Date()) {
    return null;
  }

  // Revoke the current token
  await prisma.refreshToken.update({
    where: { id: existing.id },
    data: { revokedAt: new Date() },
  });

  // Issue a new token in the same family
  const result = await createRefreshToken(prisma, existing.userId, existing.family);

  return {
    rawToken: result.rawToken,
    expiresAt: result.expiresAt,
    userId: existing.userId,
  };
}

/**
 * Revoke all refresh tokens in a family (used on logout).
 */
export async function revokeTokenFamily(
  prisma: PrismaClient,
  rawToken: string,
): Promise<void> {
  const tokenHash = hashString(rawToken);
  const existing = await prisma.refreshToken.findUnique({
    where: { tokenHash },
    select: { family: true },
  });

  if (existing) {
    await prisma.refreshToken.updateMany({
      where: { family: existing.family },
      data: { revokedAt: new Date() },
    });
  }
}

/**
 * Revoke ALL refresh tokens for a user (e.g., password change).
 */
export async function revokeAllUserTokens(
  prisma: PrismaClient,
  userId: string,
): Promise<void> {
  await prisma.refreshToken.updateMany({
    where: { userId, revokedAt: null },
    data: { revokedAt: new Date() },
  });
}

/**
 * Build the Set-Cookie options for the refresh token.
 */
export function getRefreshCookieOptions(expiresAt: Date) {
  return {
    path: '/api/v1/auth',
    httpOnly: true,
    secure: config.server.isProd,
    sameSite: 'lax' as const,
    expires: expiresAt,
  };
}

/**
 * Build options to clear the refresh cookie.
 */
export function getClearCookieOptions() {
  return {
    path: '/api/v1/auth',
    httpOnly: true,
    secure: config.server.isProd,
    sameSite: 'lax' as const,
  };
}
