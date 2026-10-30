import type { FastifyBaseLogger } from 'fastify';
import type { PrismaClient } from '@prisma/client';
import { cacheDel } from '../lib/cache.js';

/**
 * Revoking QR codes in bulk. Same effect per code as DELETE /qrcodes/:token:
 * status REVOKED, revokedAt set, and the verify cache entry removed.
 */

export type BulkRevokeStatus = 'revoked' | 'already_revoked' | 'not_found';

export interface BulkRevokeItem {
  token: string;
  status: BulkRevokeStatus;
}

type RevocationDb = Pick<PrismaClient, 'qRCode'>;

const CACHE_DEL_BATCH = 100;

/**
 * Removes the verify cache entries for revoked tokens. Best effort: the
 * revocation is already in the database, which the verify path reads on every
 * request, so a cache failure is logged and does not fail the call.
 */
async function invalidateVerifyCache(tokens: string[], log: FastifyBaseLogger): Promise<void> {
  for (let i = 0; i < tokens.length; i += CACHE_DEL_BATCH) {
    const batch = tokens.slice(i, i + CACHE_DEL_BATCH);
    const results = await Promise.allSettled(batch.map((t) => cacheDel(`verify:${t}`)));
    const failed = results.filter((r) => r.status === 'rejected').length;
    if (failed > 0) {
      log.warn({ failed, batch: batch.length }, 'qr-revocation: verify cache invalidation failed for some tokens');
    }
  }
}

/**
 * Revokes the given tokens within one organization. Tokens that do not exist
 * or belong to another organization are reported as `not_found`, so the
 * response never reveals another tenant's codes. Results follow the request
 * order, without duplicates.
 */
export async function revokeTokensForOrg(
  prisma: RevocationDb,
  log: FastifyBaseLogger,
  organizationId: string,
  tokens: readonly string[],
): Promise<BulkRevokeItem[]> {
  const unique = [...new Set(tokens)];
  const rows = await prisma.qRCode.findMany({
    where: { organizationId, token: { in: unique } },
    select: { token: true, status: true },
  });
  const statusByToken = new Map(rows.map((r) => [r.token, r.status]));
  const toRevoke = rows.filter((r) => r.status !== 'REVOKED').map((r) => r.token);

  if (toRevoke.length > 0) {
    await prisma.qRCode.updateMany({
      where: { organizationId, token: { in: toRevoke }, status: { not: 'REVOKED' } },
      data: { status: 'REVOKED', revokedAt: new Date() },
    });
    await invalidateVerifyCache(toRevoke, log);
  }

  return unique.map((token) => {
    const status = statusByToken.get(token);
    if (status === undefined) return { token, status: 'not_found' };
    return { token, status: status === 'REVOKED' ? 'already_revoked' : 'revoked' };
  });
}

/** Revokes every ACTIVE code of an organization. Returns how many were revoked. */
export async function revokeAllActiveForOrg(
  prisma: RevocationDb,
  log: FastifyBaseLogger,
  organizationId: string,
): Promise<number> {
  const active = await prisma.qRCode.findMany({
    where: { organizationId, status: 'ACTIVE' },
    select: { token: true },
  });
  const tokens = active.map((r) => r.token);
  if (tokens.length === 0) return 0;

  const { count } = await prisma.qRCode.updateMany({
    where: { organizationId, token: { in: tokens }, status: 'ACTIVE' },
    data: { status: 'REVOKED', revokedAt: new Date() },
  });
  await invalidateVerifyCache(tokens, log);
  return count;
}
