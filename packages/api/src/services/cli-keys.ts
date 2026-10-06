import type { PrismaClient } from '@prisma/client';

/**
 * Revoke (soft-delete) every CLI-minted API key a user created for a given org.
 *
 * This is the membership-removal cascade from ADR-0002: a CLI key is org+role
 * scoped at the auth layer (not user-scoped), so when a member is removed their
 * `source='cli'` keys for that org must be revoked or they retain API access.
 * Scoped to `source='cli'` so dashboard-minted org keys are never touched.
 *
 * Returns the number of keys revoked. Idempotent: already-revoked keys are
 * excluded by the `revokedAt: null` guard.
 */
export async function revokeCliKeysForMember(
  prisma: PrismaClient,
  organizationId: string,
  userId: string,
): Promise<number> {
  const { count } = await prisma.apiKey.updateMany({
    where: { organizationId, createdByUserId: userId, source: 'cli', revokedAt: null },
    data: { revokedAt: new Date() },
  });
  return count;
}
