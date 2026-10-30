import type { PrismaClient } from '@prisma/client';

/**
 * OIDC clients of a suspended organization are disabled while the
 * suspension lasts: /authorize answers access_denied, /token (every grant)
 * answers invalid_client, and /userinfo rejects their access tokens. Nothing
 * is revoked, so lifting the suspension restores existing refresh and
 * access tokens that have not expired.
 *
 * The rule follows the owning organization only. FIRST_PARTY clients belong
 * to the qrauth-platform organization, which routes/admin.ts refuses to
 * suspend.
 */

export const OIDC_CLIENT_DISABLED = 'the client is disabled';

export async function isClientOrgSuspended(
  prisma: Pick<PrismaClient, 'organization'>,
  organizationId: string,
): Promise<boolean> {
  const org = await prisma.organization.findUnique({
    where: { id: organizationId },
    select: { suspendedAt: true },
  });
  return Boolean(org?.suspendedAt);
}
