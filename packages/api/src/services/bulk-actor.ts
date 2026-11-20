import type { BulkJob, PrismaClient } from '@prisma/client';
import { planAllowsGovernance, roleAtLeast, type MembershipRole } from '@qrauth/shared';

import { lowerRole } from '../middleware/auth.js';

/**
 * Before a bulk job does its work it checks again, as of now, what the
 * request checked when it was started (ADR-0008 D9): the organization is
 * not suspended and on Business or above, and the member or key that
 * started it still has the role (and, for an import, the verified email
 * that creating codes needs). A job queued before a member was removed or a
 * key revoked does not run.
 */

/** Import: who may create codes. Export: who may read and export codes. */
export const BULK_IMPORT_MIN_ROLE: MembershipRole = 'MEMBER';
export const BULK_EXPORT_MIN_ROLE: MembershipRole = 'VIEWER';

/** The starter's current role in the organization, or null when they no longer have access. */
async function currentRole(prisma: PrismaClient, job: BulkJob): Promise<MembershipRole | null> {
  if (job.actorType === 'USER' && job.actorUserId) {
    const membership = await prisma.membership.findUnique({
      where: { userId_organizationId: { userId: job.actorUserId, organizationId: job.organizationId } },
      select: { role: true },
    });
    return membership?.role ?? null;
  }
  if (job.actorType === 'API_KEY' && job.actorApiKeyId) {
    const key = await prisma.apiKey.findFirst({
      where: { id: job.actorApiKeyId, organizationId: job.organizationId, revokedAt: null },
      select: { role: true, createdByUserId: true },
    });
    if (!key) return null;
    if (!key.createdByUserId) return key.role;
    const membership = await prisma.membership.findUnique({
      where: { userId_organizationId: { userId: key.createdByUserId, organizationId: job.organizationId } },
      select: { role: true },
    });
    return membership ? lowerRole(key.role, membership.role) : null;
  }
  return null;
}

/** For an import: the user's email, or for a key an owner's email, is verified (lib/verified-actor.ts). */
async function emailVerified(prisma: PrismaClient, job: BulkJob): Promise<boolean> {
  if (job.actorType === 'USER' && job.actorUserId) {
    const user = await prisma.user.findUnique({ where: { id: job.actorUserId }, select: { emailVerified: true } });
    return user?.emailVerified === true;
  }
  const owner = await prisma.membership.findFirst({
    where: { organizationId: job.organizationId, role: 'OWNER', user: { emailVerified: true } },
    select: { id: true },
  });
  return owner !== null;
}

/** Why the job may not run now, or null when it may. */
export async function bulkStarterRefusal(prisma: PrismaClient, job: BulkJob): Promise<string | null> {
  const org = await prisma.organization.findUnique({
    where: { id: job.organizationId },
    select: { plan: true, suspendedAt: true },
  });
  if (!org) return 'The organization no longer exists.';
  if (org.suspendedAt) return 'The organization is suspended.';
  if (!planAllowsGovernance(org.plan)) return 'Bulk operations need the Business plan or above.';
  const role = await currentRole(prisma, job);
  const min = job.kind === 'IMPORT' ? BULK_IMPORT_MIN_ROLE : BULK_EXPORT_MIN_ROLE;
  if (!role || !roleAtLeast(role, min)) return 'The member or API key that started the job no longer has access.';
  if (job.kind === 'IMPORT' && !(await emailVerified(prisma, job))) return 'Creating QR codes needs a verified email address.';
  return null;
}
