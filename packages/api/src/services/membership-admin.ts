import { Prisma, type Membership, type PrismaClient } from '@prisma/client';
import { ROLE_HIERARCHY, type MembershipRole } from '@qrauth/shared';
import { revokeCliKeysForMember } from './cli-keys.js';

/**
 * Member removal and role change (audit 2026-10 FINDING-006 / FINDING-010).
 *
 * - An actor may act only on members with a strictly lower role, except an
 *   OWNER, who may also act on another OWNER.
 * - The last-owner check and the change run in ONE serializable transaction,
 *   so two concurrent requests cannot each see "two owners" and leave none.
 * - The member's CLI keys for the organization are revoked in the same
 *   transaction: on removal (ADR-0002 cascade) and on any role change.
 */

type MembershipAdminDb = Pick<PrismaClient, '$transaction'>;

interface MemberTarget {
  organizationId: string;
  targetUserId: string;
  actorRole: MembershipRole;
}

type Refusal =
  | { outcome: 'not_found' }
  | { outcome: 'forbidden' }
  | { outcome: 'last_owner' }
  | { outcome: 'conflict' };

export type RemoveMemberResult =
  | { outcome: 'removed'; previousRole: MembershipRole; revokedCliKeys: number }
  | Refusal;

export type ChangeMemberRoleResult =
  | { outcome: 'updated'; membership: Membership; previousRole: MembershipRole; revokedCliKeys: number }
  | Refusal;

/** ROLE_HIERARCHY is ordered highest first, so a lower index outranks a higher one. */
export function canManageMember(actorRole: MembershipRole, targetRole: MembershipRole): boolean {
  if (actorRole === 'OWNER') return true;
  return ROLE_HIERARCHY.indexOf(actorRole) < ROLE_HIERARCHY.indexOf(targetRole);
}

/** Prisma surfaces a serialization conflict (Postgres 40001) as P2034. */
function isSerializationFailure(err: unknown): boolean {
  return err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2034';
}

/** Run a serializable transaction, retrying once on a serialization conflict. */
async function runSerializable<T>(
  db: MembershipAdminDb,
  work: (tx: Prisma.TransactionClient) => Promise<T>,
): Promise<T | { outcome: 'conflict' }> {
  const attempt = () => db.$transaction(work, { isolationLevel: 'Serializable' });
  try {
    return await attempt();
  } catch (first: unknown) {
    if (!isSerializationFailure(first)) throw first;
    try {
      return await attempt();
    } catch (second: unknown) {
      if (!isSerializationFailure(second)) throw second;
      return { outcome: 'conflict' };
    }
  }
}

async function isLastOwner(tx: Prisma.TransactionClient, organizationId: string): Promise<boolean> {
  const ownerCount = await tx.membership.count({ where: { organizationId, role: 'OWNER' } });
  return ownerCount <= 1;
}

export async function removeMember(
  db: MembershipAdminDb,
  params: MemberTarget,
): Promise<RemoveMemberResult> {
  const { organizationId, targetUserId, actorRole } = params;
  const where = { userId_organizationId: { userId: targetUserId, organizationId } };

  return runSerializable<RemoveMemberResult>(db, async (tx) => {
    const target = await tx.membership.findUnique({ where });
    if (!target) return { outcome: 'not_found' };
    if (!canManageMember(actorRole, target.role)) return { outcome: 'forbidden' };
    if (target.role === 'OWNER' && (await isLastOwner(tx, organizationId))) {
      return { outcome: 'last_owner' };
    }

    await tx.membership.delete({ where });
    const revokedCliKeys = await revokeCliKeysForMember(tx, organizationId, targetUserId);
    return { outcome: 'removed', previousRole: target.role, revokedCliKeys };
  });
}

export async function changeMemberRole(
  db: MembershipAdminDb,
  params: MemberTarget & { newRole: MembershipRole },
): Promise<ChangeMemberRoleResult> {
  const { organizationId, targetUserId, actorRole, newRole } = params;
  const where = { userId_organizationId: { userId: targetUserId, organizationId } };

  return runSerializable<ChangeMemberRoleResult>(db, async (tx) => {
    const target = await tx.membership.findUnique({ where });
    if (!target) return { outcome: 'not_found' };
    if (!canManageMember(actorRole, target.role)) return { outcome: 'forbidden' };
    if (target.role === 'OWNER' && newRole !== 'OWNER' && (await isLastOwner(tx, organizationId))) {
      return { outcome: 'last_owner' };
    }

    const membership = await tx.membership.update({ where, data: { role: newRole } });
    // A CLI key snapshots the role it was minted with; a changed role makes
    // that snapshot stale, so the member re-authorizes the CLI.
    const revokedCliKeys = target.role === newRole
      ? 0
      : await revokeCliKeysForMember(tx, organizationId, targetUserId);
    return { outcome: 'updated', membership, previousRole: target.role, revokedCliKeys };
  });
}
