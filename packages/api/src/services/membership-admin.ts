import { Prisma, type Membership, type PrismaClient } from '@prisma/client';
import { canGrantRole, canManageMember, type MembershipRole } from '@qrauth/shared';
import { revokeCliKeysForMember } from './cli-keys.js';

/**
 * Member removal and role change (audit 2026-10 FINDING-006 / FINDING-010).
 *
 * - An actor may act only on members with a strictly lower role, except an
 *   OWNER, who may also act on another OWNER.
 * - An actor may not grant a role above their own: only an OWNER makes an OWNER.
 *   (Both rules: @qrauth/shared member-roles.ts, shared with the dashboard.)
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

/** Runs in the transaction that made the change (ADR-0008: the audit entry commits with it). */
export type MemberAuditHook<R> = (tx: Prisma.TransactionClient, result: R) => Promise<void>;
type Removed = Extract<RemoveMemberResult, { outcome: 'removed' }>;
type Updated = Extract<ChangeMemberRoleResult, { outcome: 'updated' }>;

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
  audit?: MemberAuditHook<Removed>,
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
    const result: Removed = { outcome: 'removed', previousRole: target.role, revokedCliKeys };
    await audit?.(tx, result);
    return result;
  });
}

export async function changeMemberRole(
  db: MembershipAdminDb,
  params: MemberTarget & { newRole: MembershipRole },
  audit?: MemberAuditHook<Updated>,
): Promise<ChangeMemberRoleResult> {
  const { organizationId, targetUserId, actorRole, newRole } = params;
  const where = { userId_organizationId: { userId: targetUserId, organizationId } };

  return runSerializable<ChangeMemberRoleResult>(db, async (tx) => {
    const target = await tx.membership.findUnique({ where });
    if (!target) return { outcome: 'not_found' };
    if (!canManageMember(actorRole, target.role) || !canGrantRole(actorRole, newRole)) {
      return { outcome: 'forbidden' };
    }
    if (target.role === 'OWNER' && newRole !== 'OWNER' && (await isLastOwner(tx, organizationId))) {
      return { outcome: 'last_owner' };
    }

    const membership = await tx.membership.update({ where, data: { role: newRole } });
    // A CLI key snapshots the role it was minted with; a changed role makes
    // that snapshot stale, so the member re-authorizes the CLI.
    const revokedCliKeys = target.role === newRole
      ? 0
      : await revokeCliKeysForMember(tx, organizationId, targetUserId);
    const result: Updated = { outcome: 'updated', membership, previousRole: target.role, revokedCliKeys };
    // Setting the role a member already has changes nothing: no entry.
    if (target.role !== newRole) await audit?.(tx, result);
    return result;
  });
}
