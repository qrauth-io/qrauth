import type { Invitation, Membership, Prisma } from '@prisma/client';
import { normalizeEmail } from '../lib/email-normalize.js';
import { recordAudit, type AuditContext } from './audit.js';

/**
 * Organization invitations: look one up by its token and accept it.
 *
 * The token is emailed to the invited address and never returned by the API,
 * so holding it shows control of that mailbox (the same proof as an email
 * verification link). Shared by the accept route and sign-up from an invite.
 */

type InvitationReader = { invitation: Pick<Prisma.TransactionClient['invitation'], 'findUnique'> };

/** The invitation for this token while it can still be accepted, else null. */
export async function findPendingInvitation(
  db: InvitationReader,
  token: string,
  now: Date = new Date(),
): Promise<Invitation | null> {
  const invitation = await db.invitation.findUnique({ where: { token } });
  if (!invitation || invitation.acceptedAt !== null || invitation.expiresAt <= now) return null;
  return invitation;
}

/** True when the address is the one the invitation was sent to. */
export function invitationMatchesEmail(invitation: Pick<Invitation, 'email'>, email: string): boolean {
  return normalizeEmail(invitation.email) === normalizeEmail(email);
}

export type AcceptInvitationResult =
  | { outcome: 'accepted'; membership: Membership }
  | { outcome: 'already_member' }
  | { outcome: 'spent' };

/**
 * Add the user to the invitation's organization with the invited role, mark
 * the invitation used and record invitation.accept, all in the caller's
 * transaction. The claim is conditional, so two concurrent accepts of one
 * invitation cannot both succeed.
 */
export async function acceptInvitation(
  tx: Prisma.TransactionClient,
  audit: AuditContext,
  invitation: Invitation,
  userId: string,
): Promise<AcceptInvitationResult> {
  const existing = await tx.membership.findUnique({
    where: { userId_organizationId: { userId, organizationId: invitation.organizationId } },
    select: { id: true },
  });
  if (existing) return { outcome: 'already_member' };

  const now = new Date();
  const claimed = await tx.invitation.updateMany({
    where: { id: invitation.id, acceptedAt: null, expiresAt: { gt: now } },
    data: { acceptedAt: now },
  });
  if (claimed.count === 0) return { outcome: 'spent' };

  const membership = await tx.membership.create({
    data: {
      userId,
      organizationId: invitation.organizationId,
      role: invitation.role,
      invitedBy: invitation.invitedBy,
    },
  });
  await recordAudit(tx, audit, {
    organizationId: invitation.organizationId,
    action: 'invitation.accept',
    resource: 'Invitation',
    resourceId: invitation.id,
    metadata: { invitationId: invitation.id, role: invitation.role, invitedBy: invitation.invitedBy },
  });
  return { outcome: 'accepted', membership };
}
