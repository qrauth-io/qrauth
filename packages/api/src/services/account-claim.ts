import type { Prisma, PrismaClient } from '@prisma/client';
import { revokeOidcAccessForUser } from '../lib/oidc-revocation.js';

/**
 * Claiming an unverified account (audit 2026-10 FINDING-001 and follow-up).
 *
 * An account with `emailVerified = false` was set up by someone who has not
 * shown they own its address. The FIRST proof of ownership — a
 * provider-verified OAuth sign-in, the verify-email link, or completing a
 * password reset — hands the account to whoever gave that proof, and
 * everything attached to it before then goes: the provider link, passkeys,
 * trusted devices, dashboard sessions, API and CLI keys (including
 * organization-level keys in organizations it owns), OP sessions, OIDC
 * tokens and consents, invitations it sent that are still pending, QR / CLI
 * approvals not yet exchanged, and any pending verify/reset token.
 *
 * Not covered: an access JWT issued before the claim stays valid until it
 * expires (15 minutes) and can be used to attach something new in that
 * window; apps, webhooks and OIDC clients the account registered in its
 * organization are left for the new owner to review.
 *
 * What the proof itself establishes is kept, and that differs by path, so
 * the caller passes it in `keep`:
 *   - oauth          → the proven provider identity; the password is dropped.
 *   - password_reset → the password just set; nothing else.
 *   - verify_email   → the existing password. An unverified password account
 *                      cannot sign in, so a pre-registered password only
 *                      becomes usable if the address owner deliberately
 *                      verifies an account they never created; wiping it here
 *                      would instead break every ordinary signup.
 *
 * Memberships of OTHER users in organizations this account owns are not
 * removed (that would destroy a real team on a normal signup); their ids go
 * into the audit row so the owner can review who was let in.
 *
 * One transaction: pass a transaction client. A verified account is left
 * exactly as it is.
 */
export const ACCOUNT_CLAIM_AUDIT_ACTION = 'auth.unverified_account_claimed';

export type AccountClaimVia = 'oauth' | 'verify_email' | 'password_reset';

export type ClaimTx = Pick<
  PrismaClient,
  | 'user'
  | 'passkey'
  | 'trustedDevice'
  | 'refreshToken'
  | 'apiKey'
  | 'oidcSession'
  | 'oidcRefreshToken'
  | 'oidcAccessToken'
  | 'oidcAuthCode'
  | 'oidcConsent'
  | 'invitation'
  | 'authSession'
  | 'membership'
  | 'auditLog'
>;

export interface AccountClaimCounts {
  passkeysDeleted: number;
  devicesDeleted: number;
  refreshTokensRevoked: number;
  apiKeysRevoked: number;
  oidcSessionsRevoked: number;
  oidcRefreshTokensRevoked: number;
  oidcAccessTokensRevoked: number;
  oidcAuthCodesVoided: number;
  oidcConsentsRevoked: number;
  invitationsCancelled: number;
  pendingApprovalsExpired: number;
}

export type AccountClaimResult =
  | { claimed: false }
  | { claimed: true; counts: AccountClaimCounts; membershipsToReview: string[] };

export async function claimUnverifiedAccount(
  tx: ClaimTx,
  params: {
    userId: string;
    via: AccountClaimVia;
    /** Fields the proof establishes, applied on top of the wipe (see above). */
    keep?: Prisma.UserUpdateInput;
    ipAddress?: string;
  },
): Promise<AccountClaimResult> {
  const { userId, via } = params;

  const current = await tx.user.findUnique({ where: { id: userId }, select: { emailVerified: true } });
  if (!current || current.emailVerified) return { claimed: false };

  const now = new Date();
  const live = { userId, revokedAt: null };

  // Organizations the account owns. A key minted there without a creator
  // link is still something the previous holder made and still holds.
  const owned = await tx.membership.findMany({
    where: { userId, role: 'OWNER' },
    orderBy: { joinedAt: 'asc' },
    select: { organizationId: true },
  });
  const ownedOrgIds = owned.map((m) => m.organizationId);

  // Passkeys reference trusted devices, so they go first.
  const passkeys = await tx.passkey.deleteMany({ where: { userId } });
  const devices = await tx.trustedDevice.deleteMany({ where: { userId } });
  const refreshTokens = await tx.refreshToken.updateMany({ where: live, data: { revokedAt: now } });
  // CLI keys are API keys minted for a user, so the first branch covers
  // both; the second is organization-level keys in organizations it owns.
  const apiKeys = await tx.apiKey.updateMany({
    where: {
      revokedAt: null,
      OR: [{ createdByUserId: userId }, { createdByUserId: null, organizationId: { in: ownedOrgIds } }],
    },
    data: { revokedAt: now },
  });
  // OP sessions, OIDC tokens and unredeemed codes (lib/oidc-revocation.ts).
  const oidc = await revokeOidcAccessForUser(tx, userId);
  // Consents the previous holder gave must not bind the new owner.
  const oidcConsents = await tx.oidcConsent.updateMany({ where: live, data: { revokedAt: now } });
  // Invitations it sent and nobody accepted yet would let someone in later.
  const invitations = await tx.invitation.deleteMany({ where: { invitedBy: userId, acceptedAt: null } });
  // A QR / CLI approval it gave that has not been exchanged yet could still
  // be turned into a key.
  const approvals = await tx.authSession.updateMany({
    where: { userId, status: 'APPROVED', exchangedAt: null },
    data: { status: 'EXPIRED' },
  });

  await tx.user.update({
    where: { id: userId },
    data: {
      emailVerified: true,
      provider: 'EMAIL',
      providerId: null,
      providerTenantId: null,
      emailVerifyToken: null,
      emailVerifyExpires: null,
      passwordResetToken: null,
      passwordResetExpires: null,
      ...params.keep,
    },
  });

  const counts: AccountClaimCounts = {
    passkeysDeleted: passkeys.count,
    devicesDeleted: devices.count,
    refreshTokensRevoked: refreshTokens.count,
    apiKeysRevoked: apiKeys.count,
    oidcSessionsRevoked: oidc.sessions,
    oidcRefreshTokensRevoked: oidc.refreshTokens,
    oidcAccessTokensRevoked: oidc.accessTokens,
    oidcAuthCodesVoided: oidc.authCodes,
    oidcConsentsRevoked: oidcConsents.count,
    invitationsCancelled: invitations.count,
    pendingApprovalsExpired: approvals.count,
  };

  // Other people the account let into organizations it owns.
  const others = ownedOrgIds.length
    ? await tx.membership.findMany({
        where: { organizationId: { in: ownedOrgIds }, userId: { not: userId } },
        select: { id: true },
      })
    : [];
  const membershipsToReview = others.map((m) => m.id);

  // AuditLog rows are org-scoped. The row names memberships of organizations
  // the account owns, so it is filed under one of those when there is one;
  // otherwise under the account's newest membership. No membership, no
  // organization to file it under.
  const auditOrgId =
    ownedOrgIds[0] ??
    (
      await tx.membership.findFirst({
        where: { userId },
        orderBy: { joinedAt: 'desc' },
        select: { organizationId: true },
      })
    )?.organizationId;
  if (auditOrgId) {
    await tx.auditLog.create({
      data: {
        organizationId: auditOrgId,
        userId,
        action: ACCOUNT_CLAIM_AUDIT_ACTION,
        resource: 'User',
        resourceId: userId,
        metadata: { via, ...counts, membershipsToReview },
        ipAddress: params.ipAddress ?? null,
      },
    });
  }

  return { claimed: true, counts, membershipsToReview };
}
