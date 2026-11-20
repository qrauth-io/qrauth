/**
 * Organization audit log (Milestone 2, ADR-0008): actor types, the event
 * catalogue, the plan gate and the wire shape of GET /api/v1/audit. The API
 * writes only actions listed here; the dashboard and the Node SDK read the
 * same names.
 */

import { PLAN_RANK, isPlanTier } from './plans.js';

export const AUDIT_ACTOR_TYPES = ['USER', 'API_KEY', 'SYSTEM', 'SUPERADMIN'] as const;
export type AuditActorType = (typeof AUDIT_ACTOR_TYPES)[number];

/**
 * QR code events. They are read from the QR code edit history
 * (QRCodeRevision), never written to the audit table.
 */
export const QR_REVISION_ACTIONS = {
  'qr.baseline': 'QR code history started',
  'qr.created': 'QR code created',
  'qr.updated': 'QR code updated',
  'qr.restored': 'QR code destination restored',
  'qr.revoked': 'QR code revoked',
} as const;

/** Events written to the audit table, with the label the dashboard shows. */
export const AUDIT_LOG_ACTIONS = {
  // Organization and plan
  'organization.create': 'Organization created',
  'organization.update': 'Organization settings updated',
  'organization.kyc.submit': 'Verification submitted',
  'organization.domain.tokenGenerate': 'Domain verification token generated',
  'organization.domain.verify': 'Domain verified',
  'organization.domain.heldForReview': 'Domain held for review',
  'billing.plan.change': 'Plan changed',
  'billing.subscription.cancel': 'Subscription cancelled',
  'signingKey.rotate': 'Signing key rotated',
  'securityWebhook.update': 'Security webhook updated',
  'securityWebhook.delete': 'Security webhook removed',
  'devicePolicy.update': 'Device policy updated',
  'policy.update': 'Organization policy updated',
  // Members
  'invitation.create': 'Member invited',
  'invitation.accept': 'Invitation accepted',
  'member.remove': 'Member removed',
  'member.role.update': 'Member role changed',
  // Credentials and clients
  'apiKey.create': 'API key created',
  'apiKey.revoke': 'API key revoked',
  'apiKey.rotate': 'API key rotated',
  'oidcClient.create': 'Sign-in client created',
  'oidcClient.update': 'Sign-in client updated',
  'oidcClient.rotateSecret': 'Sign-in client secret rotated',
  'oidcClient.delete': 'Sign-in client deleted',
  'app.create': 'App created',
  'app.update': 'App updated',
  'app.rotateSecret': 'App secret rotated',
  'app.delete': 'App deleted',
  // QR organisation (fields outside the QR edit history)
  'qr.organize': 'QR code label or scan limits changed',
  'qr.bulkTag': 'Tags applied to QR codes',
  'qr.bulkMove': 'QR codes moved to a folder',
  'tag.create': 'Tag created',
  'tag.update': 'Tag updated',
  'tag.delete': 'Tag deleted',
  'folder.create': 'Folder created',
  'folder.update': 'Folder updated',
  'folder.delete': 'Folder deleted',
  'logo.upload': 'Logo uploaded',
  'logo.delete': 'Logo deleted',
  // Operator scripts run on the QRAuth host (packages/api/scripts)
  'organization.created_by_operator': 'Organization created by QRAuth',
  'user.provisioned_by_operator': 'Member account created by QRAuth',
  'user.set_password_link_reissued_by_operator': 'Set-password link reissued by QRAuth',
  'oidcClient.trust_set_by_operator': 'Sign-in client trust set by QRAuth',
  // Bulk operations (ADR-0008 D9)
  'bulk.start': 'Bulk job started',
  'bulk.finish': 'Bulk job finished',
  // Fraud
  'fraudIncident.acknowledge': 'Fraud incident acknowledged',
  'fraudIncident.resolve': 'Fraud incident resolved',
  // Delegated access
  'ephemeral.create': 'Ephemeral access created',
  'ephemeral.revoke': 'Ephemeral access revoked',
  // Member accounts (acting on the member's own account, logged in the
  // organization the member was signed in to)
  'user.org_switch': 'Switched organization',
  'user.password_reset': 'Password reset',
  'user.data_export': 'Account data exported',
  'user.delete': 'Account deleted',
  'auth.unverified_account_claimed': 'Unverified account claimed',
  'session.revoke': 'Session signed out',
  'session.revoke_all': 'All other sessions signed out',
  'device.update': 'Device renamed',
  'device.revoke': 'Device revoked',
  'device.delete': 'Device removed',
  'device.reverify': 'Device re-verified',
  'passkey.register': 'Passkey added',
  'passkey.update': 'Passkey renamed',
  'passkey.delete': 'Passkey removed',
  'oidc.consent_granted': 'Sign-in consent granted',
  'oidc.consent_revoked': 'Sign-in consent revoked',
  // QRAuth staff actions on the organization
  'admin.organization.kycApproved': 'Verification approved by QRAuth',
  'admin.organization.kycRejected': 'Verification rejected by QRAuth',
  'admin.organization.domainVerified': 'Domain verified by QRAuth',
  'admin.organization.domainUnverified': 'Domain verification removed by QRAuth',
  'admin.organization.domainHeldForReview': 'Domain held for review by QRAuth',
  'admin.organization.domainReviewApproved': 'Domain review approved by QRAuth',
  'admin.organization.domainReviewRejected': 'Domain review rejected by QRAuth',
  'admin.organization.domainApprovalRevoked': 'Domain approval withdrawn by QRAuth',
  'admin.organization.planChange': 'Plan changed by QRAuth',
  'admin.organization.suspend': 'Organization suspended by QRAuth',
  'admin.organization.unsuspend': 'Organization reinstated by QRAuth',
  'admin.organization.revokeAllCodesStarted': 'Revoking all QR codes started by QRAuth',
  'admin.organization.revokeAllCodes': 'All QR codes revoked by QRAuth',
  'admin.qrcode.clearDestinationFlag': 'QR destination flag cleared by QRAuth',
  'admin.abuseReport.resolve': 'Abuse report resolved by QRAuth',
  'admin.abuseReport.dismiss': 'Abuse report dismissed by QRAuth',
  // Platform fraud rules (logged in the QRAuth platform organization)
  'admin.fraudRule.update': 'Fraud rule updated',
  'admin.fraudRule.promote': 'Fraud rule promoted to active',
  'admin.fraudRule.demote': 'Fraud rule returned to shadow',
} as const;

export type QrRevisionAction = keyof typeof QR_REVISION_ACTIONS;
export type AuditLogAction = keyof typeof AUDIT_LOG_ACTIONS;
export type AuditAction = QrRevisionAction | AuditLogAction;

export const AUDIT_ACTION_LABELS: Readonly<Record<AuditAction, string>> = {
  ...QR_REVISION_ACTIONS,
  ...AUDIT_LOG_ACTIONS,
};

export function isAuditAction(value: unknown): value is AuditAction {
  return typeof value === 'string' && Object.prototype.hasOwnProperty.call(AUDIT_ACTION_LABELS, value);
}

/** Days an audit entry or QR revision is kept (privacy policy, cleanup worker). */
export const AUDIT_RETENTION_DAYS = 730;

/**
 * The audit log, organization policies and bulk operations (ADR-0008 D5)
 * need the Business plan or above. The API enforces this; the dashboard
 * mirrors it with a locked page.
 */
export const GOVERNANCE_MIN_PLAN = 'BUSINESS' as const;

export function planAllowsGovernance(plan: string): boolean {
  return isPlanTier(plan) && PLAN_RANK[plan] >= PLAN_RANK[GOVERNANCE_MIN_PLAN];
}

/** Roles that may read the audit log (ADR-0008 D6). */
export const AUDIT_VIEWER_ROLES = ['OWNER', 'ADMIN'] as const;

/** Who acted. SUPERADMIN entries never name the staff member to the organization. */
export type AuditActorView =
  | { type: 'USER'; id: string; name: string | null; email: string | null }
  | { type: 'API_KEY'; id: string; label: string | null; prefix: string | null }
  | { type: 'SYSTEM'; id: string }
  | { type: 'SUPERADMIN'; id: null; name: 'QRAuth' };

/** One entry of GET /api/v1/audit. */
export interface AuditEntry {
  /** `log:<id>` for audit-table rows, `qr:<id>` for QR revisions. */
  id: string;
  source: 'audit' | 'qr_revision';
  action: string;
  label: string;
  resourceType: string;
  resourceId: string;
  /** QR events: the code's token, when the code still exists. */
  resourceName: string | null;
  actor: AuditActorView;
  createdAt: string;
  requestId: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  metadata: Record<string, unknown> | null;
  /** QR events: changed fields, `{ field: { before, after } }`. */
  changes: Record<string, { before: unknown; after: unknown }> | null;
}

export interface AuditPage {
  data: AuditEntry[];
  /** Opaque; pass as `cursor` for the next (older) page. Null at the end. */
  nextCursor: string | null;
}
