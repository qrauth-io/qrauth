import type { AuditAction } from '@qrauth/shared';

/**
 * Every mutating route (method other than GET/HEAD/OPTIONS) and how it is
 * audited (ADR-0008 D3). routes/__tests__/audit-coverage.test.ts registers
 * every route plugin and fails when a mutating route is missing here, or an
 * entry names a route that no longer exists.
 *
 * `events`: the audit events the route can write. qr.* events are QR code
 * revisions (services/qr-revisions.ts); the rest are audit-table entries,
 * written in the transaction of the change (services/audit.ts).
 * `exempt`: why the route writes no audit entry.
 */
export type RouteAudit = { readonly events: readonly AuditAction[] } | { readonly exempt: string };

const PUBLIC_SCAN = 'Public scan surface: no organization change; scans, feedback and attestations are their own records.';
const SIGN_IN = 'Authentication event: recorded in LoginEvent and the session or token store, not an organization change.';
const LEGACY_AUTH_SESSION = 'Legacy QR sign-in flow (ADR-0004, frozen): each AuthSession row is its own record; sign-ins are in LoginEvent.';
const OIDC_PROTOCOL = 'OIDC protocol endpoint: authorization codes, tokens and OP sessions are their own records.';
const LIVING_CODES = 'Living Codes display session: short-lived Redis state, no organization change.';
const WEBAUTHN_CEREMONY = 'WebAuthn challenge or sign-in assertion: no stored change; sign-ins are in LoginEvent.';
const STRIPE_SESSION = 'Opens a Stripe-hosted session only; the plan change is audited when the Stripe webhook applies it.';

export const ROUTE_AUDIT: Readonly<Record<string, RouteAudit>> = {
  // Account (the member's own account, logged in the organization signed in to)
  'DELETE /api/v1/account/delete-account': { events: ['user.delete'] },
  'DELETE /api/v1/sessions': { events: ['session.revoke_all'] },
  'DELETE /api/v1/sessions/:id': { events: ['session.revoke'] },
  'PATCH /api/v1/devices/:id': { events: ['device.update'] },
  'DELETE /api/v1/devices/:id': { events: ['device.delete'] },
  'POST /api/v1/devices/:id/revoke': { events: ['device.revoke'] },
  'POST /api/v1/devices/:id/reverify': { events: ['device.reverify'] },
  'PUT /api/v1/devices/policy': { events: ['devicePolicy.update'] },
  'POST /api/v1/webauthn/register/options': { exempt: WEBAUTHN_CEREMONY },
  'POST /api/v1/webauthn/register/verify': { events: ['passkey.register'] },
  'POST /api/v1/webauthn/authenticate/options': { exempt: WEBAUTHN_CEREMONY },
  'POST /api/v1/webauthn/authenticate/verify': { exempt: WEBAUTHN_CEREMONY },
  'PATCH /api/v1/webauthn/passkeys/:id': { events: ['passkey.update'] },
  'DELETE /api/v1/webauthn/passkeys/:id': { events: ['passkey.delete'] },
  'DELETE /api/v1/oidc/consents/:id': { events: ['oidc.consent_revoked'] },

  // Sign-up, sign-in, onboarding
  'POST /api/v1/auth/signup': { events: ['organization.create', 'invitation.accept'] },
  'POST /api/v1/auth/login': { exempt: SIGN_IN },
  'POST /api/v1/auth/logout': { exempt: SIGN_IN },
  'POST /api/v1/auth/refresh': { exempt: SIGN_IN },
  'POST /api/v1/auth/forgot-password': { exempt: 'Sends a reset email only; the reset itself is audited (user.password_reset).' },
  'POST /api/v1/auth/resend-verification': { exempt: 'Sends a verification email only; no stored change to the organization.' },
  'POST /api/v1/auth/reset-password': { events: ['user.password_reset', 'auth.unverified_account_claimed'] },
  'POST /api/v1/auth/switch-org': { events: ['user.org_switch'] },
  'POST /api/v1/auth/oauth/:provider/callback': { events: ['organization.create', 'auth.unverified_account_claimed'] },
  'POST /api/v1/auth/onboarding/complete': { events: ['organization.update'] },

  // Organization, members, credentials
  'PATCH /api/v1/organizations/:id': { events: ['organization.update', 'organization.domain.heldForReview'] },
  'POST /api/v1/organizations/:id/verify': { events: ['organization.kyc.submit'] },
  'POST /api/v1/organizations/:id/keys/rotate': { events: ['signingKey.rotate'] },
  'POST /api/v1/organizations/:id/invitations': { events: ['invitation.create'] },
  'POST /api/v1/organizations/invitations/:token/accept': { events: ['invitation.accept'] },
  'DELETE /api/v1/organizations/:id/members/:userId': { events: ['member.remove'] },
  'PATCH /api/v1/organizations/:id/members/:userId': { events: ['member.role.update'] },
  'POST /api/v1/organizations/:id/api-keys': { events: ['apiKey.create'] },
  'DELETE /api/v1/organizations/:id/api-keys/:keyId': { events: ['apiKey.revoke'] },
  'POST /api/v1/organizations/:id/generate-verify-token': { events: ['organization.domain.tokenGenerate'] },
  'POST /api/v1/organizations/:id/verify-domain': { events: ['organization.domain.verify', 'organization.domain.heldForReview'] },
  'POST /api/v1/organizations/:id/security-webhook': { events: ['securityWebhook.update'] },
  'DELETE /api/v1/organizations/:id/security-webhook': { events: ['securityWebhook.delete'] },
  'POST /api/v1/api-keys': { events: ['apiKey.create'] },
  'POST /api/v1/api-keys/:id/rotate': { events: ['apiKey.rotate'] },
  'POST /api/v1/api-keys/self-revoke': { events: ['apiKey.revoke'] },
  'DELETE /api/v1/api-keys/:id': { events: ['apiKey.revoke'] },
  'POST /api/v1/oidc/clients': { events: ['oidcClient.create'] },
  'PATCH /api/v1/oidc/clients/:id': { events: ['oidcClient.update'] },
  'POST /api/v1/oidc/clients/:id/rotate-secret': { events: ['oidcClient.rotateSecret'] },
  'DELETE /api/v1/oidc/clients/:id': { events: ['oidcClient.delete'] },
  'POST /api/v1/apps': { events: ['app.create'] },
  'PATCH /api/v1/apps/:id': { events: ['app.update'] },
  'POST /api/v1/apps/:id/rotate-secret': { events: ['app.rotateSecret'] },
  'DELETE /api/v1/apps/:id': { events: ['app.delete'] },
  'PUT /api/v1/policies': { events: ['policy.update'] },
  'POST /api/v1/policies/preview': { exempt: 'Read-only: normalises a proposed allowlist and lists the codes it would leave outside; stores nothing.' },

  // Billing
  'POST /api/v1/billing/checkout': { exempt: STRIPE_SESSION },
  'POST /api/v1/billing/portal': { exempt: STRIPE_SESSION },
  'POST /api/v1/billing/webhook': { events: ['billing.plan.change', 'billing.subscription.cancel'] },

  // QR codes: the edit history is the record (no duplicate audit entries)
  'POST /api/v1/qrcodes': { events: ['qr.created'] },
  'POST /api/v1/qrcodes/bulk': { events: ['qr.created'] },
  'PATCH /api/v1/qrcodes/:token': { events: ['qr.updated', 'qr.organize'] },
  'DELETE /api/v1/qrcodes/:token': { events: ['qr.revoked'] },
  'POST /api/v1/qrcodes/:token/history/:revision/restore': { events: ['qr.restored'] },
  'POST /api/v1/qrcodes/bulk-revoke': { events: ['qr.revoked'] },
  'POST /api/v1/qrcodes/bulk-tag': { events: ['qr.bulkTag'] },
  'POST /api/v1/qrcodes/bulk-move': { events: ['qr.bulkMove'] },
  // Bulk import and export (ADR-0008 D9): bulk.start with the job; the job
  // writes qr.created per code (revisions), folder.create / tag.create and
  // bulk.finish.
  'POST /api/v1/bulk/imports/dry-run': { exempt: 'Validates a file and keeps the result for an hour; changes nothing.' },
  'POST /api/v1/bulk/imports/dry-run/:id/commit': { events: ['bulk.start', 'bulk.finish', 'qr.created', 'folder.create', 'tag.create'] },
  'POST /api/v1/bulk/exports': { events: ['bulk.start', 'bulk.finish'] },
  'POST /api/v1/bulk/exports/:id/link': { exempt: 'Issues a 5-minute download link for an export its caller started; changes nothing.' },
  'POST /api/v1/demo/qrcodes': { events: ['qr.created'] },
  'POST /api/v1/tags': { events: ['tag.create'] },
  'PATCH /api/v1/tags/:id': { events: ['tag.update'] },
  'DELETE /api/v1/tags/:id': { events: ['tag.delete'] },
  'POST /api/v1/folders': { events: ['folder.create'] },
  'PATCH /api/v1/folders/:id': { events: ['folder.update'] },
  'DELETE /api/v1/folders/:id': { events: ['folder.delete'] },
  'POST /api/v1/assets/logos': { events: ['logo.upload'] },
  'DELETE /api/v1/assets/logos/:id': { events: ['logo.delete'] },

  // Fraud
  'POST /api/v1/analytics/fraud/:id/acknowledge': { events: ['fraudIncident.acknowledge'] },
  'POST /api/v1/analytics/fraud/:id/resolve': { events: ['fraudIncident.resolve'] },
  'PATCH /api/v1/analytics/fraud-rules/:id': { events: ['admin.fraudRule.update'] },
  'POST /api/v1/analytics/fraud-rules/:id/promote': { events: ['admin.fraudRule.promote'] },
  'POST /api/v1/analytics/fraud-rules/:id/demote': { events: ['admin.fraudRule.demote'] },

  // Ephemeral delegated access
  'POST /api/v1/ephemeral': { events: ['ephemeral.create'] },
  'POST /api/v1/ephemeral/:token/claim': { exempt: 'Recipient claim: recorded on the session (claimedAt, device binding), not an organization change.' },
  'DELETE /api/v1/ephemeral/:id': { events: ['ephemeral.revoke'] },

  // QRAuth staff (SUPERADMIN actor, logged in the affected organization)
  'POST /api/v1/admin/kyc-reviews/:orgId/approve': { events: ['admin.organization.kycApproved'] },
  'POST /api/v1/admin/kyc-reviews/:orgId/reject': { events: ['admin.organization.kycRejected'] },
  'POST /api/v1/admin/organizations/:orgId/verify-domain': { events: ['admin.organization.domainVerified', 'admin.organization.domainHeldForReview'] },
  'POST /api/v1/admin/organizations/:orgId/unverify-domain': { events: ['admin.organization.domainUnverified'] },
  'POST /api/v1/admin/organizations/:orgId/domain-review/approve': { events: ['admin.organization.domainReviewApproved'] },
  'POST /api/v1/admin/organizations/:orgId/domain-review/reject': {
    events: ['admin.organization.domainReviewRejected', 'admin.organization.domainApprovalRevoked'],
  },
  'PATCH /api/v1/admin/organizations/:orgId/plan': { events: ['admin.organization.planChange'] },
  'POST /api/v1/admin/organizations/:orgId/suspend': { events: ['admin.organization.suspend'] },
  'POST /api/v1/admin/organizations/:orgId/unsuspend': { events: ['admin.organization.unsuspend'] },
  'POST /api/v1/admin/organizations/:orgId/revoke-all-codes': { events: ['admin.organization.revokeAllCodesStarted', 'admin.organization.revokeAllCodes', 'qr.revoked'] },
  'POST /api/v1/admin/qrcodes/:token/clear-destination-flag': { events: ['admin.qrcode.clearDestinationFlag'] },
  'POST /api/v1/admin/abuse-reports/:id/resolve': { events: ['admin.abuseReport.resolve'] },
  'POST /api/v1/admin/abuse-reports/:id/dismiss': { events: ['admin.abuseReport.dismiss'] },

  // Legacy QR sign-in (AuthSession)
  'POST /api/v1/auth-sessions': { exempt: LEGACY_AUTH_SESSION },
  'POST /api/v1/auth-sessions/:token/approve': { exempt: LEGACY_AUTH_SESSION },
  'POST /api/v1/auth-sessions/:token/deny': { exempt: LEGACY_AUTH_SESSION },
  // CLI credential exchange (ADR-0002): mints an API key for the approving user.
  'POST /api/v1/auth-sessions/:id/exchange': { events: ['apiKey.create'] },
  'POST /api/v1/auth-sessions/verify-result': { exempt: LEGACY_AUTH_SESSION },

  // OIDC provider
  'POST /authorize': { exempt: OIDC_PROTOCOL },
  'POST /authorize/consent': { events: ['oidc.consent_granted'] },
  'POST /token': { exempt: OIDC_PROTOCOL },
  'POST /userinfo': { exempt: OIDC_PROTOCOL },
  'POST /logout': { exempt: OIDC_PROTOCOL },
  'POST /revoke': { exempt: OIDC_PROTOCOL },

  // Living Codes, proximity, public verify surface
  'POST /api/v1/animated-qr/session': { exempt: LIVING_CODES },
  'POST /api/v1/animated-qr/session/secret': { exempt: LIVING_CODES },
  'POST /api/v1/animated-qr/validate': { exempt: LIVING_CODES },
  'POST /api/v1/proximity/:token': { exempt: PUBLIC_SCAN },
  'POST /api/v1/proximity/verify': { exempt: PUBLIC_SCAN },
  'POST /v/:token/feedback': { exempt: PUBLIC_SCAN },
  'POST /v/:token/webauthn/options': { exempt: PUBLIC_SCAN },
  'POST /v/:token/webauthn/verify': { exempt: PUBLIC_SCAN },
  'POST /api/v1/verify/:token/feedback': { exempt: PUBLIC_SCAN },
  'POST /api/v1/verify/:token/webauthn/options': { exempt: PUBLIC_SCAN },
  'POST /api/v1/verify/:token/webauthn/verify': { exempt: PUBLIC_SCAN },
  'POST /v/:token/report': { exempt: 'Public abuse report: the report is its own record; staff decisions on it are audited.' },
};
