/**
 * ADR-0004 in code (audit 2026-10 FINDING-009).
 *
 * Third-party sign-in is the OpenID Provider's job; the App-based sign-in
 * surface is frozen. When `LEGACY_APP_FREEZE=1`, no new App can be
 * registered except by the platform organization, which owns the CLI's app.
 * Existing apps are untouched.
 *
 * The switch is off by default: Apps also carry the credentials for the
 * non-sign-in APIs ADR-0004 leaves alone (2FA, ephemeral, proximity), and
 * the dashboard still creates them. Turning it on is an operator decision.
 */
export const PLATFORM_ORG_SLUG = 'qrauth-platform';

export const LEGACY_APP_FREEZE_MESSAGE =
  'New apps can no longer be registered. For "Sign in with QRAuth", create an OIDC client under ' +
  'Sign-in clients in the dashboard (/dashboard/sign-in-clients) or via POST /api/v1/oidc/clients.';

export function appCreationBlockedByFreeze(input: {
  freezeEnabled: boolean;
  organizationSlug: string | null | undefined;
}): boolean {
  return input.freezeEnabled && input.organizationSlug !== PLATFORM_ORG_SLUG;
}
