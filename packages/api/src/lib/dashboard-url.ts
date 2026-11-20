/**
 * Public base URL of the web dashboard, used to build links that end up in
 * emails or are handed to users out-of-band (operator scripts).
 *
 * Kept free of side effects (no SMTP transport, no Redis) so standalone
 * scripts can build the same links as the email templates without pulling in
 * the mail transport.
 */
export const DASHBOARD_URL = process.env.WEBAUTHN_ORIGIN || 'http://localhost:8081';

/** Link consumed by the web reset-password page (web/src/routes/paths.ts `auth.jwt.resetPassword`). */
export function passwordResetUrl(rawToken: string): string {
  return `${DASHBOARD_URL}/auth/jwt/reset-password?token=${rawToken}`;
}
