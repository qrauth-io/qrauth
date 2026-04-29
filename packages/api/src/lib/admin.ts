/**
 * Platform-level admin (superadmin) helpers.
 *
 * Superadmin status is determined by matching the authenticated user's email
 * against the `ADMIN_EMAILS` env var (comma-separated list). This is a
 * platform-level role, independent of per-organization Membership.role.
 */

export function getAdminEmails(): string[] {
  return (process.env.ADMIN_EMAILS ?? '')
    .split(',')
    .map((e) => e.trim())
    .filter(Boolean);
}

export function isAdminEmail(email: string | null | undefined): boolean {
  if (!email) return false;
  return getAdminEmails().includes(email);
}
