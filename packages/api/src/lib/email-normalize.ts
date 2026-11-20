/**
 * Canonical form for an account email: trimmed and lowercased. Applied at
 * every point an address enters the system (signup, login, password reset,
 * resend-verification, invitations) so two accounts can never differ only in
 * case (audit 2026-10 FINDING-001). Existing rows were brought to this form
 * by migration 20261012130000_normalize_account_emails, so every lookup uses
 * the canonical form and nothing else.
 */
export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}
