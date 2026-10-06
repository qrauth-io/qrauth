import type { AuthProvider, PrismaClient } from '@prisma/client';
import type { OAuthUser } from '../lib/oauth.js';
import { getAdminEmails } from '../lib/admin.js';

// ---------------------------------------------------------------------------
// OAuth account-linking policy (nOAuth fix)
// ---------------------------------------------------------------------------

/**
 * Decides which QRAuth account (if any) an OAuth identity may sign in to:
 *
 * 1. `(provider, providerId)` match → sign in (exact match).
 * 2. Provider-VERIFIED email → case-insensitive email match → sign in and link.
 *    No match → create a new account.
 * 3. Unverified email matching an existing account → refuse (never link).
 * 4. Unverified email, no account → refuse (no account creation).
 * 5. Microsoft only, NO email claim at all (a user without an email
 *    attribute) but a plain sign-in name: an account with that address exists
 *    → refuse (NEVER link); otherwise create a new account with that address,
 *    marked UNVERIFIED. The sign-in name never selects an existing account.
 *
 * An email the provider has not verified must never select an account: e.g.
 * Microsoft Graph `mail` is set freely by any tenant admin, which let anyone
 * sign in as any user whose address they asserted.
 */
export type OAuthResolution =
  | { kind: 'signin'; userId: string; via: 'providerId' }
  | { kind: 'signin'; userId: string; via: 'verifiedEmail'; linkProvider: boolean }
  | { kind: 'create'; email: string; emailVerified: boolean; via: 'verifiedEmail' | 'signInName' }
  | { kind: 'refuse'; reason: OAuthRefusalReason; userId?: string };

export type OAuthRefusalReason =
  | 'missing_email'
  | 'sign_in_name_existing_account'
  | 'unverified_email_existing_account'
  | 'unverified_email_new_account'
  | 'ambiguous_email';

/** Structured log event name per refusal reason (no email is ever logged). */
export const OAUTH_REFUSAL_EVENTS: Record<OAuthRefusalReason, string> = {
  missing_email: 'oauth.refused_missing_email',
  sign_in_name_existing_account: 'oauth.link_refused_sign_in_name',
  unverified_email_existing_account: 'oauth.link_refused_unverified_email',
  unverified_email_new_account: 'oauth.signup_refused_unverified_email',
  ambiguous_email: 'oauth.link_refused_ambiguous_email',
};

type LinkDb = { user: Pick<PrismaClient['user'], 'findFirst' | 'findMany'> };

/**
 * Prisma compiles `equals` + `mode: 'insensitive'` to an UNESCAPED Postgres
 * `ILIKE`, so `_` / `%` in an email would act as wildcards (a verified
 * `j_hn@x` would match `john@x`). Escape them (backslash is ILIKE's default
 * escape character).
 */
export function escapeLikePattern(value: string): string {
  return value.replace(/[\\%_]/g, '\\$&');
}

export async function resolveOAuthAccount(
  db: LinkDb,
  provider: AuthProvider,
  oauthUser: OAuthUser,
): Promise<OAuthResolution> {
  if (oauthUser.providerId) {
    const byProvider = await db.user.findFirst({
      where: { provider, providerId: oauthUser.providerId },
      select: { id: true },
    });
    if (byProvider) return { kind: 'signin', userId: byProvider.id, via: 'providerId' };
  }

  if (!oauthUser.email) return resolveWithoutEmail(db, provider, oauthUser);

  const byEmail = await findUsersByEmail(db, oauthUser.email);

  if (!oauthUser.emailVerified) {
    return byEmail.length > 0
      ? { kind: 'refuse', reason: 'unverified_email_existing_account', userId: byEmail[0].id }
      : { kind: 'refuse', reason: 'unverified_email_new_account' };
  }

  if (byEmail.length > 1) return { kind: 'refuse', reason: 'ambiguous_email' };
  if (byEmail.length === 1) {
    return {
      kind: 'signin',
      userId: byEmail[0].id,
      via: 'verifiedEmail',
      linkProvider: !byEmail[0].providerId,
    };
  }
  return { kind: 'create', email: oauthUser.email, emailVerified: true, via: 'verifiedEmail' };
}

/**
 * users.email is case-sensitive in Postgres, so two rows can differ only in
 * case; take 2 to detect that rather than pick one arbitrarily. The JS filter
 * re-checks exact case-insensitive equality so a pattern match can never
 * select an account, whatever SQL Prisma generates.
 */
async function findUsersByEmail(db: LinkDb, email: string) {
  const wanted = email.toLowerCase();
  const rows = await db.user.findMany({
    where: { email: { equals: escapeLikePattern(email), mode: 'insensitive' } },
    select: { id: true, email: true, providerId: true },
    orderBy: { createdAt: 'asc' },
    take: 2,
  });
  return rows.filter((u) => u.email.toLowerCase() === wanted);
}

/**
 * No email claim. Only a Microsoft work or school identity with a plain
 * sign-in name gets any further, and then only to CREATE: the name is not a
 * verified email, so an existing account with that address is never selected.
 */
async function resolveWithoutEmail(
  db: LinkDb,
  provider: AuthProvider,
  oauthUser: OAuthUser,
): Promise<OAuthResolution> {
  const { signInName } = oauthUser;
  if (provider !== 'MICROSOFT' || !signInName || oauthUser.personalMicrosoftAccount) {
    return { kind: 'refuse', reason: 'missing_email' };
  }

  // Platform superadmin is granted by address (lib/admin.ts), so an unverified
  // sign-in name must never be able to claim one.
  const wanted = signInName.toLowerCase();
  if (getAdminEmails().some((adminEmail) => adminEmail.toLowerCase() === wanted)) {
    return { kind: 'refuse', reason: 'missing_email' };
  }

  const existing = await findUsersByEmail(db, signInName);
  if (existing.length > 0) {
    return { kind: 'refuse', reason: 'sign_in_name_existing_account', userId: existing[0].id };
  }
  return { kind: 'create', email: signInName, emailVerified: false, via: 'signInName' };
}
