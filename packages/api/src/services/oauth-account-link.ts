import type { AuthProvider, PrismaClient } from '@prisma/client';
import type { OAuthUser } from '../lib/oauth.js';
import { getAdminEmails } from '../lib/admin.js';
import { claimUnverifiedAccount, type ClaimTx } from './account-claim.js';

// ---------------------------------------------------------------------------
// OAuth account-linking policy (nOAuth fix)
// ---------------------------------------------------------------------------

/**
 * Decides which QRAuth account (if any) an OAuth identity may sign in to:
 *
 * 1. `(provider, providerId)` match → sign in (exact match). Microsoft: the
 *    account's stored tenant must equal the token's `tid`, or the sign-in is
 *    refused; an account with no stored tenant yet records this one.
 * 2. Provider-VERIFIED email → case-insensitive email match → sign in and link.
 *    No match → create a new account. Exception: a match that is UNVERIFIED
 *    and already holds a provider link is refused (see below).
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
  /** `recordTenantId`: Microsoft only, the `tid` to store on an account that has none yet. */
  | { kind: 'signin'; userId: string; via: 'providerId'; recordTenantId?: string }
  | { kind: 'signin'; userId: string; via: 'verifiedEmail'; linkProvider: boolean }
  | { kind: 'create'; email: string; emailVerified: boolean; via: 'verifiedEmail' | 'signInName' }
  | { kind: 'refuse'; reason: OAuthRefusalReason; userId?: string };

export type OAuthRefusalReason =
  | 'missing_email'
  | 'sign_in_name_existing_account'
  | 'unverified_email_existing_account'
  | 'unverified_email_new_account'
  | 'ambiguous_email'
  | 'tenant_mismatch';

/** Structured log event name per refusal reason (no email is ever logged). */
export const OAUTH_REFUSAL_EVENTS: Record<OAuthRefusalReason, string> = {
  missing_email: 'oauth.refused_missing_email',
  sign_in_name_existing_account: 'oauth.link_refused_sign_in_name',
  unverified_email_existing_account: 'oauth.link_refused_unverified_email',
  unverified_email_new_account: 'oauth.signup_refused_unverified_email',
  ambiguous_email: 'oauth.link_refused_ambiguous_email',
  tenant_mismatch: 'oauth.refused_tenant_mismatch',
};

/**
 * The Microsoft tenant id to store with a link, lowercase so stored and
 * incoming values compare exactly. Undefined for every other provider.
 */
export function providerTenantIdFor(provider: AuthProvider, oauthUser: OAuthUser): string | undefined {
  return provider === 'MICROSOFT' && oauthUser.tenantId ? oauthUser.tenantId.toLowerCase() : undefined;
}

/**
 * An exact `(provider, providerId)` match. For Microsoft, `oid` is only
 * meaningful inside its tenant, so the stored tenant must match the token's.
 */
function resolveProviderMatch(
  provider: AuthProvider,
  row: { id: string; providerTenantId: string | null },
  oauthUser: OAuthUser,
): OAuthResolution {
  if (provider !== 'MICROSOFT') return { kind: 'signin', userId: row.id, via: 'providerId' };

  const tenantId = providerTenantIdFor(provider, oauthUser);
  if (row.providerTenantId === null) {
    return { kind: 'signin', userId: row.id, via: 'providerId', ...(tenantId ? { recordTenantId: tenantId } : {}) };
  }
  if (row.providerTenantId !== tenantId) {
    return { kind: 'refuse', reason: 'tenant_mismatch', userId: row.id };
  }
  return { kind: 'signin', userId: row.id, via: 'providerId' };
}

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
      select: { id: true, providerTenantId: true },
    });
    if (byProvider) return resolveProviderMatch(provider, byProvider, oauthUser);
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
    // An unverified account that already has a provider link was created
    // through the Microsoft sign-in-name path (rule 5). Its holder can sign
    // in, register passkeys and invite members without ever proving the
    // address, so the proven owner must not be merged into it. Unverified
    // password signups (no provider link) are claimed instead: see
    // applyVerifiedEmailSignIn.
    if (!byEmail[0].emailVerified && byEmail[0].providerId) {
      return { kind: 'refuse', reason: 'unverified_email_existing_account', userId: byEmail[0].id };
    }
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
export async function findUsersByEmail(db: LinkDb, email: string) {
  const wanted = email.toLowerCase();
  const rows = await db.user.findMany({
    where: { email: { equals: escapeLikePattern(email), mode: 'insensitive' } },
    select: { id: true, email: true, providerId: true, emailVerified: true },
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

type OAuthClaimDb = { $transaction: <T>(fn: (tx: ClaimTx) => Promise<T>) => Promise<T> };

export interface OAuthSignInUpdate {
  avatarUrl?: string;
  lastLoginAt: Date;
  provider?: AuthProvider;
  providerId?: string;
  providerTenantId?: string;
}

/**
 * Apply a verified-email OAuth sign-in to an existing account (audit 2026-10
 * FINDING-001). The provider has just proven who owns the address. If the
 * account was NOT verified before, this is the first proof of ownership and
 * the account is claimed (services/account-claim.ts): the password and
 * everything else attached to it so far is removed, and the proven provider
 * identity is what remains.
 *
 * An already-verified account only gets the provider link. Returns whether
 * the account was claimed. Run this BEFORE issuing the new session, or the
 * session being issued would be revoked with the rest.
 */
export async function applyVerifiedEmailSignIn(
  db: OAuthClaimDb,
  params: { userId: string; update: OAuthSignInUpdate; ipAddress?: string },
): Promise<{ claimed: boolean; revokedApiKeys: number }> {
  const { userId, update, ipAddress } = params;

  return db.$transaction(async (tx) => {
    const result = await claimUnverifiedAccount(tx, {
      userId,
      via: 'oauth',
      // The password predates the proof; the provider identity is the proof.
      // `provider` / `providerId` are only present when the caller links one.
      keep: { ...update, passwordHash: '' },
      ipAddress,
    });
    if (result.claimed) return { claimed: true, revokedApiKeys: result.counts.apiKeysRevoked };

    await tx.user.update({ where: { id: userId }, data: { ...update, emailVerified: true } });
    return { claimed: false, revokedApiKeys: 0 };
  });
}
