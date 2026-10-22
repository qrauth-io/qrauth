import { randomBytes } from 'node:crypto';
import type { PrismaClient } from '@prisma/client';
import { hashString } from './crypto.js';
import { constantTimeEqualString } from './constant-time.js';
import { cacheSet, cacheTake } from './cache.js';

/**
 * OP consent for self-serve clients (audit 2026-10 FINDING-002). Asked for
 * every client that is neither FIRST_PARTY nor operator-vetted.
 *
 * A consent is one OidcConsent row per (user, client). It is live while
 * `revokedAt` is null and covers a request when every requested scope is in
 * `grantedScopes`.
 *
 * The consent page is tied to the browser and the request it was rendered for
 * by a single-use token: `<id>.<secret>`. The id keys a short-lived Redis
 * entry holding the SHA-256 of the secret, the SHA-256 of the OP session
 * cookie that was presented, and the validated authorization request. Nothing
 * else travels through the form, so the POST cannot be pointed at a different
 * client, redirect URI or scope set, and a token lifted from one browser is
 * useless in another.
 */

export const CONSENT_GRANTED_AUDIT_ACTION = 'oidc.consent_granted';
export const CONSENT_REVOKED_AUDIT_ACTION = 'oidc.consent_revoked';

/** How long a rendered consent page stays answerable. */
export const PENDING_CONSENT_TTL_SECONDS = 600;

const PENDING_KEY_PREFIX = 'oidc_consent:';

/** The validated authorization request a consent page was rendered for. */
export interface PendingConsentRequest {
  userId: string;
  /** OidcClient.id (row id, not the public client_id). */
  oidcClientId: string;
  redirectUri: string;
  scopes: string[];
  state: string;
  codeChallenge?: string;
  nonce?: string;
}

interface PendingConsentEntry extends PendingConsentRequest {
  secretHash: string;
  sessionHash: string;
}

/** Plain-language line shown on the consent page for each scope. */
const SCOPE_DESCRIPTIONS: Record<string, string> = {
  openid: 'Confirm who you are, using an identifier that is unique to this app',
  profile: 'Your name and profile picture',
  email: 'Your email address',
  offline_access: 'Keep its access while you are not using it',
  'qrauth:auth_method': 'How you signed in (for example a passkey or a QR approval)',
};

export function describeScope(scope: string): string {
  return SCOPE_DESCRIPTIONS[scope] ?? scope;
}

export function scopesCovered(granted: readonly string[], requested: readonly string[]): boolean {
  const have = new Set(granted);
  return requested.every((scope) => have.has(scope));
}

/**
 * Whether the OP issues to this client without asking the user. True for
 * FIRST_PARTY clients (QRAuth's own) and for clients an operator has vetted
 * (`consentRequired = false`, set only by scripts/oidc-set-trusted.ts). Every
 * other client — any other tier, present or future — is asked. The one place
 * this rule is written, so /authorize and the refresh grant cannot disagree.
 */
export function clientSkipsConsent(client: { tier: string; consentRequired: boolean }): boolean {
  return client.tier === 'FIRST_PARTY' || client.consentRequired === false;
}

type ConsentReader = Pick<PrismaClient, 'oidcConsent'>;
type ConsentWriter = {
  $transaction: <T>(
    fn: (tx: ConsentReader) => Promise<T>,
    options?: { isolationLevel?: 'Serializable' },
  ) => Promise<T>;
};

/** Whether the user has a live consent for this client covering `requested`. */
export async function hasCoveringConsent(
  prisma: ConsentReader,
  params: { userId: string; oidcClientId: string; requested: readonly string[] },
): Promise<boolean> {
  const consent = await prisma.oidcConsent.findUnique({
    where: { userId_oidcClientId: { userId: params.userId, oidcClientId: params.oidcClientId } },
    select: { grantedScopes: true, revokedAt: true },
  });
  if (!consent || consent.revokedAt !== null) return false;
  return scopesCovered(consent.grantedScopes, params.requested);
}

/**
 * Record an approval. A live consent is widened to the union of what was
 * granted before and what was just approved; a revoked one is replaced, so
 * scopes the user withdrew do not come back unasked.
 */
export async function grantConsent(
  prisma: ConsentWriter,
  params: { userId: string; oidcClientId: string; scopes: readonly string[] },
): Promise<string[]> {
  const key = { userId: params.userId, oidcClientId: params.oidcClientId };
  // Serializable: the union is computed from a read, so a revoke landing
  // between the read and the write must fail this transaction rather than be
  // overwritten with the scopes it just withdrew.
  return prisma.$transaction(
    async (tx) => {
      const existing = await tx.oidcConsent.findUnique({
        where: { userId_oidcClientId: key },
        select: { grantedScopes: true, revokedAt: true },
      });
      const carried = existing && existing.revokedAt === null ? existing.grantedScopes : [];
      const grantedScopes = [...new Set([...carried, ...params.scopes])];

      await tx.oidcConsent.upsert({
        where: { userId_oidcClientId: key },
        create: { ...key, grantedScopes },
        update: { grantedScopes, grantedAt: new Date(), revokedAt: null },
      });
      return grantedScopes;
    },
    { isolationLevel: 'Serializable' },
  );
}

/** Store the request behind a new single-use token and return the token. */
export async function createPendingConsent(
  request: PendingConsentRequest,
  opSessionToken: string,
): Promise<string> {
  const id = randomBytes(16).toString('base64url');
  const secret = randomBytes(32).toString('base64url');
  const entry: PendingConsentEntry = {
    ...request,
    secretHash: hashString(secret),
    sessionHash: hashString(opSessionToken),
  };
  await cacheSet(`${PENDING_KEY_PREFIX}${id}`, entry, PENDING_CONSENT_TTL_SECONDS);
  return `${id}.${secret}`;
}

/**
 * Consume a consent token. The entry is removed whatever the outcome, so a
 * token gets exactly one attempt. Returns the request only when the secret
 * matches and the token is presented with the OP session it was issued to.
 */
export async function consumePendingConsent(
  token: string | undefined,
  opSessionToken: string | undefined,
): Promise<PendingConsentRequest | null> {
  if (!token || !opSessionToken) return null;
  const separator = token.indexOf('.');
  if (separator <= 0) return null;
  const id = token.slice(0, separator);
  const secret = token.slice(separator + 1);

  const entry = await cacheTake<PendingConsentEntry>(`${PENDING_KEY_PREFIX}${id}`);
  if (!entry) return null;
  if (!constantTimeEqualString(hashString(secret), entry.secretHash)) return null;
  if (!constantTimeEqualString(hashString(opSessionToken), entry.sessionHash)) return null;

  const { secretHash: _secretHash, sessionHash: _sessionHash, ...request } = entry;
  return request;
}
