import type { PrismaClient } from '@prisma/client';

/**
 * Authentication-method derivation for OIDC acr/amr + the custom
 * `qrauth:auth_method` claim (ADR-0003 Slice 4).
 *
 * Every OIDC user reaches the OP by scanning a Living Code QR, so
 * `qr_living_code` is always the base. What's interesting is the *underlying*
 * dashboard authentication the user did on the approving device — that's the
 * factor with real assurance weight. We source it without any schema change:
 *
 *   - `LoginEvent.provider` records PASSKEY and EMAIL (password) logins. A
 *     recent successful PASSKEY login → the user holds a hardware-backed
 *     credential (RFC 8176 `hwk`).
 *   - OAuth upstream logins (Google / GitHub / Microsoft / Apple) do NOT write
 *     a LoginEvent in Phase 1, but the federated identity is pinned on
 *     `User.provider` — so a federated `User.provider` → `fed` (RFC 8176).
 *   - Everything else (EMAIL/password, or no recent login in the window) stays
 *     at the base `qr_living_code`.
 *
 * This is the pragmatic Phase-1 mapping: read-only, additive, no new tables.
 * Phase 2 (device_trust / proximity / fraud claims) can enrich it.
 */

export interface AuthMethodContext {
  /** OIDC standard: authentication context class (ID-token `acr`). */
  acr: string;
  /** OIDC standard: authentication methods reference (ID-token `amr`). */
  amr: string[];
  /** Custom `qrauth:auth_method` claim discriminator. */
  qrauthAuthMethod: 'qr_living_code' | 'passkey' | 'oauth_upstream';
}

/** How far back to look for the underlying dashboard login (24h). */
const RECENT_LOGIN_WINDOW_MS = 24 * 60 * 60 * 1000;

const ACR_BASE = 'qrauth:living-code';
const AMR_BASE = 'qrauth-living-code';

/** Federated upstreams that imply an OAuth dashboard login (`User.provider`). */
const OAUTH_UPSTREAM_PROVIDERS: ReadonlySet<string> = new Set([
  'GOOGLE',
  'GITHUB',
  'MICROSOFT',
  'APPLE',
]);

/**
 * Derive the authentication context for a user, anchored at `referenceTime`
 * (the OP-session creation time at /token; the access-token issuance time at
 * /userinfo — both proxies for "when the OIDC auth happened"). Read-only.
 *
 * Resolution order (strongest factor wins):
 *   1. recent PASSKEY LoginEvent → passkey / `hwk`
 *   2. federated `User.provider`  → oauth_upstream / `fed`
 *   3. otherwise                  → qr_living_code (base only)
 */
export async function deriveAuthMethod(
  prisma: PrismaClient,
  userId: string,
  referenceTime: Date,
): Promise<AuthMethodContext> {
  const since = new Date(referenceTime.getTime() - RECENT_LOGIN_WINDOW_MS);
  const recentLogin = await prisma.loginEvent.findFirst({
    where: {
      userId,
      success: true,
      createdAt: { gte: since, lte: referenceTime },
    },
    orderBy: { createdAt: 'desc' },
    select: { provider: true },
  });

  if (recentLogin?.provider === 'PASSKEY') {
    return {
      acr: `${ACR_BASE}+passkey`,
      amr: [AMR_BASE, 'hwk'],
      qrauthAuthMethod: 'passkey',
    };
  }

  // OAuth logins don't emit LoginEvents — the federated identity is on the User.
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { provider: true },
  });
  if (user && OAUTH_UPSTREAM_PROVIDERS.has(user.provider)) {
    return {
      acr: `${ACR_BASE}+oauth_upstream`,
      amr: [AMR_BASE, 'fed'],
      qrauthAuthMethod: 'oauth_upstream',
    };
  }

  return {
    acr: ACR_BASE,
    amr: [AMR_BASE],
    qrauthAuthMethod: 'qr_living_code',
  };
}
