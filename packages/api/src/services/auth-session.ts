import type { MembershipRole, PrismaClient } from '@prisma/client';
import { createHash, randomBytes } from 'node:crypto';
import { verifySignature, generateApiKey } from '../lib/crypto.js';
import { cacheSet, cacheGet, cacheDel } from '../lib/cache.js';
import { AUTH_SESSION_EXPIRY_SECONDS, assertCanonicalSafe } from '@qrauth/shared';
import { constantTimeEqualString } from '../lib/constant-time.js';
import type { SigningService } from './signing.js';

/**
 * Stable identifiers for the first-party CLI app provisioned by migration
 * 20260521120100_provision_qrauth_cli_app (ADR-0002 §1). The slug gates the
 * first-party approval UX; the clientId is the well-known X-Client-Id the
 * published CLI ships. Both are 'qrauth-cli'.
 */
export const QRAUTH_CLI_SLUG = 'qrauth-cli' as const;
export const QRAUTH_CLI_CLIENT_ID = 'qrauth-cli' as const;

// The CLI verification-code derivation (deriveCliVerificationCode +
// CLI_VERIFICATION_CODE_DOMAIN) is the single source of truth in
// `@qrauth/shared` so the API and the @qrauth/cli client reproduce the exact
// same code. Import it from there; do not reimplement here.

/**
 * Verify a PKCE `code_verifier` against a stored S256 `code_challenge`.
 * Constant-time on the digest (AUDIT-FINDING-012 contract: never `===` on
 * cryptographic strings). Kept here so the exchange path and the route share
 * one implementation.
 */
export function verifyCodeChallenge(codeVerifier: string, codeChallenge: string): boolean {
  const hash = createHash('sha256').update(codeVerifier, 'ascii').digest('base64url');
  return constantTimeEqualString(hash, codeChallenge);
}

/**
 * Typed failure from the CLI credential exchange. The route maps `.statusCode`
 * straight to the HTTP response; `.code` is a stable machine-readable token.
 */
export class CliExchangeError extends Error {
  constructor(
    readonly statusCode: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'CliExchangeError';
  }
}

/**
 * Domain-separated canonical form for auth-session approval signatures
 * (AUDIT-FINDING-002 + 021). The signer and verifier both build this
 * string from the same fields and feed it to ECDSA-P256. Fields go
 * through `assertCanonicalSafe` so a `|`, newline, or NUL in any input
 * fails loudly instead of silently collapsing two sessions to the same
 * bytes.
 */
export const AUTH_SESSION_APPROVAL_ALG_VERSION = 'qrauth-auth-session-v1' as const;
export const AUTH_SESSION_APPROVAL_DOMAIN = 'qrauth:auth-session:v1' as const;

/**
 * AUDIT-2 N-2: domain-separation prefix applied by the ECDSA signer on
 * the signing path. The verify leg below has to reconstruct it so
 * signatures produced under the new signer verify correctly. Byte-
 * identical to the constants in `services/signing.ts`,
 * `services/proximity.ts`, `services/ecdsa-signer/local.ts`, and
 * `packages/signer-service/src/server.ts`. Pinned in `ALGORITHM.md §12`.
 */
const ECDSA_CANONICAL_DOMAIN_PREFIX = 'qrauth:ecdsa-canonical:v1:';

/**
 * Thrown by `approveSession` when no active signing key exists for the
 * session's organisation or when the PEM read / sign step fails
 * (AUDIT-FINDING-007). The route handler catches this and returns
 * `503 SIGNING_UNAVAILABLE` so operators see a hard failure instead of
 * an unsigned approval sliding through unnoticed.
 */
export class SigningUnavailableError extends Error {
  readonly code = 'SIGNING_UNAVAILABLE' as const;
  constructor(message: string) {
    super(message);
    this.name = 'SigningUnavailableError';
  }
}

export function buildApprovalCanonical(parts: {
  algVersion: string;
  kid: string;
  sessionId: string;
  userId: string;
  appId: string;
  resolvedAtIso: string;
}): string {
  assertCanonicalSafe('algVersion', parts.algVersion);
  assertCanonicalSafe('kid', parts.kid);
  assertCanonicalSafe('sessionId', parts.sessionId);
  assertCanonicalSafe('userId', parts.userId);
  assertCanonicalSafe('appId', parts.appId);
  assertCanonicalSafe('resolvedAtIso', parts.resolvedAtIso);
  return [
    AUTH_SESSION_APPROVAL_DOMAIN,
    parts.algVersion,
    parts.kid,
    parts.sessionId,
    parts.userId,
    parts.appId,
    parts.resolvedAtIso,
  ].join('|');
}

/**
 * Parse the `<kid>:<base64sig>` envelope produced by `approveSession`.
 * Returns `null` for malformed or legacy (`unsigned:*`) values — the
 * caller should treat `null` as an immediate verification failure.
 */
export function parseApprovalSignature(
  stored: string,
): { kid: string; signatureBase64: string } | null {
  if (!stored || stored.startsWith('unsigned:')) return null;
  const idx = stored.indexOf(':');
  if (idx <= 0 || idx === stored.length - 1) return null;
  const kid = stored.slice(0, idx);
  const signatureBase64 = stored.slice(idx + 1);
  if (!kid || !signatureBase64) return null;
  return { kid, signatureBase64 };
}

/**
 * Verify an auth-session approval signature by looking up the signing
 * key via `(organizationId, kid)` and feeding the ECDSA verifier the
 * canonical payload the signer produced. Returns `true` only on
 * cryptographic success — no fallback to byte-equality.
 */
export async function verifyApprovalSignature(
  prisma: PrismaClient,
  session: {
    id: string;
    userId: string | null;
    appId: string;
    signature: string | null;
    resolvedAt: Date | null;
    app: { organizationId: string };
  },
  providedSignatureEnvelope: string,
): Promise<boolean> {
  if (!session.userId || !session.signature || !session.resolvedAt) return false;
  // Constant-time envelope compare (AUDIT-FINDING-002 requires
  // `constantTimeEqualString` in new code paths). This short-circuit
  // flags envelope mismatches before any crypto work; authenticity is
  // still established by the ECDSA verify below, not by this byte
  // compare.
  if (!constantTimeEqualString(session.signature, providedSignatureEnvelope)) {
    return false;
  }

  const parsed = parseApprovalSignature(session.signature);
  if (!parsed) return false;

  const signingKey = await prisma.signingKey.findFirst({
    where: {
      organizationId: session.app.organizationId,
      keyId: parsed.kid,
    },
    select: { publicKey: true, status: true },
  });
  if (!signingKey) return false;
  // Accept both ACTIVE and ROTATED within their normal grace window.
  // RETIRED keys are intentionally rejected even if the kid still matches.
  if (signingKey.status !== 'ACTIVE' && signingKey.status !== 'ROTATED') return false;

  const canonical = buildApprovalCanonical({
    algVersion: AUTH_SESSION_APPROVAL_ALG_VERSION,
    kid: parsed.kid,
    sessionId: session.id,
    userId: session.userId,
    appId: session.appId,
    resolvedAtIso: session.resolvedAt.toISOString(),
  });

  // AUDIT-2 N-2: reconstruct the ECDSA domain-separation prefix the
  // signer prepends on the signing side.
  return verifySignature(
    signingKey.publicKey,
    parsed.signatureBase64,
    ECDSA_CANONICAL_DOMAIN_PREFIX + canonical,
  );
}

// SSE subscriber registry (in-memory, per-process)
type SSESubscriber = (event: string, data: string) => void;
const subscribers = new Map<string, Set<SSESubscriber>>();

export function subscribeToSession(sessionId: string, callback: SSESubscriber): () => void {
  if (!subscribers.has(sessionId)) {
    subscribers.set(sessionId, new Set());
  }
  subscribers.get(sessionId)!.add(callback);

  // Return unsubscribe function
  return () => {
    const subs = subscribers.get(sessionId);
    if (subs) {
      subs.delete(callback);
      if (subs.size === 0) subscribers.delete(sessionId);
    }
  };
}

function notifySubscribers(sessionId: string, event: string, data: Record<string, unknown>) {
  const subs = subscribers.get(sessionId);
  if (subs) {
    const payload = JSON.stringify(data);
    for (const cb of subs) {
      cb(event, payload);
    }
  }
}

export class AuthSessionService {
  /**
   * AUDIT-FINDING-016: approval signing routes through the
   * `SigningService.signCanonical` path, which delegates to the
   * `EcdsaSigner` backend. The API server no longer reads PEM files
   * for auth-session approvals.
   */
  constructor(
    private prisma: PrismaClient,
    private signingService: SigningService,
  ) {}

  /**
   * Create a new auth session. Called by third-party apps via clientId/secret auth.
   * Returns the session with a unique token to encode in the QR code.
   */
  async createSession(appId: string, data: {
    scopes?: string[];
    redirectUrl?: string;
    metadata?: Record<string, unknown>;
  }) {
    // Generate a cryptographically random token for the QR code
    const token = `as_${randomBytes(24).toString('base64url')}`;

    const expiresAt = new Date(Date.now() + AUTH_SESSION_EXPIRY_SECONDS * 1000);

    const session = await this.prisma.authSession.create({
      data: {
        appId,
        token,
        scopes: data.scopes ?? ['identity'],
        redirectUrl: data.redirectUrl,
        metadata: data.metadata ? (data.metadata as import('@prisma/client').Prisma.InputJsonValue) : undefined,
        expiresAt,
      },
      include: {
        app: {
          select: { name: true, logoUrl: true, organizationId: true },
        },
      },
    });

    // Cache the session for fast lookups from QR scans
    const sessionWithApp = session as typeof session & { app: { name: string; logoUrl: string | null; organizationId: string } };
    await cacheSet(`auth_session:${token}`, {
      id: sessionWithApp.id,
      appId: sessionWithApp.appId,
      appName: sessionWithApp.app.name,
      appLogoUrl: sessionWithApp.app.logoUrl,
      scopes: sessionWithApp.scopes,
      status: sessionWithApp.status,
      expiresAt: sessionWithApp.expiresAt.toISOString(),
    }, AUTH_SESSION_EXPIRY_SECONDS);

    return session;
  }

  /**
   * Get session by ID. For polling by the third-party app.
   */
  async getSession(sessionId: string) {
    const session = await this.prisma.authSession.findUnique({
      where: { id: sessionId },
      include: {
        app: { select: { name: true, logoUrl: true, clientId: true } },
        user: { select: { id: true, name: true, email: true } },
      },
    });

    if (!session) return null;

    // Check expiry
    if (session.status === 'PENDING' && new Date() > session.expiresAt) {
      await this.expireSession(session.id);
      return { ...session, status: 'EXPIRED' as const };
    }

    return session;
  }

  /**
   * Get session by token. Used when user scans the QR code.
   * First checks cache, falls back to DB.
   */
  async getSessionByToken(token: string) {
    // Try cache first
    const cached = await cacheGet<{ id: string }>(`auth_session:${token}`);
    const sessionId = cached?.id;

    const session = await this.prisma.authSession.findUnique({
      where: sessionId ? { id: sessionId } : { token },
      include: {
        app: { select: { id: true, name: true, slug: true, logoUrl: true, organizationId: true, allowedScopes: true } },
      },
    });

    if (!session) return null;

    // Check expiry
    if (session.status === 'PENDING' && new Date() > session.expiresAt) {
      await this.expireSession(session.id);
      return null;
    }

    return session;
  }

  /**
   * Mark session as scanned. Called when user opens the approval page.
   */
  async markScanned(sessionId: string, userAgent?: string, clientIpHash?: string) {
    const session = await this.prisma.authSession.findUnique({ where: { id: sessionId } });
    if (!session || session.status !== 'PENDING') return null;
    if (new Date() > session.expiresAt) {
      await this.expireSession(sessionId);
      return null;
    }

    const updated = await this.prisma.authSession.update({
      where: { id: sessionId },
      data: {
        status: 'SCANNED',
        userAgent,
        clientIpHash,
        scannedAt: new Date(),
      },
    });

    // Notify SSE subscribers
    notifySubscribers(sessionId, 'scanned', { status: 'SCANNED', scannedAt: updated.scannedAt });

    return updated;
  }

  /**
   * Approve the session. The user confirms their identity.
   * Signs the approval with ECDSA to create a cryptographic proof.
   */
  async approveSession(
    sessionId: string,
    userId: string,
    geoLat?: number,
    geoLng?: number,
    targetOrganizationId?: string,
  ) {
    const session = await this.prisma.authSession.findUnique({
      where: { id: sessionId },
      include: { app: true },
    });

    if (!session) throw new Error('Session not found');
    if (session.status !== 'PENDING' && session.status !== 'SCANNED') {
      throw new Error(`Session cannot be approved in status: ${session.status}`);
    }
    if (new Date() > session.expiresAt) {
      await this.expireSession(sessionId);
      throw new Error('Session expired');
    }

    // Fetch user details
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, name: true, email: true },
    });
    if (!user) throw new Error('User not found');

    // Create ECDSA signature as cryptographic proof of approval
    // (AUDIT-FINDING-002 + 021). The signed payload is the unified
    // auth-session canonical form, and the stored value is an envelope
    // `${kid}:${base64sig}` so the verifier can look up the correct key
    // at verify time.
    //
    // AUDIT-FINDING-007: no fallback. If no active signing key exists or
    // the PEM read fails, the approval fails closed with a structured
    // error. The route handler catches `SigningUnavailableError` and
    // returns 503 `SIGNING_UNAVAILABLE` so operators are alerted to
    // missing key material — an unsigned approval is NOT still valid.
    const resolvedAtIso = new Date().toISOString();

    // ADR-0002 §7: the first-party CLI flow does NOT produce a federation
    // approval signature. That signature is the federated identity assertion a
    // relying party verifies via /verify-result; the CLI never consumes it (the
    // exchange authorizes key minting via targetOrganizationId + a fresh
    // membership re-check, not the signature). The qrauth-cli app is owned by
    // the keyless QRAuth Platform org, so requiring a signature here would 503
    // every CLI approve. Skip signing for qrauth-cli only — every other app
    // path below is byte-identical to before (same lookup, same
    // SigningUnavailableError on a missing key).
    const isCliApp = session.app.slug === QRAUTH_CLI_SLUG;

    let signature: string | null = null;
    if (!isCliApp) {
      // Get the organization's active signing key
      const signingKey = await this.prisma.signingKey.findFirst({
        where: { organizationId: session.app.organizationId, status: 'ACTIVE' },
      });

      if (!signingKey) {
        throw new SigningUnavailableError(
          `No active signing key for organization "${session.app.organizationId}" — cannot sign approval`,
        );
      }

      try {
        const canonical = buildApprovalCanonical({
          algVersion: AUTH_SESSION_APPROVAL_ALG_VERSION,
          kid: signingKey.keyId,
          sessionId,
          userId,
          appId: session.appId,
          resolvedAtIso,
        });
        const base64sig = await this.signingService.signCanonical(signingKey.keyId, canonical);
        signature = `${signingKey.keyId}:${base64sig}`;
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        throw new SigningUnavailableError(
          `Failed to sign approval for org "${session.app.organizationId}" keyId "${signingKey.keyId}": ${message}`,
        );
      }
    }

    // Atomic update: only approve if still in PENDING/SCANNED state
    // This prevents race conditions where two concurrent approvals both succeed
    const { count } = await this.prisma.authSession.updateMany({
      where: { id: sessionId, status: { in: ['PENDING', 'SCANNED'] } },
      data: {
        status: 'APPROVED',
        userId,
        geoLat,
        geoLng,
        signature,
        // CLI flow only (ADR-0002 §3): the org the approver scoped the key
        // to, resolved on the trusted device. Undefined for third-party
        // federation, leaving the column null and that flow unchanged.
        ...(targetOrganizationId ? { targetOrganizationId } : {}),
        // Same ISO string we signed over — `new Date(iso)` round-trips
        // losslessly for the subset of ISO values `toISOString()` produces.
        resolvedAt: new Date(resolvedAtIso),
      },
    });

    if (count === 0) {
      throw new Error('Session was already resolved by another request');
    }

    const updated = await this.prisma.authSession.findUniqueOrThrow({ where: { id: sessionId } });

    // Clear cache
    await cacheDel(`auth_session:${session.token}`);

    // Determine which user fields to return based on approved scopes
    const scopedUser: Record<string, unknown> = { id: user.id };
    if (session.scopes.includes('identity')) {
      scopedUser.name = user.name;
    }
    if (session.scopes.includes('email')) {
      scopedUser.email = user.email;
    }

    const result = {
      sessionId: updated.id,
      status: 'APPROVED',
      user: scopedUser,
      signature,
      resolvedAt: updated.resolvedAt?.toISOString(),
    };

    // Notify SSE subscribers
    notifySubscribers(sessionId, 'approved', result);

    // TODO: Call webhook if configured on the app
    // await this.callWebhook(session.app.webhookUrl, result);

    return result;
  }

  /**
   * Deny the session. The user declines.
   */
  async denySession(sessionId: string) {
    const session = await this.prisma.authSession.findUnique({ where: { id: sessionId } });
    if (!session) throw new Error('Session not found');
    if (session.status !== 'PENDING' && session.status !== 'SCANNED') {
      throw new Error(`Session cannot be denied in status: ${session.status}`);
    }

    // Atomic update: only deny if still in PENDING/SCANNED state
    const { count } = await this.prisma.authSession.updateMany({
      where: { id: sessionId, status: { in: ['PENDING', 'SCANNED'] } },
      data: {
        status: 'DENIED',
        resolvedAt: new Date(),
      },
    });

    if (count === 0) {
      throw new Error('Session was already resolved by another request');
    }

    await cacheDel(`auth_session:${session.token}`);

    notifySubscribers(sessionId, 'denied', { sessionId, status: 'DENIED' });

    return { sessionId, status: 'DENIED' };
  }

  /**
   * Expire a session.
   */
  async expireSession(sessionId: string) {
    const session = await this.prisma.authSession.update({
      where: { id: sessionId },
      data: { status: 'EXPIRED', resolvedAt: new Date() },
    });

    await cacheDel(`auth_session:${session.token}`);

    notifySubscribers(sessionId, 'expired', { sessionId: session.id, status: 'EXPIRED' });

    return session;
  }

  /**
   * Verify that an app owns a session (for polling/SSE).
   */
  async verifyAppOwnsSession(sessionId: string, appId: string): Promise<boolean> {
    const session = await this.prisma.authSession.findUnique({
      where: { id: sessionId },
      select: { appId: true },
    });
    return session?.appId === appId;
  }

  /**
   * Resolve the single org/role a CLI login should be scoped to (ADR-0002 §5).
   *
   * v0 auto-selects the approver's sole membership — no on-page picker. If the
   * approver has more than one membership we fail with a clear message rather
   * than guessing (the org-selector that resolves multi-org is deferred to
   * v0.1); zero memberships is also an error.
   */
  async resolveSoleCliMembership(
    userId: string,
  ): Promise<{ organizationId: string; role: MembershipRole }> {
    const memberships = await this.prisma.membership.findMany({
      where: { userId },
      select: { organizationId: true, role: true },
    });
    if (memberships.length === 0) {
      throw new CliExchangeError(
        403,
        'CLI_NO_MEMBERSHIP',
        'You are not a member of any organization, so a CLI key cannot be scoped.',
      );
    }
    if (memberships.length > 1) {
      throw new CliExchangeError(
        409,
        'CLI_MULTI_ORG',
        'Multi-org CLI login is not yet supported. You belong to more than one organization.',
      );
    }
    return memberships[0];
  }

  /**
   * Exchange an APPROVED CLI auth session for a freshly minted, org-scoped
   * `ApiKey` (ADR-0002 §3). Single-use and PKCE-bound. Throws `CliExchangeError`
   * on any precondition failure; returns the raw key exactly once on success.
   *
   * Minting goes through the primitive (`generateApiKey` + `apiKey.create`), not
   * the dashboard route — the role is the approver's *current* membership role
   * in the target org (re-checked here, not snapshotted at approve time), and
   * the key is tagged `source='cli'` + `createdByUserId` for the revocation
   * cascade.
   */
  async exchangeForApiKey(params: {
    sessionId: string;
    cliAppId: string;
    codeVerifier: string;
    hostLabel?: string;
  }): Promise<{ apiKey: string; organizationId: string; orgSlug: string; role: MembershipRole }> {
    const { sessionId, cliAppId, codeVerifier, hostLabel } = params;

    const session = await this.prisma.authSession.findUnique({
      where: { id: sessionId },
      select: {
        id: true,
        appId: true,
        status: true,
        userId: true,
        codeChallenge: true,
        targetOrganizationId: true,
        exchangedAt: true,
      },
    });

    // Scope every failure to "not found" until ownership is proven, so the
    // endpoint never confirms the existence of another app's session.
    if (!session || session.appId !== cliAppId) {
      throw new CliExchangeError(404, 'SESSION_NOT_FOUND', 'Session not found.');
    }
    if (!session.codeChallenge) {
      // A CLI session is always created with PKCE; a missing challenge means
      // this isn't an exchange-eligible session.
      throw new CliExchangeError(400, 'NOT_PKCE', 'Session is not PKCE-bound.');
    }
    if (!verifyCodeChallenge(codeVerifier, session.codeChallenge)) {
      throw new CliExchangeError(403, 'INVALID_VERIFIER', 'Invalid code_verifier.');
    }
    if (session.status !== 'APPROVED') {
      throw new CliExchangeError(409, 'NOT_APPROVED', `Session is not approved (status: ${session.status}).`);
    }
    if (session.exchangedAt !== null) {
      throw new CliExchangeError(409, 'ALREADY_EXCHANGED', 'This session has already been exchanged.');
    }
    if (!session.userId || !session.targetOrganizationId) {
      throw new CliExchangeError(409, 'NOT_RESOLVED', 'Session has no resolved approver or target organization.');
    }

    // Role ceiling: the minted key mirrors the approver's CURRENT membership
    // role in the target org. Re-checked at mint time so a membership revoked
    // between approve and exchange blocks issuance.
    const membership = await this.prisma.membership.findUnique({
      where: {
        userId_organizationId: {
          userId: session.userId,
          organizationId: session.targetOrganizationId,
        },
      },
      select: { role: true },
    });
    if (!membership) {
      throw new CliExchangeError(403, 'MEMBERSHIP_REVOKED', 'Your membership in the target organization no longer exists.');
    }

    const { fullKey, prefix, hash } = generateApiKey();
    const datePart = new Date().toISOString().slice(0, 10);
    const label = `cli:${hostLabel ? `${hostLabel}:` : ''}${datePart}`;

    // Single-use claim + mint in one transaction: the atomic `exchangedAt IS
    // NULL` guard (mirroring approveSession's status guard) means concurrent
    // exchanges race to the claim and exactly one wins; if the mint then fails
    // the claim rolls back so the session stays exchangeable.
    const orgId = session.targetOrganizationId;
    await this.prisma.$transaction(async (tx) => {
      const claim = await tx.authSession.updateMany({
        where: { id: sessionId, status: 'APPROVED', exchangedAt: null },
        data: { exchangedAt: new Date() },
      });
      if (claim.count === 0) {
        throw new CliExchangeError(409, 'ALREADY_EXCHANGED', 'This session has already been exchanged.');
      }
      await tx.apiKey.create({
        data: {
          organizationId: orgId,
          keyHash: hash,
          prefix,
          role: membership.role,
          label,
          source: 'cli',
          createdByUserId: session.userId,
        },
      });
    });

    const org = await this.prisma.organization.findUnique({
      where: { id: orgId },
      select: { slug: true },
    });

    return {
      apiKey: fullKey,
      organizationId: orgId,
      orgSlug: org?.slug ?? '',
      role: membership.role,
    };
  }
}
