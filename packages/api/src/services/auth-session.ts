import type { PrismaClient } from '@prisma/client';
import { randomBytes } from 'node:crypto';
import { verifySignature } from '../lib/crypto.js';
import { cacheSet, cacheGet, cacheDel } from '../lib/cache.js';
import { AUTH_SESSION_EXPIRY_SECONDS, assertCanonicalSafe } from '@qrauth/shared';
import { constantTimeEqualString } from '../lib/constant-time.js';
import type { SigningService } from './signing.js';

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
        app: { select: { id: true, name: true, logoUrl: true, organizationId: true, allowedScopes: true } },
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
  async approveSession(sessionId: string, userId: string, geoLat?: number, geoLng?: number) {
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

    // Get the organization's active signing key
    const signingKey = await this.prisma.signingKey.findFirst({
      where: { organizationId: session.app.organizationId, status: 'ACTIVE' },
    });

    if (!signingKey) {
      throw new SigningUnavailableError(
        `No active signing key for organization "${session.app.organizationId}" — cannot sign approval`,
      );
    }

    let signature: string;
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
}
