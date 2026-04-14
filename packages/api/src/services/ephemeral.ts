import type { PrismaClient } from '@prisma/client';
import { randomBytes, createHash } from 'node:crypto';
import { cacheSet, cacheGet, cacheDel } from '../lib/cache.js';
import { EPHEMERAL_SESSION_DEFAULT_TTL, EPHEMERAL_SESSION_MAX_TTL } from '@qrauth/shared';
import { config } from '../lib/config.js';

// ---------------------------------------------------------------------------
// TTL parsing
// ---------------------------------------------------------------------------

/**
 * Parse a human-readable TTL string into seconds.
 * Supports: '30s', '5m', '6h', '30d'.
 * Returns the value clamped to EPHEMERAL_SESSION_MAX_TTL.
 * Defaults to EPHEMERAL_SESSION_DEFAULT_TTL if the string is unrecognised.
 */
export function parseTTL(ttl: string): number {
  const match = ttl.trim().match(/^(\d+)([smhd])$/);
  if (!match) return EPHEMERAL_SESSION_DEFAULT_TTL;

  const value = parseInt(match[1], 10);
  const unit = match[2];

  let seconds: number;
  switch (unit) {
    case 's': seconds = value; break;
    case 'm': seconds = value * 60; break;
    case 'h': seconds = value * 3600; break;
    case 'd': seconds = value * 86400; break;
    default:  seconds = EPHEMERAL_SESSION_DEFAULT_TTL;
  }

  return Math.min(seconds, EPHEMERAL_SESSION_MAX_TTL);
}

// ---------------------------------------------------------------------------
// Cache key helpers
// ---------------------------------------------------------------------------

function cacheKey(token: string): string {
  return `ephemeral:${token}`;
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export class EphemeralSessionService {
  constructor(private prisma: PrismaClient) {}

  /**
   * Create a new ephemeral session for the given app.
   * Returns the session record including the one-time claim URL.
   */
  async createSession(
    appId: string,
    data: {
      scopes: string[];
      ttl?: string;
      maxUses?: number;
      deviceBinding?: boolean;
      metadata?: Record<string, unknown>;
    },
  ) {
    const token = randomBytes(24).toString('base64url');
    const ttlSeconds = parseTTL(data.ttl ?? '30m');
    const expiresAt = new Date(Date.now() + ttlSeconds * 1000);

    const baseUrl = process.env.WEBAUTHN_ORIGIN ?? `http://localhost:${config.server.port}`;
    const claimUrl = `${baseUrl}/api/v1/ephemeral/${token}/claim`;

    const session = await this.prisma.ephemeralSession.create({
      data: {
        appId,
        token,
        scopes: data.scopes,
        ttlSeconds,
        maxUses: data.maxUses ?? 1,
        deviceBinding: data.deviceBinding ?? false,
        metadata: data.metadata
          ? (data.metadata as import('@prisma/client').Prisma.InputJsonValue)
          : undefined,
        claimUrl,
        expiresAt,
      },
      include: {
        app: {
          select: { name: true, organizationId: true },
        },
      },
    });

    // Cache for fast claim lookups
    await cacheSet(cacheKey(token), {
      id: session.id,
      appId: session.appId,
      scopes: session.scopes,
      status: session.status,
      ttlSeconds: session.ttlSeconds,
      maxUses: session.maxUses,
      useCount: session.useCount,
      deviceBinding: session.deviceBinding,
      boundDeviceHash: session.boundDeviceHash,
      expiresAt: session.expiresAt.toISOString(),
    }, ttlSeconds);

    return session;
  }

  /**
   * Claim an ephemeral session by its token.
   * Validates status, expiry, and optional device binding.
   * Uses an atomic updateMany to prevent double-claims.
   */
  async claimSession(token: string, deviceFingerprint?: string) {
    // Try cache first, then fall back to DB
    const cached = await cacheGet<{ id: string }>(cacheKey(token));
    const sessionId = cached?.id;

    const session = await this.prisma.ephemeralSession.findUnique({
      where: sessionId ? { id: sessionId } : { token },
      include: {
        app: { select: { organizationId: true } },
      },
    });

    if (!session) {
      throw Object.assign(new Error('Session not found'), { statusCode: 404 });
    }

    if (session.status !== 'PENDING') {
      throw Object.assign(
        new Error(`Session cannot be claimed in status: ${session.status}`),
        { statusCode: 409 },
      );
    }

    if (new Date() > session.expiresAt) {
      // Mark expired in DB (best-effort, do not await for claim path)
      this.prisma.ephemeralSession
        .updateMany({
          where: { id: session.id, status: 'PENDING' },
          data: { status: 'EXPIRED' },
        })
        .catch(() => {});
      await cacheDel(cacheKey(token));
      throw Object.assign(new Error('Session has expired'), {
        statusCode: 410,
        sessionId: session.id,
        organizationId: session.app.organizationId,
      });
    }

    // Device binding checks
    if (session.deviceBinding) {
      if (!deviceFingerprint) {
        throw Object.assign(
          new Error('Device fingerprint required for device-bound sessions'),
          { statusCode: 400 },
        );
      }

      const fingerprintHash = createHash('sha256')
        .update(deviceFingerprint)
        .digest('hex');

      if (session.boundDeviceHash) {
        // Already bound — verify the fingerprint matches
        if (session.boundDeviceHash !== fingerprintHash) {
          throw Object.assign(
            new Error('Device fingerprint mismatch'),
            { statusCode: 403 },
          );
        }
      }
    }

    // Calculate next useCount and whether the session should be fully claimed
    const nextUseCount = session.useCount + 1;
    const shouldClaim = nextUseCount >= session.maxUses;
    const newStatus = shouldClaim ? 'CLAIMED' : 'PENDING';

    // Build device hash for binding (if first claim and deviceBinding is on)
    const boundDeviceHash =
      session.deviceBinding && !session.boundDeviceHash && deviceFingerprint
        ? createHash('sha256').update(deviceFingerprint).digest('hex')
        : session.boundDeviceHash;

    // Atomic update — only proceed if still PENDING to prevent race conditions
    const { count } = await this.prisma.ephemeralSession.updateMany({
      where: { id: session.id, status: 'PENDING' },
      data: {
        useCount: nextUseCount,
        status: newStatus,
        boundDeviceHash: boundDeviceHash ?? undefined,
        claimedAt: shouldClaim ? new Date() : undefined,
      },
    });

    if (count === 0) {
      throw Object.assign(
        new Error('Session was already claimed by another request'),
        { statusCode: 409 },
      );
    }

    // Refresh cache or evict when fully claimed
    if (shouldClaim) {
      await cacheDel(cacheKey(token));
    } else {
      await cacheSet(cacheKey(token), {
        id: session.id,
        appId: session.appId,
        scopes: session.scopes,
        status: 'PENDING',
        ttlSeconds: session.ttlSeconds,
        maxUses: session.maxUses,
        useCount: nextUseCount,
        deviceBinding: session.deviceBinding,
        boundDeviceHash,
        expiresAt: session.expiresAt.toISOString(),
      }, Math.max(0, Math.floor((session.expiresAt.getTime() - Date.now()) / 1000)));
    }

    return {
      sessionId: session.id,
      status: newStatus,
      scopes: session.scopes,
      metadata: session.metadata,
      expiresAt: session.expiresAt.toISOString(),
      useCount: nextUseCount,
      maxUses: session.maxUses,
      organizationId: session.app.organizationId,
    };
  }

  /**
   * Revoke an ephemeral session. Only the owning app can revoke.
   */
  async revokeSession(sessionId: string, appId: string) {
    const session = await this.prisma.ephemeralSession.findUnique({
      where: { id: sessionId },
      select: { appId: true, token: true, status: true },
    });

    if (!session) {
      throw Object.assign(new Error('Session not found'), { statusCode: 404 });
    }

    if (session.appId !== appId) {
      throw Object.assign(new Error('Session not found'), { statusCode: 404 });
    }

    if (session.status === 'REVOKED') {
      throw Object.assign(new Error('Session is already revoked'), { statusCode: 409 });
    }

    // Atomic update
    const { count } = await this.prisma.ephemeralSession.updateMany({
      where: { id: sessionId, appId, status: { not: 'REVOKED' } },
      data: { status: 'REVOKED', revokedAt: new Date() },
    });

    if (count === 0) {
      throw Object.assign(
        new Error('Session could not be revoked — it may already be revoked'),
        { statusCode: 409 },
      );
    }

    await cacheDel(cacheKey(session.token));

    return { sessionId, status: 'REVOKED' };
  }

  /**
   * Get a single session by ID, including the associated app.
   */
  async getSession(sessionId: string) {
    const session = await this.prisma.ephemeralSession.findUnique({
      where: { id: sessionId },
      include: {
        app: { select: { id: true, name: true, clientId: true } },
      },
    });

    if (!session) return null;

    // Auto-expire PENDING sessions that have passed their expiry
    if (session.status === 'PENDING' && new Date() > session.expiresAt) {
      await this.prisma.ephemeralSession.updateMany({
        where: { id: sessionId, status: 'PENDING' },
        data: { status: 'EXPIRED' },
      });
      return { ...session, status: 'EXPIRED' as const, justExpired: true };
    }

    return { ...session, justExpired: false };
  }

  /**
   * List ephemeral sessions for the given app with optional status filter
   * and pagination. PENDING sessions past their expiresAt are auto-expired.
   */
  async listSessions(
    appId: string,
    filters: {
      status?: 'PENDING' | 'CLAIMED' | 'EXPIRED' | 'REVOKED';
      page?: number;
      pageSize?: number;
    },
  ) {
    const page = Math.max(1, filters.page ?? 1);
    const pageSize = Math.min(100, Math.max(1, filters.pageSize ?? 20));
    const skip = (page - 1) * pageSize;

    // Auto-expire stale PENDING sessions for this app
    const staleIds = (await this.prisma.ephemeralSession.findMany({
      where: { appId, status: 'PENDING', expiresAt: { lt: new Date() } },
      select: { id: true },
    })).map((s) => s.id);

    if (staleIds.length > 0) {
      await this.prisma.ephemeralSession.updateMany({
        where: { id: { in: staleIds }, status: 'PENDING' },
        data: { status: 'EXPIRED' },
      });
    }

    const where = {
      appId,
      ...(filters.status ? { status: filters.status } : {}),
    };

    const [total, sessions] = await Promise.all([
      this.prisma.ephemeralSession.count({ where }),
      this.prisma.ephemeralSession.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip,
        take: pageSize,
        include: {
          app: { select: { name: true } },
        },
      }),
    ]);

    return {
      sessions,
      total,
      page,
      pageSize,
      totalPages: Math.ceil(total / pageSize),
      expiredSessionIds: staleIds,
    };
  }
}
