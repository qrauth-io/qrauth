import type { PrismaClient } from '@prisma/client';
import { randomBytes } from 'node:crypto';
import { signPayload, hashString } from '../lib/crypto.js';
import { config } from '../lib/config.js';
import { cacheSet, cacheGet, cacheDel } from '../lib/cache.js';
import { AUTH_SESSION_EXPIRY_SECONDS } from '@vqr/shared';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';

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
  constructor(private prisma: PrismaClient) {}

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
    const token = randomBytes(24).toString('base64url'); // 32 chars, URL-safe

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
    // Payload: sessionId + userId + appId + timestamp
    const timestamp = new Date().toISOString();
    const payload = `${sessionId}:${userId}:${session.appId}:${timestamp}`;

    // Get the organization's active signing key
    const signingKey = await this.prisma.signingKey.findFirst({
      where: { organizationId: session.app.organizationId, status: 'ACTIVE' },
    });

    let signature = '';
    if (signingKey) {
      try {
        const keyPath = path.join(config.kms.ecdsaPrivateKeyPath, `${signingKey.keyId}.pem`);
        const privateKey = await fs.readFile(keyPath, 'utf-8');
        signature = signPayload(privateKey, payload);
      } catch {
        // If signing fails, continue without signature — the session approval is still valid
        signature = `unsigned:${hashString(payload)}`;
      }
    } else {
      signature = `unsigned:${hashString(payload)}`;
    }

    const updated = await this.prisma.authSession.update({
      where: { id: sessionId },
      data: {
        status: 'APPROVED',
        userId,
        geoLat,
        geoLng,
        signature,
        resolvedAt: new Date(),
      },
    });

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

    const updated = await this.prisma.authSession.update({
      where: { id: sessionId },
      data: {
        status: 'DENIED',
        resolvedAt: new Date(),
      },
    });

    await cacheDel(`auth_session:${session.token}`);

    notifySubscribers(sessionId, 'denied', { sessionId: updated.id, status: 'DENIED' });

    return updated;
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
