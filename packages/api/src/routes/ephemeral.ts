import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { zodValidator } from '../middleware/validate.js';
import { rateLimitPublic, rateLimitAuth } from '../middleware/rateLimit.js';
import {
  createEphemeralSessionSchema,
  claimEphemeralSessionSchema,
  listEphemeralSessionsSchema,
} from '@qrauth/shared';
import { AppService } from '../services/app.js';
import { WebhookService } from '../services/webhook.js';
import { EphemeralSessionService } from '../services/ephemeral.js';
import { UsageService } from '../services/usage.js';

/**
 * Authenticate a request using app credentials.
 *
 * Supports two modes:
 *   1. Full auth: Basic auth or X-Client-Id/X-Client-Secret (for server-side use)
 *   2. PKCE: X-Client-Id only (for browser SDK — no secret required)
 *
 * Returns the app record and whether this was a PKCE (public-client) auth.
 */
async function authenticateApp(
  request: FastifyRequest,
  reply: FastifyReply,
  appService: AppService,
  allowPublicClient = false,
): Promise<{ id: string; organizationId: string; allowedScopes: string[]; isPublicClient: boolean } | null> {
  let clientId: string | undefined;
  let clientSecret: string | undefined;

  // Try Basic auth first
  const authHeader = request.headers.authorization;
  if (authHeader?.startsWith('Basic ')) {
    const decoded = Buffer.from(authHeader.slice(6), 'base64').toString('utf-8');
    const colonIndex = decoded.indexOf(':');
    if (colonIndex > 0) {
      clientId = decoded.slice(0, colonIndex);
      clientSecret = decoded.slice(colonIndex + 1);
    }
  }

  // Fall back to headers
  if (!clientId) {
    clientId = request.headers['x-client-id'] as string;
    clientSecret = request.headers['x-client-secret'] as string;
  }

  if (!clientId) {
    reply.status(401).send({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'App authentication required. Provide Basic auth, X-Client-Id/X-Client-Secret headers, or X-Client-Id with PKCE.',
    });
    return null;
  }

  // PKCE mode: clientId only, no secret
  if (!clientSecret && allowPublicClient) {
    const app = await appService.findByClientId(clientId);
    if (!app) {
      reply.status(401).send({ statusCode: 401, error: 'Unauthorized', message: 'Invalid client ID.' });
      return null;
    }
    return { ...app, isPublicClient: true };
  }

  if (!clientSecret) {
    reply.status(401).send({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'App authentication required. Provide client secret or use PKCE flow.',
    });
    return null;
  }

  const app = await appService.authenticateApp(clientId, clientSecret);
  if (!app) {
    reply.status(401).send({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Invalid app credentials.',
    });
    return null;
  }

  return { ...app, isPublicClient: false };
}

export default async function ephemeralRoutes(fastify: FastifyInstance): Promise<void> {
  const appService = new AppService(fastify.prisma);
  const sessionService = new EphemeralSessionService(fastify.prisma);

  // -----------------------------------------------------------------------
  // POST / — Create ephemeral session (app-authenticated)
  // -----------------------------------------------------------------------
  fastify.post('/', {
    config: { rateLimit: rateLimitAuth },
    preValidation: zodValidator({ body: createEphemeralSessionSchema }),
  }, async (request, reply) => {
    const app = await authenticateApp(request, reply, appService, true);
    if (!app) return; // 401 already sent

    const body = request.body as {
      scopes: string[];
      ttl?: string;
      maxUses?: number;
      deviceBinding?: boolean;
      metadata?: Record<string, unknown>;
    };

    // Check quota (reuse authSessions quota bucket for ephemeral sessions)
    const usageService = new UsageService(fastify.prisma);
    const appRecord = await fastify.prisma.app.findUnique({
      where: { id: app.id },
      select: { organizationId: true, organization: { select: { plan: true } } },
    });
    if (appRecord) {
      const quotaError = await usageService.checkQuota(
        appRecord.organizationId,
        appRecord.organization.plan || 'FREE',
        'authSessions',
      );
      if (quotaError) {
        return reply.status(429).send({ statusCode: 429, error: 'Quota Exceeded', message: quotaError });
      }
    }

    try {
      const session = await sessionService.createSession(app.id, body);

      // Increment usage counter (fire-and-forget)
      if (appRecord) {
        usageService.increment(appRecord.organizationId, 'authSessions').catch(() => {});
      }

      return reply.status(201).send({
        sessionId: session.id,
        token: session.token,
        claimUrl: session.claimUrl,
        expiresAt: session.expiresAt.toISOString(),
        scopes: session.scopes,
        ttlSeconds: session.ttlSeconds,
        maxUses: session.maxUses,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      return reply.status(500).send({ statusCode: 500, error: 'Internal Server Error', message });
    }
  });

  // -----------------------------------------------------------------------
  // GET / — List ephemeral sessions (app-authenticated)
  // -----------------------------------------------------------------------
  fastify.get('/', {
    config: { rateLimit: rateLimitAuth },
    preValidation: zodValidator({ querystring: listEphemeralSessionsSchema }),
  }, async (request, reply) => {
    const app = await authenticateApp(request, reply, appService);
    if (!app) return;

    const query = request.query as {
      status?: 'PENDING' | 'CLAIMED' | 'EXPIRED' | 'REVOKED';
      page?: number;
      pageSize?: number;
    };

    try {
      const result = await sessionService.listSessions(app.id, query);

      // Emit webhooks for sessions that were just auto-expired
      if (result.expiredSessionIds.length > 0) {
        const webhookService = new WebhookService(fastify.prisma);
        for (const sessionId of result.expiredSessionIds) {
          webhookService.emit(app.organizationId, {
            event: 'ephemeral.expired',
            data: { sessionId },
          }).catch(() => {});
        }
      }

      return reply.send({
        sessions: result.sessions.map((s) => ({
          sessionId: s.id,
          token: s.token,
          status: s.status,
          scopes: s.scopes,
          ttlSeconds: s.ttlSeconds,
          maxUses: s.maxUses,
          useCount: s.useCount,
          deviceBinding: s.deviceBinding,
          claimUrl: s.claimUrl,
          expiresAt: s.expiresAt.toISOString(),
          claimedAt: s.claimedAt?.toISOString() ?? null,
          revokedAt: s.revokedAt?.toISOString() ?? null,
          createdAt: s.createdAt.toISOString(),
        })),
        total: result.total,
        page: result.page,
        pageSize: result.pageSize,
        totalPages: result.totalPages,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      return reply.status(500).send({ statusCode: 500, error: 'Internal Server Error', message });
    }
  });

  // -----------------------------------------------------------------------
  // GET /:id — Get session status (app-authenticated)
  // -----------------------------------------------------------------------
  fastify.get('/:id', { config: { rateLimit: rateLimitAuth } }, async (request, reply) => {
    const app = await authenticateApp(request, reply, appService, true);
    if (!app) return;

    const { id } = request.params as { id: string };

    try {
      const session = await sessionService.getSession(id);
      if (!session || session.appId !== app.id) {
        return reply.status(404).send({ statusCode: 404, error: 'Not Found', message: 'Session not found' });
      }

      // Emit webhook if session was just auto-expired
      if (session.justExpired) {
        const webhookService = new WebhookService(fastify.prisma);
        webhookService.emit(app.organizationId, {
          event: 'ephemeral.expired',
          data: { sessionId: session.id },
        }).catch(() => {});
      }

      return reply.send({
        sessionId: session.id,
        token: session.token,
        status: session.status,
        scopes: session.scopes,
        ttlSeconds: session.ttlSeconds,
        maxUses: session.maxUses,
        useCount: session.useCount,
        deviceBinding: session.deviceBinding,
        claimUrl: session.claimUrl,
        expiresAt: session.expiresAt.toISOString(),
        claimedAt: session.claimedAt?.toISOString() ?? null,
        revokedAt: session.revokedAt?.toISOString() ?? null,
        createdAt: session.createdAt.toISOString(),
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      return reply.status(500).send({ statusCode: 500, error: 'Internal Server Error', message });
    }
  });

  // -----------------------------------------------------------------------
  // POST /:token/claim — Claim a session (public, rate-limited)
  // -----------------------------------------------------------------------
  fastify.post('/:token/claim', {
    config: { rateLimit: rateLimitPublic },
    preValidation: zodValidator({ body: claimEphemeralSessionSchema }),
  }, async (request, reply) => {
    const { token } = request.params as { token: string };
    const body = request.body as { deviceFingerprint?: string };

    try {
      const result = await sessionService.claimSession(token, body.deviceFingerprint);

      // Emit webhook (fire-and-forget)
      const webhookService = new WebhookService(fastify.prisma);
      webhookService.emit(result.organizationId, {
        event: 'ephemeral.claimed',
        data: { sessionId: result.sessionId, appId: undefined },
      }).catch(() => {});

      return reply.send({
        sessionId: result.sessionId,
        status: result.status,
        scopes: result.scopes,
        metadata: result.metadata,
        expiresAt: result.expiresAt,
        useCount: result.useCount,
        maxUses: result.maxUses,
      });
    } catch (err: unknown) {
      const statusCode = (err as { statusCode?: number }).statusCode;
      const message = err instanceof Error ? err.message : 'Unknown error';

      if (statusCode === 404) {
        return reply.status(404).send({ statusCode: 404, error: 'Not Found', message });
      }
      if (statusCode === 409) {
        return reply.status(409).send({ statusCode: 409, error: 'Conflict', message });
      }
      if (statusCode === 410) {
        // Emit expired webhook when a claim attempt discovers the session is expired
        const orgId = (err as { organizationId?: string }).organizationId;
        const expiredId = (err as { sessionId?: string }).sessionId;
        if (orgId && expiredId) {
          const webhookService = new WebhookService(fastify.prisma);
          webhookService.emit(orgId, {
            event: 'ephemeral.expired',
            data: { sessionId: expiredId },
          }).catch(() => {});
        }
        return reply.status(410).send({ statusCode: 410, error: 'Gone', message });
      }
      if (statusCode === 403) {
        return reply.status(403).send({ statusCode: 403, error: 'Forbidden', message });
      }
      if (statusCode === 400) {
        return reply.status(400).send({ statusCode: 400, error: 'Bad Request', message });
      }

      return reply.status(500).send({ statusCode: 500, error: 'Internal Server Error', message });
    }
  });

  // -----------------------------------------------------------------------
  // DELETE /:id — Revoke a session (app-authenticated)
  // -----------------------------------------------------------------------
  fastify.delete('/:id', { config: { rateLimit: rateLimitAuth } }, async (request, reply) => {
    const app = await authenticateApp(request, reply, appService);
    if (!app) return;

    const { id } = request.params as { id: string };

    try {
      const result = await sessionService.revokeSession(id, app.id);
      return reply.send(result);
    } catch (err: unknown) {
      const statusCode = (err as { statusCode?: number }).statusCode;
      const message = err instanceof Error ? err.message : 'Unknown error';

      if (statusCode === 404) {
        return reply.status(404).send({ statusCode: 404, error: 'Not Found', message });
      }
      if (statusCode === 409) {
        return reply.status(409).send({ statusCode: 409, error: 'Conflict', message });
      }

      return reply.status(500).send({ statusCode: 500, error: 'Internal Server Error', message });
    }
  });
}
