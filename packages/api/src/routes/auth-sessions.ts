import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { zodValidator } from '../middleware/validate.js';
import { createAuthSessionSchema } from '@qrauth/shared';
import { AppService } from '../services/app.js';
import { WebhookService } from '../services/webhook.js';
import { AuthSessionService, subscribeToSession } from '../services/auth-session.js';
import { hashString } from '../lib/crypto.js';
import { collectRequestMetadata } from '../lib/metadata.js';
import { UsageService } from '../services/usage.js';

/**
 * Authenticate a request using app credentials (Basic auth or X-Client-Id/X-Client-Secret headers).
 * Returns the app record or sends a 401 response.
 */
async function authenticateApp(
  request: FastifyRequest,
  reply: FastifyReply,
  appService: AppService,
): Promise<{ id: string; organizationId: string; allowedScopes: string[] } | null> {
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

  if (!clientId || !clientSecret) {
    reply.status(401).send({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'App authentication required. Provide Basic auth or X-Client-Id/X-Client-Secret headers.',
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

  return app;
}

export default async function authSessionRoutes(fastify: FastifyInstance): Promise<void> {
  const appService = new AppService(fastify.prisma);
  const sessionService = new AuthSessionService(fastify.prisma);
  const { authenticate } = fastify;

  // -----------------------------------------------------------------------
  // POST / — Create auth session (app-authenticated)
  // -----------------------------------------------------------------------
  fastify.post('/', {
    preValidation: zodValidator({ body: createAuthSessionSchema }),
  }, async (request, reply) => {
    const app = await authenticateApp(request, reply, appService);
    if (!app) return; // 401 already sent

    const body = request.body as {
      scopes?: string[];
      redirectUrl?: string;
      metadata?: Record<string, unknown>;
    };

    // Validate requested scopes against app's allowed scopes
    if (body.scopes) {
      const disallowed = body.scopes.filter((s: string) => !app.allowedScopes.includes(s));
      if (disallowed.length > 0) {
        return reply.status(400).send({
          statusCode: 400,
          error: 'Bad Request',
          message: `Scopes not allowed for this app: ${disallowed.join(', ')}`,
        });
      }
    }

    const session = await sessionService.createSession(app.id, body);

    // Track auth session usage
    const usageService = new UsageService(fastify.prisma);
    const appRecord = await fastify.prisma.app.findUnique({ where: { id: app.id }, select: { organizationId: true } });
    if (appRecord) {
      usageService.increment(appRecord.organizationId, 'authSessions').catch(() => {});
    }

    // Build the QR URL — this is what gets encoded in the QR code
    const baseUrl = process.env.WEBAUTHN_ORIGIN ?? `http://localhost:${config_port(fastify)}`;
    const qrUrl = `${baseUrl}/a/${session.token}`;

    return reply.status(201).send({
      sessionId: session.id,
      token: session.token,
      qrUrl,
      qrDataUrl: qrUrl, // same — the value to encode in QR
      status: session.status,
      scopes: session.scopes,
      expiresAt: session.expiresAt.toISOString(),
    });
  });

  // -----------------------------------------------------------------------
  // GET /:id — Get session status (app-authenticated)
  // -----------------------------------------------------------------------
  fastify.get('/:id', async (request, reply) => {
    const app = await authenticateApp(request, reply, appService);
    if (!app) return;

    const { id } = request.params as { id: string };

    // Verify the app owns this session
    const owns = await sessionService.verifyAppOwnsSession(id, app.id);
    if (!owns) {
      return reply.status(404).send({ statusCode: 404, error: 'Not Found', message: 'Session not found' });
    }

    const session = await sessionService.getSession(id);
    if (!session) {
      return reply.status(404).send({ statusCode: 404, error: 'Not Found', message: 'Session not found' });
    }

    return reply.send({
      sessionId: session.id,
      status: session.status,
      scopes: session.scopes,
      user: session.user ? {
        id: session.user.id,
        ...(session.scopes.includes('identity') ? { name: session.user.name } : {}),
        ...(session.scopes.includes('email') ? { email: session.user.email } : {}),
      } : null,
      signature: session.signature,
      expiresAt: session.expiresAt.toISOString(),
      scannedAt: session.scannedAt?.toISOString() ?? null,
      resolvedAt: session.resolvedAt?.toISOString() ?? null,
    });
  });

  // -----------------------------------------------------------------------
  // GET /:id/sse — Real-time SSE stream (app-authenticated)
  // -----------------------------------------------------------------------
  fastify.get('/:id/sse', async (request, reply) => {
    const app = await authenticateApp(request, reply, appService);
    if (!app) return;

    const { id } = request.params as { id: string };

    const owns = await sessionService.verifyAppOwnsSession(id, app.id);
    if (!owns) {
      return reply.status(404).send({ statusCode: 404, error: 'Not Found', message: 'Session not found' });
    }

    // Set up SSE
    reply.raw.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no', // Disable nginx buffering
    });

    // Send initial status
    const session = await sessionService.getSession(id);
    if (session) {
      reply.raw.write(`event: status\ndata: ${JSON.stringify({ status: session.status })}\n\n`);

      // If already resolved, send the final event and close
      if (['APPROVED', 'DENIED', 'EXPIRED'].includes(session.status)) {
        reply.raw.write(`event: ${session.status.toLowerCase()}\ndata: ${JSON.stringify({
          sessionId: session.id,
          status: session.status,
          user: session.user,
          signature: session.signature,
        })}\n\n`);
        reply.raw.end();
        return;
      }
    }

    // Subscribe to real-time events
    const unsubscribe = subscribeToSession(id, (event, data) => {
      try {
        reply.raw.write(`event: ${event}\ndata: ${data}\n\n`);
      } catch {
        // Client disconnected
      }

      // Close after terminal events
      if (['approved', 'denied', 'expired'].includes(event)) {
        try { reply.raw.end(); } catch { /* already closed */ }
      }
    });

    // Heartbeat to keep connection alive
    const heartbeat = setInterval(() => {
      try {
        reply.raw.write(`:heartbeat\n\n`);
      } catch {
        clearInterval(heartbeat);
      }
    }, 15000);

    // Clean up on client disconnect
    request.raw.on('close', () => {
      clearInterval(heartbeat);
      unsubscribe();
    });
  });

  // -----------------------------------------------------------------------
  // POST /:token/approve — User approves (JWT-authenticated)
  // -----------------------------------------------------------------------
  fastify.post('/:token/approve', {
    preHandler: [authenticate],
  }, async (request, reply) => {
    const { token } = request.params as { token: string };
    const body = request.body as { geoLat?: number; geoLng?: number } | undefined;

    // Suppress unused variable warning — hashString is imported for use in approval routes
    void hashString;

    const session = await sessionService.getSessionByToken(token);
    if (!session) {
      return reply.status(404).send({ statusCode: 404, error: 'Not Found', message: 'Session not found or expired' });
    }

    const meta = await collectRequestMetadata(request);

    try {
      const result = await sessionService.approveSession(
        session.id,
        request.user!.id,
        body?.geoLat,
        body?.geoLng,
      );

      // Update session with metadata
      await fastify.prisma.authSession.update({
        where: { id: session.id },
        data: {
          deviceFingerprint: (request.body as any)?.fingerprint || meta.fingerprint,
          ipCountry: meta.ipCountry,
          ipCity: meta.ipCity,
          referrer: meta.referrer,
        },
      });

      // Emit webhook (fire-and-forget).
      const webhookService = new WebhookService(fastify.prisma);
      webhookService.emit(session.app.organizationId, {
        event: 'auth.approved',
        data: { sessionId: session.id, appId: session.appId },
      }).catch(() => {});

      return reply.send(result);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      return reply.status(400).send({ statusCode: 400, error: 'Bad Request', message });
    }
  });

  // -----------------------------------------------------------------------
  // POST /:token/deny — User denies (JWT-authenticated)
  // -----------------------------------------------------------------------
  fastify.post('/:token/deny', {
    preHandler: [authenticate],
  }, async (request, reply) => {
    const { token } = request.params as { token: string };

    const session = await sessionService.getSessionByToken(token);
    if (!session) {
      return reply.status(404).send({ statusCode: 404, error: 'Not Found', message: 'Session not found or expired' });
    }

    try {
      await sessionService.denySession(session.id);

      // Emit webhook (fire-and-forget).
      const webhookService = new WebhookService(fastify.prisma);
      webhookService.emit(session.app.organizationId, {
        event: 'auth.denied',
        data: { sessionId: session.id, appId: session.appId },
      }).catch(() => {});

      return reply.send({ status: 'DENIED' });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      return reply.status(400).send({ statusCode: 400, error: 'Bad Request', message });
    }
  });

  // -----------------------------------------------------------------------
  // POST /verify-result — Verify an auth session result (public, for third-party backends)
  // -----------------------------------------------------------------------
  fastify.post('/verify-result', async (request, reply) => {
    const body = request.body as { sessionId: string; signature: string };

    if (!body.sessionId || !body.signature) {
      return reply.status(400).send({
        statusCode: 400, error: 'Bad Request',
        message: 'sessionId and signature are required',
      });
    }

    const session = await fastify.prisma.authSession.findUnique({
      where: { id: body.sessionId },
      include: {
        app: { select: { name: true, clientId: true, organizationId: true } },
        user: { select: { id: true, name: true, email: true } },
      },
    });

    if (!session) {
      return reply.status(404).send({ statusCode: 404, error: 'Not Found', message: 'Session not found' });
    }

    const signatureMatch = session.signature === body.signature;

    return reply.send({
      valid: signatureMatch && session.status === 'APPROVED',
      session: {
        id: session.id,
        status: session.status,
        appName: session.app.name,
        scopes: session.scopes,
        user: session.user ? {
          id: session.user.id,
          ...(session.scopes.includes('identity') ? { name: session.user.name } : {}),
          ...(session.scopes.includes('email') ? { email: session.user.email } : {}),
        } : null,
        signature: session.signature,
        resolvedAt: session.resolvedAt?.toISOString(),
      },
    });
  });
}

function config_port(fastify: FastifyInstance): number {
  const addr = fastify.server.address();
  return addr && typeof addr === 'object' ? addr.port : 3000;
}
