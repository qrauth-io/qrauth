import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { createHash } from 'node:crypto';
import { zodValidator } from '../middleware/validate.js';
import { rateLimitPublic, rateLimitAuth } from '../middleware/rateLimit.js';
import { createAuthSessionSchema } from '@qrauth/shared';
import { AppService } from '../services/app.js';
import { WebhookService } from '../services/webhook.js';
import {
  AuthSessionService,
  subscribeToSession,
  verifyApprovalSignature,
  SigningUnavailableError,
} from '../services/auth-session.js';
import { hashString } from '../lib/crypto.js';
import { constantTimeEqualString } from '../lib/constant-time.js';
import { collectRequestMetadata } from '../lib/metadata.js';
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
): Promise<{
  id: string;
  organizationId: string;
  allowedScopes: string[];
  redirectUrls: string[];
  isPublicClient: boolean;
} | null> {
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

  // PKCE mode: clientId only, no secret (allowed for session creation + polling)
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

/**
 * Verify a PKCE code_verifier against a stored code_challenge (S256).
 *
 * AUDIT-FINDING-012: constant-time compare on the challenge digest.
 * `===` on the base64url SHA-256 is not observably exploitable on the
 * public internet (network jitter exceeds the signal), but the
 * repository-wide contract is "never `===` on cryptographic strings".
 */
function verifyCodeChallenge(codeVerifier: string, codeChallenge: string): boolean {
  const hash = createHash('sha256').update(codeVerifier, 'ascii').digest('base64url');
  return constantTimeEqualString(hash, codeChallenge);
}

/**
 * Canonicalise a redirect URL for allowlist comparison.
 *
 * Strategy: parse with URL(), require http/https, drop query+fragment,
 * normalise trailing slash on the path. Returns null on parse failure.
 *
 * Rationale: developers register entry URLs (e.g. https://example.com/cb).
 * We compare on the canonical origin+path so that consumers can append
 * their own query parameters at runtime (e.g. ?from=qrauth) without
 * needing to re-register every variation. Path is matched exactly to
 * avoid open-redirect via path traversal.
 */
function normalizeRedirectUrl(input: string): string | null {
  try {
    const u = new URL(input);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
    const pathname = u.pathname.length > 1 && u.pathname.endsWith('/')
      ? u.pathname.slice(0, -1)
      : u.pathname;
    return `${u.origin}${pathname}`;
  } catch {
    return null;
  }
}

export default async function authSessionRoutes(fastify: FastifyInstance): Promise<void> {
  const appService = new AppService(fastify.prisma);
  const signingService = fastify.signingService;
  const sessionService = new AuthSessionService(fastify.prisma, signingService);
  const { authenticate } = fastify;

  // -----------------------------------------------------------------------
  // POST / — Create auth session (app-authenticated)
  // -----------------------------------------------------------------------
  fastify.post('/', {
    config: { rateLimit: rateLimitAuth },
    preValidation: zodValidator({ body: createAuthSessionSchema }),
  }, async (request, reply) => {
    // Allow public clients (PKCE) for session creation
    const app = await authenticateApp(request, reply, appService, true);
    if (!app) return; // 401 already sent

    const body = request.body as {
      scopes?: string[];
      redirectUrl?: string;
      metadata?: Record<string, unknown>;
      codeChallenge?: string;
      codeChallengeMethod?: string;
    };

    // PKCE validation: public clients MUST provide a code_challenge
    if (app.isPublicClient && !body.codeChallenge) {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: 'Public clients must provide a code_challenge for PKCE.',
      });
    }

    if (body.codeChallengeMethod && body.codeChallengeMethod !== 'S256') {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: 'Only S256 code_challenge_method is supported.',
      });
    }

    // Validate redirectUrl against the app's registered redirectUrls
    // allowlist. This is the same security model as OAuth 2.0: any URL the
    // hosted approval page navigates to after APPROVED must be pre-registered
    // by the app owner. Without this, a malicious caller could create a
    // session with redirectUrl=evil.com and trick a user into approving — the
    // approval page would then forward them to the attacker's site.
    if (body.redirectUrl) {
      const candidate = normalizeRedirectUrl(body.redirectUrl);
      if (!candidate) {
        return reply.status(400).send({
          statusCode: 400,
          error: 'Bad Request',
          message: 'redirectUrl must be a valid http(s) URL.',
        });
      }
      if (!app.redirectUrls || app.redirectUrls.length === 0) {
        return reply.status(400).send({
          statusCode: 400,
          error: 'Bad Request',
          message:
            'redirectUrl was provided but the app has no registered redirect URLs. ' +
            'Register the URL on the app first via the dashboard or PATCH /apps/:id.',
        });
      }
      const allowed = app.redirectUrls.map(normalizeRedirectUrl).filter((u): u is string => !!u);
      if (!allowed.includes(candidate)) {
        return reply.status(400).send({
          statusCode: 400,
          error: 'Bad Request',
          message:
            `redirectUrl "${body.redirectUrl}" is not registered for this app. ` +
            `Allowed URLs: ${app.redirectUrls.join(', ')}.`,
        });
      }
    }

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

    // Check auth session quota before creating
    const usageService = new UsageService(fastify.prisma);
    const appRecord = await fastify.prisma.app.findUnique({ where: { id: app.id }, select: { organizationId: true, organization: { select: { plan: true } } } });
    if (appRecord) {
      const quotaError = await usageService.checkQuota(appRecord.organizationId, appRecord.organization.plan || 'FREE', 'authSessions');
      if (quotaError) {
        return reply.status(429).send({ statusCode: 429, error: 'Quota Exceeded', message: quotaError });
      }
    }

    const session = await sessionService.createSession(app.id, body);

    // Store PKCE code_challenge on the session if provided
    if (body.codeChallenge) {
      await fastify.prisma.authSession.update({
        where: { id: session.id },
        data: { codeChallenge: body.codeChallenge },
      });
    }

    // Increment usage counter (fire-and-forget, quota already checked above)
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
  fastify.get('/:id', { config: { rateLimit: rateLimitAuth } }, async (request, reply) => {
    // Allow public clients (PKCE) for session polling
    const app = await authenticateApp(request, reply, appService, true);
    if (!app) return;

    const { id } = request.params as { id: string };
    const query = request.query as { code_verifier?: string };

    // Verify the app owns this session
    const owns = await sessionService.verifyAppOwnsSession(id, app.id);
    if (!owns) {
      return reply.status(404).send({ statusCode: 404, error: 'Not Found', message: 'Session not found' });
    }

    const session = await sessionService.getSession(id);
    if (!session) {
      return reply.status(404).send({ statusCode: 404, error: 'Not Found', message: 'Session not found' });
    }

    // For PKCE sessions: require code_verifier to access approved results
    const isPkceSession = !!session.codeChallenge;
    const hasUserData = session.status === 'APPROVED' && session.user;

    if (isPkceSession && hasUserData && app.isPublicClient) {
      if (!query.code_verifier) {
        // Return status without sensitive data until code_verifier is provided
        return reply.send({
          sessionId: session.id,
          status: session.status,
          scopes: session.scopes,
          user: null,
          signature: null,
          expiresAt: session.expiresAt.toISOString(),
          scannedAt: session.scannedAt?.toISOString() ?? null,
          resolvedAt: session.resolvedAt?.toISOString() ?? null,
        });
      }

      if (!verifyCodeChallenge(query.code_verifier, session.codeChallenge!)) {
        return reply.status(403).send({
          statusCode: 403,
          error: 'Forbidden',
          message: 'Invalid code_verifier.',
        });
      }
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
  fastify.get('/:id/sse', { config: { rateLimit: rateLimitAuth } }, async (request, reply) => {
    // Allow public clients (PKCE) for SSE streaming
    const app = await authenticateApp(request, reply, appService, true);
    if (!app) return;

    const { id } = request.params as { id: string };
    const query = request.query as { code_verifier?: string };

    const owns = await sessionService.verifyAppOwnsSession(id, app.id);
    if (!owns) {
      return reply.status(404).send({ statusCode: 404, error: 'Not Found', message: 'Session not found' });
    }

    // AUDIT-FINDING-018: for PKCE sessions accessed by public clients,
    // require `code_verifier` before any `user` or `signature` data
    // leaves the server. Without this gate a caller holding just the
    // clientId and session id could receive the full approved payload
    // over SSE, bypassing the PKCE binding that the polling path
    // already enforces.
    const initialSession = await sessionService.getSession(id);
    const isPkceSession = !!initialSession?.codeChallenge;
    const pkcePublicClient = app.isPublicClient && isPkceSession;
    let pkceVerified = false;
    if (pkcePublicClient) {
      if (!query.code_verifier) {
        return reply.status(403).send({
          statusCode: 403,
          error: 'Forbidden',
          message: 'code_verifier is required for SSE subscription to a PKCE-bound session.',
        });
      }
      if (!verifyCodeChallenge(query.code_verifier, initialSession!.codeChallenge!)) {
        return reply.status(403).send({
          statusCode: 403,
          error: 'Forbidden',
          message: 'Invalid code_verifier.',
        });
      }
      pkceVerified = true;
    }

    // `canEmitSensitive` gates user + signature data in every event
    // written from this handler. Non-PKCE sessions (and verified PKCE
    // sessions) get the full payload; unverified PKCE public clients
    // get only status events. This handler never enters the latter
    // branch because the 403 short-circuit above fires before SSE
    // begins — the flag is kept as a defence-in-depth readability aid.
    const canEmitSensitive = !pkcePublicClient || pkceVerified;

    // Set up SSE
    reply.raw.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no', // Disable nginx buffering
    });

    // Send initial status
    const session = initialSession;
    if (session) {
      reply.raw.write(`event: status\ndata: ${JSON.stringify({ status: session.status })}\n\n`);

      // If already resolved, send the final event and close
      if (['APPROVED', 'DENIED', 'EXPIRED'].includes(session.status)) {
        const payload: Record<string, unknown> = {
          sessionId: session.id,
          status: session.status,
        };
        if (canEmitSensitive) {
          payload.user = session.user;
          payload.signature = session.signature;
        }
        reply.raw.write(`event: ${session.status.toLowerCase()}\ndata: ${JSON.stringify(payload)}\n\n`);
        reply.raw.end();
        return;
      }
    }

    // Subscribe to real-time events. For unverified PKCE public
    // clients we would strip `user` and `signature` from each event
    // payload before forwarding; the 403 above makes that branch
    // unreachable in practice.
    const unsubscribe = subscribeToSession(id, (event, data) => {
      try {
        if (canEmitSensitive) {
          reply.raw.write(`event: ${event}\ndata: ${data}\n\n`);
        } else {
          // Strip any sensitive fields from the broadcast payload.
          let sanitized: string;
          try {
            const parsed = JSON.parse(data);
            delete parsed.user;
            delete parsed.signature;
            sanitized = JSON.stringify(parsed);
          } catch {
            sanitized = data;
          }
          reply.raw.write(`event: ${event}\ndata: ${sanitized}\n\n`);
        }
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
    config: { rateLimit: rateLimitAuth },
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
      // AUDIT-FINDING-007: approval signing failures surface as 503 so
      // operators are alerted to missing key material. The session stays
      // in PENDING/SCANNED; the client is expected to retry.
      if (err instanceof SigningUnavailableError) {
        request.log.error(
          { err, sessionId: session.id, orgId: session.app.organizationId },
          'Approval signing unavailable — check SigningKey row and PEM file on disk',
        );
        return reply.status(503).send({
          statusCode: 503,
          error: 'SIGNING_UNAVAILABLE',
          message: 'Approval signing is temporarily unavailable. Please retry.',
        });
      }
      const message = err instanceof Error ? err.message : 'Unknown error';
      return reply.status(400).send({ statusCode: 400, error: 'Bad Request', message });
    }
  });

  // -----------------------------------------------------------------------
  // POST /:token/deny — User denies (JWT-authenticated)
  // -----------------------------------------------------------------------
  fastify.post('/:token/deny', {
    config: { rateLimit: rateLimitAuth },
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
  fastify.post('/verify-result', { config: { rateLimit: rateLimitPublic } }, async (request, reply) => {
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

    // AUDIT-FINDING-002: real cryptographic verification. The previous
    // implementation performed `session.signature === body.signature`
    // which reduced the endpoint to a bearer-token check over the stored
    // signature — any actor who observed a historical `signature` value
    // could replay it and receive `valid: true` without holding any
    // secret. We now verify the ECDSA signature against the
    // organisation's public key over the auth-session canonical form.
    const cryptoValid = await verifyApprovalSignature(
      fastify.prisma,
      {
        id: session.id,
        userId: session.userId,
        appId: session.appId,
        signature: session.signature,
        resolvedAt: session.resolvedAt,
        app: { organizationId: session.app.organizationId },
      },
      body.signature,
    );
    const isApproved = session.status === 'APPROVED';

    return reply.send({
      valid: cryptoValid && isApproved,
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
