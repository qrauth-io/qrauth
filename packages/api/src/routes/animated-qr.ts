import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { rateLimitPublic, rateLimitAuth } from '../middleware/rateLimit.js';
import { AppService } from '../services/app.js';
import { AnimatedQRService } from '../services/animated-qr.js';
import { config } from '../lib/config.js';

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

export default async function animatedQRRoutes(fastify: FastifyInstance): Promise<void> {
  const appService = new AppService(fastify.prisma);
  const animatedQRService = new AnimatedQRService({
    macSigner: fastify.macSigner,
    macSignerStats: fastify.macSignerStatsCollector,
    backend: fastify.macSignerBackend,
    logger: {
      warn: (obj, msg) => fastify.log.warn(obj, msg),
      error: (obj, msg) => fastify.log.error(obj, msg),
    },
  });

  // -------------------------------------------------------------------------
  // POST /session — Create an animated display session (app-authenticated)
  // -------------------------------------------------------------------------
  fastify.post('/session', { config: { rateLimit: rateLimitAuth } }, async (request, reply) => {
    const app = await authenticateApp(request, reply, appService, true);
    if (!app) return; // 401 already sent

    const body = request.body as { authSessionId?: string; token?: string };

    if (!body.authSessionId && !body.token) {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: 'Either authSessionId or token is required.',
      });
    }

    // Resolve the auth session by ID or token
    let authSession: { id: string; token: string; appId: string; expiresAt: Date } | null = null;

    if (body.authSessionId) {
      authSession = await fastify.prisma.authSession.findUnique({
        where: { id: body.authSessionId },
        select: { id: true, token: true, appId: true, expiresAt: true },
      });
    } else if (body.token) {
      authSession = await fastify.prisma.authSession.findUnique({
        where: { token: body.token },
        select: { id: true, token: true, appId: true, expiresAt: true },
      });
    }

    if (!authSession) {
      return reply.status(404).send({
        statusCode: 404,
        error: 'Not Found',
        message: 'Auth session not found.',
      });
    }

    // Verify the session belongs to the requesting app
    if (authSession.appId !== app.id) {
      return reply.status(403).send({
        statusCode: 403,
        error: 'Forbidden',
        message: 'This auth session does not belong to your app.',
      });
    }

    // Reject already-expired sessions
    if (authSession.expiresAt < new Date()) {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: 'Auth session has expired.',
      });
    }

    const baseUrl = `${process.env.WEBAUTHN_ORIGIN ?? 'https://qrauth.io'}/v/${authSession.token}`;
    const frameSecret = animatedQRService.deriveFrameSecret(authSession.id);

    // TTL is the lesser of: remaining session life or 10 minutes
    const sessionTtlSeconds = Math.floor((authSession.expiresAt.getTime() - Date.now()) / 1000);
    const ttlSeconds = Math.min(sessionTtlSeconds, 600);

    // ADR-0001 A4-M2 — backend-aware signer registration.
    //   Phase 1 (dual): fire-and-forget. Local derivation authoritative.
    //   Phase 3 (signer): blocking + hard-dependency. The signer MUST
    //     acknowledge the session before we return the frame secret —
    //     there is no local verify fallback anymore, so a session the
    //     signer does not hold could never be verified. On failure we
    //     return 503 instead of issuing an unverifiable frame secret.
    //   local: no-op (handled inside the service methods).
    if (fastify.macSignerBackend === 'signer') {
      try {
        await animatedQRService.registerWithSignerBlocking(
          authSession.id,
          ttlSeconds,
        );
      } catch (err) {
        // Phase 3: no local fallback. Fail the create rather than hand
        // back a frame secret the signer can't verify against.
        fastify.log.error(
          {
            event: 'phase3_signer_register_hard_fail',
            authSessionId: authSession.id,
            err,
          },
          `Phase 3: signer register FAILED for session ${authSession.id} — returning 503`,
        );
        return reply.status(503).send({
          statusCode: 503,
          error: 'Service Unavailable',
          message: 'MAC signer unavailable — cannot create animated session.',
        });
      }
      // Observability: single line per session create so operators can
      // `journalctl -fu vqr-api | grep phase2_signer_register` and see
      // every session pass through the signer. (Event name retained from
      // Phase 2 for operator grep continuity.)
      fastify.log.info(
        {
          event: 'phase2_signer_register',
          authSessionId: authSession.id,
          ttlSeconds,
          signerOk: true,
        },
        `Phase 3: signer register ok for session ${authSession.id}`,
      );
    } else {
      void animatedQRService.registerWithSigner(authSession.id, ttlSeconds);
    }

    return reply.status(201).send({
      frameSecret,
      baseUrl,
      ttlSeconds,
    });
  });

  // -------------------------------------------------------------------------
  // POST /validate — Validate a scanned animated QR frame (public)
  // -------------------------------------------------------------------------
  fastify.post('/validate', { config: { rateLimit: rateLimitPublic } }, async (request, reply) => {
    const body = request.body as {
      baseUrl?: string;
      frameIndex?: number;
      timestamp?: number;
      hmac?: string;
    };

    if (
      !body.baseUrl ||
      body.frameIndex === undefined ||
      body.frameIndex === null ||
      body.timestamp === undefined ||
      body.timestamp === null ||
      !body.hmac
    ) {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: 'baseUrl, frameIndex, timestamp, and hmac are required.',
      });
    }

    // Extract the session token from the baseUrl path: /v/TOKEN or /v/TOKEN?...
    // baseUrl format: https://qrauth.io/v/TOKEN
    const urlObj = (() => {
      try {
        return new URL(body.baseUrl);
      } catch {
        return null;
      }
    })();

    if (!urlObj) {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: 'Invalid baseUrl.',
      });
    }

    // AUDIT-FINDING-015 / AUDIT-2 N-5: reject frames whose baseUrl
    // points at an origin we do not serve. The server has no reason to
    // validate frames for origins it does not own; this closes a narrow
    // downstream-confusion surface where a valid HMAC for a
    // session-bound frame secret could be submitted with a spoofed
    // `baseUrl`. N-5 routes this through `config.webauthn.origin` so
    // the check runs unconditionally — production boots already fail
    // closed if `WEBAUTHN_ORIGIN` is missing, so the previous
    // `if (expectedOrigin && …)` short-circuit only ever weakened dev.
    const expectedOrigin = config.webauthn.origin;
    if (urlObj.origin !== expectedOrigin) {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: 'baseUrl origin does not match this server.',
      });
    }

    // Path is /v/TOKEN — extract the last segment
    const pathParts = urlObj.pathname.split('/').filter(Boolean);
    const sessionToken = pathParts[pathParts.length - 1];

    if (!sessionToken) {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: 'Could not extract session token from baseUrl.',
      });
    }

    // Look up the auth session by token to get its stable ID
    const authSession = await fastify.prisma.authSession.findUnique({
      where: { token: sessionToken },
      select: { id: true, expiresAt: true },
    });

    if (!authSession) {
      return reply.status(404).send({
        statusCode: 404,
        error: 'Not Found',
        message: 'Auth session not found.',
      });
    }

    if (authSession.expiresAt < new Date()) {
      return reply.send({ valid: false, reason: 'Auth session has expired' });
    }

    // ADR-0001 A4-M2 — backend-aware frame verification.
    //   local: local validateFrame.
    //   dual:  local validateFrame, then fire-and-forget shadowVerify
    //          against the signer (Phase 1 observation).
    //   signer: signerVerifyFrame is the SOLE verifier (Phase 3). No local
    //          fallback — on signer unavailability the frame is rejected
    //          (valid:false, reason 'MAC verification unavailable').
    let result: { valid: boolean; reason?: string };

    if (fastify.macSignerBackend === 'signer') {
      const signerResult = await animatedQRService.signerVerifyFrame(
        body.baseUrl,
        body.frameIndex,
        body.timestamp,
        body.hmac,
        authSession.id,
      );
      // signerResult.source is internal-only — never leaks to the client.
      result = { valid: signerResult.valid, reason: signerResult.reason };
      // Observability: single line per validate so operators can tail logs
      // and see verification outcomes in real time. source is always
      // 'signer' in Phase 3 (no fallback). Low volume — one line per frame.
      fastify.log.info(
        {
          event: 'phase2_signer_validate',
          authSessionId: authSession.id,
          frameIndex: body.frameIndex,
          valid: signerResult.valid,
          source: signerResult.source,
        },
        `Phase 2: validate frame=${body.frameIndex} valid=${signerResult.valid} source=${signerResult.source}`,
      );
    } else {
      result = animatedQRService.validateFrame(
        body.baseUrl,
        body.frameIndex,
        body.timestamp,
        body.hmac,
        authSession.id,
      );

      // Dual-mode only: shadow verify against the signer so the divergence
      // comparator can keep observing. In local mode the service no-ops.
      if (fastify.macSignerBackend === 'dual') {
        animatedQRService.shadowVerify({
          sessionId: authSession.id,
          baseUrl: body.baseUrl,
          frameIndex: body.frameIndex,
          timestamp: body.timestamp,
          hmac: body.hmac,
          localValid: result.valid,
        });
      }
    }

    if (!result.valid) {
      return reply.send(result);
    }

    // Replay protection: frame index must be strictly increasing
    const isNew = await animatedQRService.checkReplay(authSession.id, body.frameIndex);
    if (!isNew) {
      return reply.send({ valid: false, reason: 'Replayed frame index' });
    }

    return reply.send({ valid: true });
  });
}
