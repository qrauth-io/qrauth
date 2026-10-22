import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { rateLimitPublic, rateLimitAuth } from '../middleware/rateLimit.js';
import { AppService } from '../services/app.js';
import { z } from 'zod';
import { AnimatedQRService } from '../services/animated-qr.js';
import {
  FRAME_STATE_TTL_SECONDS,
  VERIFIER_QUERY_KEYS,
  checkFrameVerifier,
  currentFrameGeneration,
  frameChallengeSchema,
  frameKeyId,
  frameVerifierSchema,
  SECRET_ATTEMPTS_PER_MINUTE,
  countSecretAttempt,
  hasFrameChallenge,
  matchFrameChallenge,
  nextFrameGeneration,
  registerFrameChallenge,
} from '../services/animated-qr-frame-proof.js';
import { config } from '../lib/config.js';

/**
 * Authenticate a request using app credentials.
 *
 * Supports two modes:
 *   1. Full auth: Basic auth or X-Client-Id/X-Client-Secret (for server-side use)
 *   2. Public client: X-Client-Id only (browser). Public clients prove
 *      possession of the frame verifier instead (see POST /session/secret).
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

type AuthSessionRow = { id: string; token: string; appId: string; expiresAt: Date };
type AuthenticatedApp = NonNullable<Awaited<ReturnType<typeof authenticateApp>>>;

/** A frame verifier must never travel in a URL; refuse requests that put one there. */
function verifierInQuery(request: FastifyRequest): boolean {
  const query = (request.query ?? {}) as Record<string, unknown>;
  return VERIFIER_QUERY_KEYS.some((k) => k in query);
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

  /**
   * Resolve the auth session a request refers to and check it belongs to the
   * calling app and has not expired. Sends the error response and returns null
   * on any failure.
   */
  async function resolveAuthSession(
    body: { authSessionId?: string; token?: string },
    app: AuthenticatedApp,
    reply: FastifyReply,
    opts: { uniformUnauthorized?: boolean } = {},
  ): Promise<AuthSessionRow | null> {
    if (!body.authSessionId && !body.token) {
      reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: 'Either authSessionId or token is required.',
      });
      return null;
    }

    const select = { id: true, token: true, appId: true, expiresAt: true } as const;
    const authSession: AuthSessionRow | null = body.authSessionId
      ? await fastify.prisma.authSession.findUnique({ where: { id: body.authSessionId }, select })
      : await fastify.prisma.authSession.findUnique({ where: { token: body.token! }, select });

    // Public clients get one uniform 401 for every lookup failure, so the
    // response does not reveal whether a token exists or which app owns it.
    if (opts.uniformUnauthorized && (!authSession || authSession.appId !== app.id || authSession.expiresAt < new Date())) {
      reply.status(401).send({ statusCode: 401, error: 'Unauthorized', message: 'Invalid frame proof.' });
      return null;
    }
    if (!authSession) {
      reply.status(404).send({ statusCode: 404, error: 'Not Found', message: 'Auth session not found.' });
      return null;
    }
    if (authSession.appId !== app.id) {
      reply.status(403).send({
        statusCode: 403,
        error: 'Forbidden',
        message: 'This auth session does not belong to your app.',
      });
      return null;
    }
    if (authSession.expiresAt < new Date()) {
      reply.status(400).send({ statusCode: 400, error: 'Bad Request', message: 'Auth session has expired.' });
      return null;
    }
    return authSession;
  }

  /** Lesser of the remaining auth-session life and 10 minutes. */
  function displayTtlSeconds(authSession: AuthSessionRow): number {
    const sessionTtlSeconds = Math.floor((authSession.expiresAt.getTime() - Date.now()) / 1000);
    return Math.min(sessionTtlSeconds, FRAME_STATE_TTL_SECONDS);
  }

  function displayBaseUrl(authSession: AuthSessionRow): string {
    return `${process.env.WEBAUTHN_ORIGIN ?? 'https://qrauth.io'}/v/${authSession.token}`;
  }

  /**
   * Start a new secret generation for the session, register it with the MAC
   * signer, and send `{ frameSecret, baseUrl, ttlSeconds }`. Frames signed under
   * any earlier generation stop verifying once this returns.
   */
  async function issueFrameSecret(authSession: AuthSessionRow, reply: FastifyReply, status: 200 | 201) {
    const ttlSeconds = displayTtlSeconds(authSession);
    let generation: number;
    try {
      generation = await nextFrameGeneration(authSession.id);
    } catch (err) {
      fastify.log.error({ event: 'animated_qr_generation_failed', authSessionId: authSession.id, err }, 'Could not start a frame-secret generation');
      return reply.status(503).send({
        statusCode: 503,
        error: 'Service Unavailable',
        message: 'Cannot issue a frame secret right now.',
      });
    }
    const keyId = frameKeyId(authSession.id, generation);
    const frameSecret = animatedQRService.deriveFrameSecret(keyId);

    // ADR-0001 A4-M2 — backend-aware signer registration.
    //   Phase 1 (dual): fire-and-forget. Local derivation authoritative.
    //   Phase 3 (signer): blocking + hard-dependency. The signer MUST
    //     acknowledge the generation before we return the frame secret —
    //     there is no local verify fallback, so a generation the signer does
    //     not hold could never be verified. On failure we return 503.
    //   local: no-op (handled inside the service methods).
    if (fastify.macSignerBackend === 'signer') {
      try {
        await animatedQRService.registerWithSignerBlocking(keyId, ttlSeconds);
      } catch (err) {
        fastify.log.error(
          { event: 'phase3_signer_register_hard_fail', authSessionId: authSession.id, generation, err },
          `Phase 3: signer register FAILED for session ${authSession.id} — returning 503`,
        );
        return reply.status(503).send({
          statusCode: 503,
          error: 'Service Unavailable',
          message: 'MAC signer unavailable — cannot create animated session.',
        });
      }
      // Event name retained from Phase 2 for operator grep continuity.
      fastify.log.info(
        { event: 'phase2_signer_register', authSessionId: authSession.id, generation, ttlSeconds, signerOk: true },
        `Phase 3: signer register ok for session ${authSession.id}`,
      );
    } else {
      void animatedQRService.registerWithSigner(keyId, ttlSeconds);
    }

    return reply.status(status).send({ frameSecret, baseUrl: displayBaseUrl(authSession), ttlSeconds });
  }

  // -------------------------------------------------------------------------
  // POST /session — Create an animated display session for an auth session.
  //
  //   Confidential client (client secret): the response carries the frame
  //     secret. Displays that are not driven by the browser that created the
  //     login session use this path.
  //   Public client (client ID only): the frame challenge
  //     (base64url(SHA-256(frameVerifier))) MUST have been registered when the
  //     auth session was created (POST /auth-sessions, `frameChallenge`). This
  //     route never registers one for a public client; if the body carries
  //     `frameChallenge` it must equal the registered value. The response
  //     carries no secret; POST /session/secret releases it on presenting the
  //     verifier.
  // -------------------------------------------------------------------------
  const sessionBodySchema = z.object({
    authSessionId: z.string().min(1).max(128).optional(),
    token: z.string().min(1).max(128).optional(),
    frameChallenge: frameChallengeSchema.optional(),
  });

  fastify.post('/session', { config: { rateLimit: rateLimitAuth } }, async (request, reply) => {
    if (verifierInQuery(request)) {
      return reply.status(400).send({ statusCode: 400, error: 'Bad Request', message: 'frameVerifier must be sent in the request body.' });
    }
    const app = await authenticateApp(request, reply, appService, true);
    if (!app) return; // 401 already sent

    const parsed = sessionBodySchema.safeParse(request.body ?? {});
    if (!parsed.success) {
      return reply.status(400).send({ statusCode: 400, error: 'Bad Request', message: parsed.error.issues[0]?.message ?? 'Invalid body.' });
    }
    const body = parsed.data;

    if (app.isPublicClient) {
      const authSession = await resolveAuthSession(body, app, reply, { uniformUnauthorized: true });
      if (!authSession) return;
      let match: 'same' | 'conflict' | 'none';
      try {
        match = body.frameChallenge
          ? await matchFrameChallenge(authSession.id, body.frameChallenge)
          : (await hasFrameChallenge(authSession.id)) ? 'same' : 'none';
      } catch (err) {
        fastify.log.error({ event: 'animated_qr_challenge_read_failed', authSessionId: authSession.id, err }, 'Could not read frame challenge');
        return reply.status(503).send({ statusCode: 503, error: 'Service Unavailable', message: 'Cannot create animated session right now.' });
      }
      if (match !== 'same') {
        return reply.status(401).send({
          statusCode: 401,
          error: 'Unauthorized',
          message: 'Public clients must register frameChallenge when creating the auth session.',
        });
      }
      return reply.status(201).send({ baseUrl: displayBaseUrl(authSession), ttlSeconds: displayTtlSeconds(authSession) });
    }

    // Confidential client.
    const authSession = await resolveAuthSession(body, app, reply);
    if (!authSession) return;

    if (body.frameChallenge) {
      let outcome: 'stored' | 'same' | 'conflict';
      try {
        outcome = await registerFrameChallenge(authSession.id, body.frameChallenge, displayTtlSeconds(authSession));
      } catch (err) {
        fastify.log.error({ event: 'animated_qr_challenge_store_failed', authSessionId: authSession.id, err }, 'Could not store frame challenge');
        return reply.status(503).send({ statusCode: 503, error: 'Service Unavailable', message: 'Cannot create animated session right now.' });
      }
      if (outcome === 'conflict') {
        return reply.status(409).send({
          statusCode: 409,
          error: 'Conflict',
          message: 'A different frameChallenge is already registered for this auth session.',
        });
      }
    }

    return issueFrameSecret(authSession, reply, 201);
  });

  // -------------------------------------------------------------------------
  // POST /session/secret — Release (and rotate) the frame secret.
  //
  //   Public client: `frameVerifier` in the body MUST match the challenge
  //     registered when the auth session was created. At most
  //     SECRET_ATTEMPTS_PER_MINUTE attempts per auth session per minute. Calling again (for example after a page
  //     reload) issues a new secret and retires the previous one.
  //   Confidential client: the client secret authenticates; a verifier, if
  //     sent, must still match.
  // -------------------------------------------------------------------------
  const secretBodySchema = z.object({
    authSessionId: z.string().min(1).max(128).optional(),
    token: z.string().min(1).max(128).optional(),
    frameVerifier: frameVerifierSchema.optional(),
  });

  fastify.post('/session/secret', { config: { rateLimit: rateLimitAuth } }, async (request, reply) => {
    if (verifierInQuery(request)) {
      return reply.status(400).send({ statusCode: 400, error: 'Bad Request', message: 'frameVerifier must be sent in the request body.' });
    }
    const app = await authenticateApp(request, reply, appService, true);
    if (!app) return;

    const parsed = secretBodySchema.safeParse(request.body ?? {});
    if (!parsed.success) {
      return reply.status(400).send({ statusCode: 400, error: 'Bad Request', message: parsed.error.issues[0]?.message ?? 'Invalid body.' });
    }
    const body = parsed.data;

    if (app.isPublicClient && !body.frameVerifier) {
      return reply.status(401).send({ statusCode: 401, error: 'Unauthorized', message: 'frameVerifier required.' });
    }

    const authSession = await resolveAuthSession(body, app, reply, { uniformUnauthorized: app.isPublicClient });
    if (!authSession) return;

    if (app.isPublicClient) {
      let attempts: number;
      try {
        attempts = await countSecretAttempt(authSession.id);
      } catch (err) {
        fastify.log.error({ event: 'animated_qr_attempt_count_failed', authSessionId: authSession.id, err }, 'Could not count secret attempts');
        return reply.status(503).send({ statusCode: 503, error: 'Service Unavailable', message: 'Cannot issue a frame secret right now.' });
      }
      if (attempts > SECRET_ATTEMPTS_PER_MINUTE) {
        return reply.status(429).send({ statusCode: 429, error: 'Too Many Requests', message: 'Too many attempts for this session.' });
      }
    }

    if (body.frameVerifier) {
      let check: 'ok' | 'mismatch' | 'no_challenge';
      try {
        check = await checkFrameVerifier(authSession.id, body.frameVerifier);
      } catch (err) {
        fastify.log.error({ event: 'animated_qr_challenge_read_failed', authSessionId: authSession.id, err }, 'Could not read frame challenge');
        return reply.status(503).send({ statusCode: 503, error: 'Service Unavailable', message: 'Cannot issue a frame secret right now.' });
      }
      if (check !== 'ok') {
        return reply.status(401).send({ statusCode: 401, error: 'Unauthorized', message: 'Invalid frame proof.' });
      }
    }

    return issueFrameSecret(authSession, reply, 200);
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

    // Only the current secret generation verifies. Frames signed with an
    // earlier generation's secret fail the HMAC check. Fail closed when the
    // generation cannot be read.
    let keyId: string;
    try {
      keyId = frameKeyId(authSession.id, await currentFrameGeneration(authSession.id));
    } catch (err) {
      fastify.log.error({ event: 'animated_qr_generation_read_failed', authSessionId: authSession.id, err }, 'Could not read frame-secret generation');
      return reply.send({ valid: false, reason: 'MAC verification unavailable' });
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
        keyId,
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
        keyId,
      );

      // Dual-mode only: shadow verify against the signer so the divergence
      // comparator can keep observing. In local mode the service no-ops.
      if (fastify.macSignerBackend === 'dual') {
        animatedQRService.shadowVerify({
          sessionId: keyId,
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

    // Replay protection: frame index must be strictly increasing within a
    // secret generation (a new generation starts again from frame 0).
    const isNew = await animatedQRService.checkReplay(keyId, body.frameIndex);
    if (!isNew) {
      return reply.send({ valid: false, reason: 'Replayed frame index' });
    }

    return reply.send({ valid: true });
  });
}
