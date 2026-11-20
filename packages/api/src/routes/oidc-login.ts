import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { PrismaClient } from '@prisma/client';
import { randomBytes } from 'node:crypto';
import QRCode from 'qrcode';
import { config } from '../lib/config.js';
import { hashString } from '../lib/crypto.js';
import { constantTimeEqualString } from '../lib/constant-time.js';
import { cacheGet, cacheSet, cacheTake } from '../lib/cache.js';
import { AuthSessionService } from '../services/auth-session.js';
import { getOpAppId } from '../lib/oidc-op-app.js';
import {
  OP_PRE_LOGIN_COOKIE_NAME,
  OP_PRE_LOGIN_TTL_SECONDS,
  OP_SESSION_COOKIE_NAME,
  clearOpSessionCookieOptions,
  createOpSession,
  preLoginCookieOptions,
} from '../lib/oidc-session.js';
import { describeRequester } from '../lib/oidc-requester.js';
import { recordLoginGrant } from '../lib/oidc-login-grant.js';
import { renderOpLoginPage, renderOpResumePage, type OpResumeState } from '../renderers/oidc/login.js';
import { loginStatusNetworkGuard, rateLimitOidcLogin, rateLimitOidcLoginStatus } from '../middleware/rateLimit.js';

/**
 * OP-hosted login (ADR-0003 Slice 3b.2): the QR page and the status poll
 * that turns an approved scan into an OP session.
 *
 * Audit 2026-10 FINDING-003: the attempt is bound to the browser that opened
 * /login. GET /login sets a random pre-login cookie and stores its SHA-256
 * with the attempt; /login/status issues the session only to a request that
 * carries the matching cookie. Knowing the attempt id is no longer enough, in
 * either direction: an id planted in someone else's browser does nothing
 * there, and an id lifted from someone's page cannot be redeemed elsewhere.
 */

export const OP_LOGIN_HTML_CSP =
  "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'self' 'unsafe-inline'; base-uri 'none'; form-action 'self'";

/** /login/resume renders no script: a meta refresh covers the one waiting state. */
export const OP_RESUME_HTML_CSP =
  "default-src 'self'; style-src 'self' 'unsafe-inline'; base-uri 'none'; form-action 'self'";

/** Attempt ids are 16 random bytes, base64url (22 chars). */
const LOGIN_ATTEMPT_ID_RE = /^[A-Za-z0-9_-]{22}$/;

interface LoginAttempt {
  authSessionId: string;
  returnTo: string;
  /** SHA-256 of the pre-login cookie given to the browser that opened /login. */
  preLoginHash: string;
}

/**
 * Validate a `returnTo` against open-redirect abuse: only a relative path
 * starting with `/authorize` is accepted (same-origin by construction; the
 * `/authorize` literal prefix can't be `//host`). Anything else falls back to
 * the issuer root.
 */
function safeReturnTo(raw: unknown): string {
  if (typeof raw === 'string' && raw.startsWith('/authorize')) return raw;
  return '/';
}

/** What the login page says about where the person is signing in. */
interface LoginDestination {
  clientName: string;
  /** Host of the redirect URI the browser is sent back to after the scan. */
  redirectHost: string;
}

/**
 * The application the `returnTo` request is for, shown on the login page.
 * Null unless the request names exactly one client and one of that client's
 * registered redirect URIs, which is what /authorize itself requires before
 * it sends anyone here; any other link gets the neutral heading. The host
 * comes from that validated redirect URI, never from anything unregistered.
 */
async function loginDestinationOf(prisma: PrismaClient, returnTo: string): Promise<LoginDestination | null> {
  const queryStart = returnTo.indexOf('?');
  if (queryStart === -1) return null;
  const query = new URLSearchParams(returnTo.slice(queryStart + 1));
  const clientIds = query.getAll('client_id');
  const redirectUris = query.getAll('redirect_uri');
  if (clientIds.length !== 1 || redirectUris.length !== 1) return null;
  const client = await prisma.oidcClient.findUnique({
    where: { clientId: clientIds[0] },
    select: { name: true, redirectUris: true },
  });
  if (!client || !client.redirectUris.includes(redirectUris[0])) return null;
  try {
    return { clientName: client.name, redirectHost: new URL(redirectUris[0]).host };
  } catch {
    return null;
  }
}

/**
 * Origin the OP pages are served from: the issuer in production; the local
 * API in development, where /login is served from localhost.
 */
function opOrigin(): string {
  return config.server.isDev ? `http://localhost:${config.server.port}` : config.oidc.issuer;
}

/** True only for the browser that opened /login (FINDING-003 pre-login cookie). */
function isSameBrowser(request: FastifyRequest, attempt: LoginAttempt): boolean {
  const preLoginToken = request.cookies[OP_PRE_LOGIN_COOKIE_NAME];
  return (
    typeof attempt.preLoginHash === 'string' &&
    !!preLoginToken &&
    constantTimeEqualString(hashString(preLoginToken), attempt.preLoginHash)
  );
}

/**
 * Turn an approved attempt into an OP session on this browser. One-shot: the
 * attempt is taken atomically (GET+DEL) before anything is minted, so a poll
 * and a resume racing each other, or a leaked URL, cannot mint twice.
 * Returns where the browser continues (the /authorize request that started
 * it), or null when another request already completed this attempt.
 */
async function completeLogin(
  prisma: PrismaClient,
  reply: FastifyReply,
  attemptId: string,
  attempt: LoginAttempt,
  userId: string,
): Promise<string | null> {
  const taken = await cacheTake<LoginAttempt>(`oidc_login:${attemptId}`);
  if (!taken) return null;
  const { token, cookieOptions } = await createOpSession(prisma, userId);
  // /authorize lets this session answer the request that started the
  // scan, once (lib/oidc-login-grant.ts); every later request scans again.
  await recordLoginGrant(token, attempt.returnTo);
  reply.setCookie(OP_SESSION_COOKIE_NAME, token, cookieOptions);
  reply.clearCookie(OP_PRE_LOGIN_COOKIE_NAME, clearOpSessionCookieOptions());
  return attempt.returnTo;
}

export function registerLoginRoutes(fastify: FastifyInstance): void {
  const prisma = fastify.prisma;

  // GET /login — OP-hosted authentication surface.
  fastify.get('/login', { config: { rateLimit: rateLimitOidcLogin } }, async (request, reply) => {
    const returnTo = safeReturnTo((request.query as { returnTo?: string }).returnTo);

    let opAppId: string;
    try {
      opAppId = await getOpAppId(prisma);
    } catch (err) {
      request.log.error({ err }, 'OP app not provisioned');
      reply.header('Content-Security-Policy', OP_LOGIN_HTML_CSP);
      return reply.status(503).type('text/html').send(
        '<!DOCTYPE html><meta charset="utf-8"><p>Sign-in is temporarily unavailable.</p>',
      );
    }

    const preLoginToken = randomBytes(32).toString('base64url');
    const loginAttemptId = randomBytes(16).toString('base64url');

    // What the approver is shown about this browser (lib/oidc-requester.ts).
    // redirectUrl is where the approval page sends a same-device approver
    // (the "Approve on this device" button, ?dr=1): /login/resume finishes the
    // sign-in in whichever tab of this browser lands there. It is set here,
    // never by a caller, so it is always this issuer.
    const sessionService = new AuthSessionService(prisma, fastify.signingService);
    const session = await sessionService.createSession(opAppId, {
      scopes: ['identity'],
      metadata: { requester: describeRequester(request.headers) },
      redirectUrl: `${opOrigin()}/login/resume?id=${loginAttemptId}`,
    });

    const destination = await loginDestinationOf(prisma, returnTo);
    const attempt: LoginAttempt = {
      authSessionId: session.id,
      returnTo,
      preLoginHash: hashString(preLoginToken),
    };
    await cacheSet(`oidc_login:${loginAttemptId}`, attempt, OP_PRE_LOGIN_TTL_SECONDS);

    const baseUrl = process.env.WEBAUTHN_ORIGIN ?? `http://localhost:${config.server.port}`;
    const scanUrl = `${baseUrl}/a/${session.token}`;
    const qrImageDataUrl = await QRCode.toDataURL(scanUrl, { width: 280, margin: 2 });

    reply.setCookie(OP_PRE_LOGIN_COOKIE_NAME, preLoginToken, preLoginCookieOptions());
    // server.ts rewrites every CSP header unless the route sets cspOverride;
    // without it the page's inline style and poller are blocked off nginx.
    (request as unknown as { cspOverride?: string }).cspOverride = OP_LOGIN_HTML_CSP;
    reply.header('Content-Security-Policy', OP_LOGIN_HTML_CSP);
    reply.header('Cache-Control', 'no-store');
    return reply
      .type('text/html')
      .send(renderOpLoginPage({ qrImageDataUrl, loginAttemptId, scanUrl, destination }));
  });

  // GET /login/status — polled by the /login page; sets the OP session cookie
  // on approval. JSON only.
  fastify.get('/login/status', {
    onRequest: loginStatusNetworkGuard(fastify),
    config: { rateLimit: rateLimitOidcLoginStatus },
  }, async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    const id = (request.query as { id?: string }).id;
    if (!id) return reply.status(400).send({ status: 'error', error: 'missing id' });

    const attempt = await cacheGet<LoginAttempt>(`oidc_login:${id}`);
    if (!attempt) return reply.status(404).send({ status: 'expired' });

    const sessionService = new AuthSessionService(prisma, fastify.signingService);
    const session = await sessionService.getSession(attempt.authSessionId);
    if (!session) return reply.send({ status: 'expired' });

    switch (session.status) {
      case 'PENDING':
        return reply.send({ status: 'pending' });
      case 'SCANNED':
        return reply.send({ status: 'scanned' });
      case 'APPROVED': {
        if (!session.userId) return reply.send({ status: 'pending' });

        // Only the browser that opened /login may collect the session. Any
        // other caller is told "pending": the attempt stays intact for the
        // right browser and nothing reveals that the scan was approved.
        if (!isSameBrowser(request, attempt)) {
          request.log.warn(
            {
              event: 'oidc.login.prelogin_mismatch',
              hasCookie: !!request.cookies[OP_PRE_LOGIN_COOKIE_NAME],
              userId: session.userId,
            },
            'approved OP login polled without the matching pre-login cookie',
          );
          return reply.send({ status: 'pending' });
        }

        const redirectUrl = await completeLogin(prisma, reply, id, attempt, session.userId);
        if (!redirectUrl) return reply.status(404).send({ status: 'expired' });
        return reply.send({ status: 'approved', redirectUrl });
      }
      case 'DENIED':
        return reply.send({ status: 'denied' });
      default:
        return reply.send({ status: 'expired' });
    }
  });

  // GET /login/resume — where the approval page sends a same-device approver.
  // In the browser that opened /login (any tab: the pre-login cookie is per
  // browser) an approved attempt becomes an OP session and the browser goes
  // straight on to /authorize. Anywhere else nothing is issued and the page
  // says to return to the original window, whose poller still finishes.
  fastify.get('/login/resume', {
    onRequest: loginStatusNetworkGuard(fastify),
    config: { rateLimit: rateLimitOidcLoginStatus },
  }, async (request, reply) => {
    const render = (state: OpResumeState, status = 200) => {
      (request as unknown as { cspOverride?: string }).cspOverride = OP_RESUME_HTML_CSP;
      reply.header('Cache-Control', 'no-store');
      return reply.status(status).type('text/html').send(renderOpResumePage(state));
    };

    const id = (request.query as { id?: string }).id;
    if (typeof id !== 'string' || !LOGIN_ATTEMPT_ID_RE.test(id)) return render('expired', 400);

    const attempt = await cacheGet<LoginAttempt>(`oidc_login:${id}`);
    if (!attempt) return render('expired');

    if (!isSameBrowser(request, attempt)) {
      request.log.warn(
        { event: 'oidc.login.resume_other_browser', hasCookie: !!request.cookies[OP_PRE_LOGIN_COOKIE_NAME] },
        'OP login resume opened without the matching pre-login cookie',
      );
      return render('other_browser');
    }

    const sessionService = new AuthSessionService(prisma, fastify.signingService);
    const session = await sessionService.getSession(attempt.authSessionId);
    if (!session) return render('expired');

    switch (session.status) {
      case 'APPROVED': {
        if (!session.userId) return render('waiting');
        const redirectUrl = await completeLogin(prisma, reply, id, attempt, session.userId);
        if (!redirectUrl) return render('expired');
        reply.header('Cache-Control', 'no-store');
        return reply.redirect(redirectUrl, 303);
      }
      case 'PENDING':
      case 'SCANNED':
        return render('waiting');
      case 'DENIED':
        return render('denied');
      default:
        return render('expired');
    }
  });
}
