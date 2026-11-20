import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { OidcClient } from '@prisma/client';
import { config } from '../lib/config.js';
import { hashString } from '../lib/crypto.js';
import { constantTimeEqualString } from '../lib/constant-time.js';
import {
  OP_SESSION_COOKIE_NAME,
  clearOpSessionCookieOptions,
  readOpSessionCookie,
  readOpSessionWithMeta,
  revokeOpSession,
} from '../lib/oidc-session.js';
import { computeSubForClient } from '../lib/oidc-sub.js';
import { verifyIdTokenHint } from '../lib/oidc-id-token-hint.js';
import { authenticateOidcClientThrottled, CLIENT_AUTH_FAILURE_WINDOW_SECONDS } from '../lib/oidc-client-auth-throttle.js';
import { rateLimitOidcLogout, rateLimitOidcRevoke } from '../middleware/rateLimit.js';
import { invalidateFamily } from '../lib/oidc-refresh-token.js';
import { renderLogoutConfirmPage, renderSignedOutPage } from '../renderers/oidc/logout.js';
import { returnToClient, sendOpHtml } from './oidc-html.js';

/**
 * Ending OP sessions and tokens (audit 2026-10 FINDING-011).
 *
 *   GET/POST /logout — RP-Initiated Logout 1.0 `end_session_endpoint`.
 *   POST /revoke     — RFC 7009 token revocation.
 */

type LogoutParams = Record<string, string | undefined>;

/** The registered post-logout URI to return to, with `state`, or null. */
function postLogoutTarget(client: OidcClient | null, params: LogoutParams): URL | null {
  const requested = params.post_logout_redirect_uri;
  if (!client || !requested || !client.postLogoutRedirectUris.includes(requested)) return null;
  const target = new URL(requested);
  if (params.state) target.searchParams.set('state', params.state);
  return target;
}

export function registerSessionEndRoutes(fastify: FastifyInstance): void {
  const prisma = fastify.prisma;

  const clearSessionCookies = (reply: FastifyReply): void => {
    reply.clearCookie(OP_SESSION_COOKIE_NAME, clearOpSessionCookieOptions());
  };

  /** True when the hint was issued to this client for the signed-in user. */
  const hintNamesUser = (hintSub: string, client: OidcClient, userId: string): boolean => {
    try {
      const sub = computeSubForClient({ userId, client, pairwiseSecret: config.oidc.pairwiseSecret });
      return constantTimeEqualString(hintSub, sub);
    } catch {
      // Pairwise secret missing: the hint cannot be checked, so it proves nothing.
      return false;
    }
  };

  const handleLogout = async (
    request: FastifyRequest,
    reply: FastifyReply,
    params: LogoutParams,
  ): Promise<unknown> => {
    reply.header('Cache-Control', 'no-store');

    const hint = params.id_token_hint
      ? await verifyIdTokenHint(prisma, params.id_token_hint, config.oidc.issuer)
      : null;
    // The hint names its client; `client_id` is the fallback when there is no
    // usable hint. If both are present they must agree, or neither is trusted.
    const clientIdsAgree = !hint || !params.client_id || hint.aud === params.client_id;
    const clientId = clientIdsAgree ? (hint?.aud ?? params.client_id) : undefined;
    const client = clientId ? await prisma.oidcClient.findUnique({ where: { clientId } }) : null;
    const target = postLogoutTarget(client, params);

    const isFormPost = request.method === 'POST';
    const finish = (): unknown => {
      if (!target) return sendOpHtml(request, reply, 200, renderSignedOutPage);
      // After a form POST a redirect would be subject to `form-action`.
      if (isFormPost) return returnToClient(request, reply, target.toString(), {});
      return reply.redirect(target.toString(), 302);
    };

    const opCookie = readOpSessionCookie(request.cookies);
    const session = await readOpSessionWithMeta(prisma, opCookie);
    if (!opCookie || !session) {
      // Nothing to end. Still clear whatever stale cookie the browser holds.
      clearSessionCookies(reply);
      return finish();
    }

    // End the session without asking only when the request shows it comes
    // from a relying party this user signed in to, or the user just confirmed
    // on our own page. The confirmation POST needs no token: the session
    // cookie is SameSite=Lax, so a cross-site POST arrives without it and
    // never reaches this point.
    const provenByHint = !!hint && !!client && clientIdsAgree && hintNamesUser(hint.sub, client, session.userId);
    const confirmed = isFormPost && params.confirm === 'yes';
    if (!provenByHint && !confirmed) {
      return sendOpHtml(request, reply, 200, (nonce) =>
        renderLogoutConfirmPage({
          nonce,
          clientId: client?.clientId,
          postLogoutRedirectUri: target ? params.post_logout_redirect_uri : undefined,
          state: target ? params.state : undefined,
        }),
      );
    }

    await revokeOpSession(prisma, opCookie);
    clearSessionCookies(reply);
    request.log.info(
      { event: 'oidc.logout', userId: session.userId, clientId: client?.clientId, via: provenByHint ? 'id_token_hint' : 'confirmed' },
      'OP session ended',
    );
    return finish();
  };

  fastify.get('/logout', { config: { rateLimit: rateLimitOidcLogout } }, (request, reply) =>
    handleLogout(request, reply, request.query as LogoutParams),
  );

  // RP-Initiated Logout §2: POST must be supported too. A relying party's
  // cross-site POST arrives without the SameSite=Lax session cookie, so it is
  // turned into the equivalent GET (a top-level navigation, which does carry
  // the cookie). Only our own confirmation form is handled as a POST.
  fastify.post('/logout', { config: { rateLimit: rateLimitOidcLogout } }, (request, reply) => {
    const body = (request.body ?? {}) as Record<string, unknown>;
    const params: LogoutParams = {};
    for (const key of ['id_token_hint', 'client_id', 'post_logout_redirect_uri', 'state', 'confirm']) {
      if (typeof body[key] === 'string') params[key] = body[key] as string;
    }
    if (params.confirm === 'yes') return handleLogout(request, reply, params);

    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && key !== 'confirm') query.set(key, value);
    }
    reply.header('Cache-Control', 'no-store');
    return reply.redirect(`/logout?${query.toString()}`, 303);
  });

  // ---------------------------------------------------------------------------
  // POST /revoke — RFC 7009. Client-authenticated exactly like /token. A token
  // that is unknown, already dead or issued to another client is answered
  // with the same 200 as a successful revocation (§2.2), so the endpoint
  // cannot be used to probe tokens.
  // ---------------------------------------------------------------------------
  fastify.post('/revoke', { config: { rateLimit: rateLimitOidcRevoke } }, async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    reply.header('Pragma', 'no-cache');
    const body = (request.body ?? {}) as Record<string, string | undefined>;

    const auth = await authenticateOidcClientThrottled(prisma, request.headers.authorization, body, request.ip);
    if (!auth.ok) {
      if (auth.throttled) reply.header('Retry-After', String(CLIENT_AUTH_FAILURE_WINDOW_SECONDS));
      return reply
        .status(auth.throttled ? 429 : 401)
        .type('application/json')
        .send({ error: 'invalid_client', error_description: auth.description });
    }
    const client = auth.client;

    const token = typeof body.token === 'string' ? body.token : '';
    if (!token) {
      return reply.status(400).type('application/json').send({ error: 'invalid_request', error_description: 'token is required' });
    }
    const tokenHash = hashString(token);
    const now = new Date();

    // `token_type_hint` only orders the lookup; both stores are checked.
    const refresh = await prisma.oidcRefreshToken.findUnique({ where: { tokenHash } });
    if (refresh) {
      if (refresh.oidcClientId === client.id) {
        // Revoking a refresh token ends the whole grant: its family, and the
        // access tokens this client holds for the user.
        const revokedCount = await invalidateFamily({ prisma, familyId: refresh.familyId });
        const access = await prisma.oidcAccessToken.updateMany({
          where: { userId: refresh.userId, oidcClientId: client.id, revokedAt: null },
          data: { revokedAt: now },
        });
        request.log.info(
          { event: 'oidc.revoke', kind: 'refresh_token', clientId: client.clientId, userId: refresh.userId, revokedCount, accessTokens: access.count },
          'refresh token family revoked by client',
        );
      }
      return reply.status(200).send();
    }

    const access = await prisma.oidcAccessToken.findUnique({ where: { tokenHash } });
    if (access && access.oidcClientId === client.id && access.revokedAt === null) {
      await prisma.oidcAccessToken.update({ where: { tokenHash }, data: { revokedAt: now } });
      request.log.info(
        { event: 'oidc.revoke', kind: 'access_token', clientId: client.clientId, userId: access.userId },
        'access token revoked by client',
      );
    }
    return reply.status(200).send();
  });
}
