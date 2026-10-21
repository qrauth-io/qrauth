import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { createHash, randomBytes } from 'node:crypto';
import { config } from '../lib/config.js';
import { hashString } from '../lib/crypto.js';
import { constantTimeEqualString } from '../lib/constant-time.js';
import { readOpSessionCookie, readOpSessionWithMeta } from '../lib/oidc-session.js';
import { OP_LOGIN_HTML_CSP, registerLoginRoutes } from './oidc-login.js';
import { OidcPairwiseSecretMissingError } from '../lib/oidc-pairwise.js';
import { computeSubForClient, OidcSectorHostMissingError } from '../lib/oidc-sub.js';
import { deriveAuthMethod } from '../lib/oidc-auth-method.js';
import { parsePrompt, isInvalidPromptCombo } from '../lib/oidc-prompt.js';
import { checkAuthorizeClientParams, checkAuthorizeParams, checkTokenParams } from '../lib/oidc-request-params.js';
import { rateLimitOidcAuthorize, rateLimitOidcToken, rateLimitOidcUserinfo } from '../middleware/rateLimit.js';
import { takeLoginGrant } from '../lib/oidc-login-grant.js';
import { clientSkipsConsent, hasCoveringConsent } from '../lib/oidc-consent.js';
import { issueAuthorizationCode } from '../lib/oidc-auth-code.js';
import { registerConsentRoutes, sendConsentPage } from './oidc-consent-flow.js';
import {
  mintRefreshToken,
  claimRefreshToken,
  invalidateFamily,
} from '../lib/oidc-refresh-token.js';
import { buildIdToken } from '../lib/oidc-id-token.js';
import { authenticateOidcClientThrottled, CLIENT_AUTH_FAILURE_WINDOW_SECONDS } from '../lib/oidc-client-auth-throttle.js';
import { resolveRefreshGrant } from '../lib/oidc-refresh-policy.js';
import { registerSessionEndRoutes } from './oidc-session-end.js';
import { platformSigningKeyWhere } from '../lib/oidc-signing-keys.js';
import { renderLandingPage } from '../renderers/oidc/landing.js';
import { renderAuthorizeErrorPage } from '../renderers/oidc/authorize-error.js';
import { profileNameClaim } from '../lib/oidc-profile-name.js';

/**
 * OIDC Provider auth-code flow + OP-hosted login (ADR-0003 Slice 3b.2).
 *
 * Registered at the ROOT prefix (the discovery/JWKS routes live under
 * /.well-known in routes/oidc.ts). All routes are public — client auth at
 * /token is in the request, and /authorize/login resolve the user from the
 * OP session cookie / the auth-sessions scan-approval, not bearer auth.
 *
 * Additive only: the auth-sessions mechanism is consumed read-only via
 * AuthSessionService (createSession + getSession). No auth-sessions code is
 * modified. ID tokens are signed exclusively via SigningService.signJws.
 */

const ACCESS_TOKEN_TTL_SECONDS = 3600; // 1 hour

const HTML_CSP = OP_LOGIN_HTML_CSP;

function base64urlSha256(input: string): string {
  return createHash('sha256').update(input, 'ascii').digest('base64url');
}

/**
 * RFC 6749 §5.2: `error_description` is `*NQCHAR` —
 * `%x20-21 / %x23-5B / %x5D-7E` (printable ASCII excluding `"` 0x22 and `\`
 * 0x5C; no control or non-ASCII chars). Strip anything outside that set so a
 * client-controlled value interpolated into a description (e.g. a submitted
 * scope) can never produce a non-conformant error response. Applied at both
 * emission helpers (redirectError + /token's tokenError) so every OAuth error
 * description is conformant by construction. ADR-0003 Slice 8.2.
 */
function nqchar(description: string): string {
  return description.replace(/[^\x20\x21\x23-\x5B\x5D-\x7E]/g, '');
}

/**
 * OAuth error redirect (RFC 6749 §4.1.2.1): only used AFTER redirect_uri is
 * validated. Echoes `state` when present. `error_description` is NQCHAR-sanitized.
 */
function redirectError(
  reply: FastifyReply,
  redirectUri: string,
  error: string,
  description: string,
  state: string | undefined,
): void {
  const u = new URL(redirectUri);
  u.searchParams.set('error', error);
  u.searchParams.set('error_description', nqchar(description));
  if (state) u.searchParams.set('state', state);
  reply.redirect(u.toString(), 302);
}

export default async function oidcFlowRoutes(fastify: FastifyInstance): Promise<void> {
  const prisma = fastify.prisma;

  // ---------------------------------------------------------------------------
  // GET / — id.qrauth.io landing page (replaces the bare 404). HTML only.
  // ---------------------------------------------------------------------------
  fastify.get('/', async (_request, reply) => {
    reply.header('Content-Security-Policy', HTML_CSP);
    reply.header('Cache-Control', 'public, max-age=300');
    return reply.type('text/html').send(renderLandingPage());
  });

  // GET /login + GET /login/status — OP-hosted login (routes/oidc-login.ts).
  registerLoginRoutes(fastify);

  // ---------------------------------------------------------------------------
  // GET/POST /authorize — OIDC authorization endpoint (auth-code flow).
  // Core §3.1.2.1 requires BOTH GET and POST; both dispatch to handleAuthorize.
  // ---------------------------------------------------------------------------
  const handleAuthorize = async (
    request: FastifyRequest,
    reply: FastifyReply,
    params: Record<string, string | undefined>,
  ): Promise<unknown> => {
    const {
      response_type,
      client_id,
      redirect_uri,
      scope,
      state,
      code_challenge,
      code_challenge_method,
      nonce,
      prompt,
      max_age,
    } = params;

    // --- Pre-redirect_uri validation: render directly, never redirect to an
    // unverified URI (RFC 6749 §4.1.2.1). Content negotiation — JSON for API
    // clients (Accept: application/json), the polished HTML error page for
    // browsers (Slice 3b.3).
    const accept = request.headers.accept ?? '';
    const wantsHtml = accept.includes('text/html');
    const bad = (msg: string) => {
      if (wantsHtml) {
        reply.header('Content-Security-Policy', HTML_CSP);
        return reply
          .status(400)
          .type('text/html')
          .send(renderAuthorizeErrorPage({ error: 'invalid_request', description: msg }));
      }
      return reply.status(400).type('application/json').send({ error: 'invalid_request', error_description: msg });
    };

    // Audit 2026-10 FINDING-021: single, bounded strings only. client_id and
    // redirect_uri first, because nothing may be redirected until they are
    // known to be a registered pair.
    const malformedClient = checkAuthorizeClientParams(params);
    if (malformedClient) return bad(malformedClient);

    if (!client_id) return bad('client_id is required');
    const client = await prisma.oidcClient.findUnique({
      where: { clientId: client_id },
      include: { organization: { select: { name: true } } },
    });
    if (!client) return bad('unknown client_id');

    if (!redirect_uri || !client.redirectUris.includes(redirect_uri)) {
      return bad('redirect_uri does not match a registered redirect URI');
    }

    // --- Post-redirect_uri validation: errors redirect back to the RP.
    // Request objects (OIDCC §6.1/§6.2): this OP supports neither `request` (by
    // value) nor `request_uri` (by reference) — discovery advertises neither
    // request_parameter_supported nor request_uri_parameter_supported (both
    // default false). Per spec, reject the parameter explicitly with its
    // dedicated error rather than silently ignoring it and then failing a
    // downstream check (which would process a request the client believes the
    // object had protected). Checked before response_type/state so the correct
    // error wins even when those params live inside the (unread) object.
    const malformed = checkAuthorizeParams(params);
    if (malformed) {
      // `state` is echoed only when it is itself a usable string.
      return redirectError(reply, redirect_uri, 'invalid_request', malformed, typeof state === 'string' && state.length <= 4096 ? state : undefined);
    }
    if (params.request !== undefined) {
      return redirectError(reply, redirect_uri, 'request_not_supported', 'request objects (request parameter) are not supported', state);
    }
    if (params.request_uri !== undefined) {
      return redirectError(reply, redirect_uri, 'request_uri_not_supported', 'request_uri is not supported', state);
    }
    if (response_type !== 'code') {
      return redirectError(reply, redirect_uri, 'unsupported_response_type', 'response_type must be code', state);
    }
    if (!state) {
      return redirectError(reply, redirect_uri, 'invalid_request', 'state is required', undefined);
    }
    // PKCE (ADR-0003 Slice 8.3): mandatory S256 for PUBLIC clients (no secret →
    // PKCE is the only code-interception defense), OPTIONAL for CONFIDENTIAL
    // clients (client_secret already authenticates the token exchange; OIDC
    // Core / Basic OP exercise confidential clients without PKCE). When a
    // challenge IS supplied, only S256 is accepted (plain rejected for all).
    const isPublicClient = !client.clientSecretHash;
    if (code_challenge) {
      if (code_challenge_method !== 'S256') {
        return redirectError(reply, redirect_uri, 'invalid_request', 'code_challenge_method must be S256', state);
      }
    } else if (isPublicClient) {
      return redirectError(reply, redirect_uri, 'invalid_request', 'PKCE (code_challenge with code_challenge_method=S256) is required for public clients', state);
    }
    const requestedScopes = (scope ?? '').split(/\s+/).filter(Boolean);
    if (!requestedScopes.includes('openid')) {
      return redirectError(reply, redirect_uri, 'invalid_scope', 'scope must include openid', state);
    }
    const unknown = requestedScopes.filter((s) => !client.allowedScopes.includes(s));
    if (unknown.length > 0) {
      return redirectError(reply, redirect_uri, 'invalid_scope', `scope not allowed for this client: ${unknown.join(' ')}`, state);
    }

    // --- prompt handling (Slice 8, OIDC Core §3.1.2.1). `none` MUST NOT be
    // combined with other prompt values.
    const promptDirectives = parsePrompt(prompt);
    if (isInvalidPromptCombo(promptDirectives)) {
      return redirectError(reply, redirect_uri, 'invalid_request', 'prompt=none cannot be combined with other prompt values', state);
    }

    // --- OP session check. Pressing "Sign in with QRAuth" always starts a QR
    // scan: an existing session is reused only when the relying party asks
    // for that explicitly, with prompt=none or with a max_age the session
    // satisfies. The one other use is the return from /login right after the
    // scan that created the session (lib/oidc-login-grant.ts), which works
    // once and only for the request that started the scan.
    //
    // prompt=login (§3.1.2.1) always re-authenticates. The cookie is NOT
    // revoked — prompt=login is per-request.
    const opCookie = readOpSessionCookie(request.cookies);
    let op = promptDirectives.login ? null : await readOpSessionWithMeta(prisma, opCookie);

    // max_age (Slice 8.1, OIDC Core §3.1.2.1 / §15.1): the session counts only
    // while its authentication is at most max_age seconds old; older than
    // that, the request falls into the /login branch and gets a fresh
    // auth_time. max_age=0 always re-authenticates. Non-integer values are
    // ignored, which here means they do not unlock the session either.
    let isWithinMaxAge = false;
    if (op && max_age !== undefined && /^\d+$/.test(max_age)) {
      const maxAgeSeconds = parseInt(max_age, 10);
      const sessionAgeSeconds = (Date.now() - op.authTime.getTime()) / 1000;
      if (sessionAgeSeconds > maxAgeSeconds) {
        op = null;
      } else {
        isWithinMaxAge = true;
      }
    }

    if (op && !promptDirectives.none && !isWithinMaxAge) {
      // `op` is only non-null when the cookie resolved to a live session.
      // If the record cannot be read (Redis unavailable), ask for a scan.
      const isReturnFromLogin = await takeLoginGrant(opCookie as string, params).catch((err: unknown) => {
        request.log.warn({ err, event: 'oidc.login_grant.unreadable' }, 'could not read the login grant; asking for a new sign-in');
        return false;
      });
      if (!isReturnFromLogin) op = null;
    }

    if (!op) {
      // prompt=none MUST NOT interact (§3.1.2.6): no usable session → return
      // login_required to the RP rather than redirecting to /login. (The
      // none+login combo is already rejected above, so `none` here implies
      // login was not also requested.)
      if (promptDirectives.none) {
        return redirectError(reply, redirect_uri, 'login_required', 'no active session and prompt=none was requested; interactive login is required', state);
      }
      // Redirect to OP-hosted login, preserving the request. Rebuild returnTo
      // from the validated params (method-agnostic — works for GET and POST)
      // and deliberately OMIT `prompt` and `max_age`: carrying either would
      // re-trigger forced re-auth after the fresh login and loop forever.
      const rt = new URLSearchParams();
      rt.set('response_type', 'code');
      rt.set('client_id', client_id);
      rt.set('redirect_uri', redirect_uri);
      rt.set('scope', requestedScopes.join(' '));
      rt.set('state', state);
      if (code_challenge) {
        rt.set('code_challenge', code_challenge);
        rt.set('code_challenge_method', 'S256');
      }
      if (nonce) rt.set('nonce', nonce);
      // `prompt=consent` does survive the login: it cannot loop (the consent
      // answer issues the code directly) and dropping it would skip a consent
      // screen the RP explicitly asked for.
      if (promptDirectives.consent) rt.set('prompt', 'consent');
      const returnTo = `/authorize?${rt.toString()}`;
      return reply.redirect(`/login?returnTo=${encodeURIComponent(returnTo)}`, 302);
    }

    // --- Consent (audit 2026-10 FINDING-002). A client gets a code only for
    // scopes the user has approved for it. Two kinds of client skip the step
    // entirely (no page, no consent lookup, `prompt=consent` ignored):
    // FIRST_PARTY clients, which are QRAuth's own, and clients an operator
    // has vetted (lib/oidc-consent.ts clientSkipsConsent). `none` + `consent`
    // together was rejected above, so `none` here means consent cannot be
    // asked for.
    if (!clientSkipsConsent(client)) {
      const covered =
        !promptDirectives.consent &&
        (await hasCoveringConsent(prisma, {
          userId: op.userId,
          oidcClientId: client.id,
          requested: requestedScopes,
        }));
      if (!covered) {
        if (promptDirectives.none) {
          return redirectError(reply, redirect_uri, 'consent_required', 'the user has not consented to this client and prompt=none was requested', state);
        }
        // `op` is only non-null when the cookie resolved to a live session.
        return sendConsentPage(fastify, request, reply, {
          client,
          opSessionToken: opCookie as string,
          request: {
            userId: op.userId,
            oidcClientId: client.id,
            redirectUri: redirect_uri,
            scopes: requestedScopes,
            state,
            codeChallenge: code_challenge,
            nonce,
          },
        });
      }
    }

    // --- Code generation.
    const code = await issueAuthorizationCode(prisma, {
      oidcClientId: client.id,
      userId: op.userId,
      redirectUri: redirect_uri,
      scopes: requestedScopes,
      codeChallenge: code_challenge,
      nonce,
      authTime: op.authTime,
    });

    const redirect = new URL(redirect_uri);
    redirect.searchParams.set('code', code);
    redirect.searchParams.set('state', state);
    return reply.redirect(redirect.toString(), 302);
  };

  fastify.get('/authorize', { config: { rateLimit: rateLimitOidcAuthorize } }, (request, reply) =>
    handleAuthorize(request, reply, request.query as Record<string, string | undefined>),
  );

  // OIDC Core §3.1.2.1: the authorization endpoint MUST also accept POST, with
  // params in an application/x-www-form-urlencoded body (RFC 6749 §3.1).
  registerConsentRoutes(fastify);
  registerSessionEndRoutes(fastify);

  fastify.post('/authorize', { config: { rateLimit: rateLimitOidcAuthorize } }, (request, reply) => {
    const contentType = request.headers['content-type'] ?? '';
    if (!contentType.includes('application/x-www-form-urlencoded')) {
      return reply.status(400).type('application/json').send({
        error: 'invalid_request',
        error_description: 'POST /authorize requires application/x-www-form-urlencoded',
      });
    }
    return handleAuthorize(request, reply, (request.body ?? {}) as Record<string, string | undefined>);
  });

  // ---------------------------------------------------------------------------
  // POST /token — token endpoint (authorization_code grant).
  // ---------------------------------------------------------------------------
  fastify.post('/token', { config: { rateLimit: rateLimitOidcToken } }, async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    reply.header('Pragma', 'no-cache');

    const body = (request.body ?? {}) as Record<string, string | undefined>;
    const tokenError = (status: number, error: string, description: string) =>
      reply.status(status).type('application/json').send({ error, error_description: nqchar(description) });

    // --- Client authentication (client_secret_basic / _post / none), shared
    // with /revoke (lib/oidc-client-auth.ts).
    // Audit 2026-10 FINDING-021: single, bounded strings only.
    const malformed = checkTokenParams((request.body ?? {}) as Record<string, unknown>);
    if (malformed) return tokenError(400, 'invalid_request', malformed);

    const auth = await authenticateOidcClientThrottled(prisma, request.headers.authorization, body, request.ip);
    if (!auth.ok) {
      if (auth.throttled) reply.header('Retry-After', String(CLIENT_AUTH_FAILURE_WINDOW_SECONDS));
      return tokenError(auth.throttled ? 429 : 401, 'invalid_client', auth.description);
    }
    const client = auth.client;

    // --- Shared token minting: pairwise sub → auth method → signing key → ID
    // token → opaque access token. Used by BOTH the authorization_code and the
    // refresh_token grant so the two paths can't drift. `client` is from the
    // client-authentication block above. Returns a discriminated result so the
    // 503-class conditions map to a structured OAuth error at the call site.
    type MintResult =
      | { ok: false; status: number; error: string; description: string }
      | { ok: true; accessToken: string; idToken: string };

    const issueAccessAndIdToken = async (opts: {
      userId: string;
      scope: string;
      authTime: Date;
      nonce: string | null;
      /** Authorization code id / refresh family id the token is issued under. */
      grantId: string;
    }): Promise<MintResult> => {
      let sub: string;
      try {
        sub = computeSubForClient({
          userId: opts.userId,
          client,
          pairwiseSecret: config.oidc.pairwiseSecret,
        });
      } catch (err) {
        if (err instanceof OidcPairwiseSecretMissingError || err instanceof OidcSectorHostMissingError) {
          return { ok: false, status: 503, error: 'temporarily_unavailable', description: 'OP not fully provisioned' };
        }
        throw err;
      }

      // Real acr/amr derived from the user's underlying dashboard auth (Slice 4),
      // anchored at the supplied auth_time.
      const authMethod = await deriveAuthMethod(prisma, opts.userId, opts.authTime);

      // ID-token alg per the client's preference (ADR-0003 Slice 7b). Default
      // RS256 (OIDC Core §15.1 baseline); ES256 for opt-in clients. The column
      // is constrained to these two on write; treat anything else as RS256.
      const idTokenAlg: 'ES256' | 'RS256' =
        client.idTokenSignedResponseAlg === 'ES256' ? 'ES256' : 'RS256';

      // ACTIVE signing key for that alg — a strict SUBSET of the set JWKS
      // publishes (JWKS also serves ROTATED keys for verification; see
      // lib/oidc-signing-keys.ts, where both filters are defined). Lazy
      // validation: a missing key surfaces as 503 here — the operator can
      // bootstrap it (e.g. the RSA key) without a code deploy, never a crash.
      const signingKey = await prisma.signingKey.findFirst({
        where: platformSigningKeyWhere(idTokenAlg),
        orderBy: { createdAt: 'desc' },
        select: { keyId: true },
      });
      if (!signingKey) {
        return { ok: false, status: 503, error: 'temporarily_unavailable', description: `no active ${idTokenAlg} signing key` };
      }

      const idToken = await buildIdToken({
        issuer: config.oidc.issuer,
        audience: client.clientId,
        subject: sub,
        nonce: opts.nonce,
        authTime: opts.authTime,
        signingKey: { keyId: signingKey.keyId },
        signingService: fastify.signingService,
        acr: authMethod.acr,
        amr: authMethod.amr,
        alg: idTokenAlg,
      });

      // Opaque access token (Phase 1; /userinfo validates it — Slice 4).
      const accessToken = randomBytes(32).toString('base64url');
      await prisma.oidcAccessToken.create({
        data: {
          tokenHash: hashString(accessToken),
          oidcClientId: client.id,
          userId: opts.userId,
          scope: opts.scope,
          grantId: opts.grantId,
          expiresAt: new Date(Date.now() + ACCESS_TOKEN_TTL_SECONDS * 1000),
        },
      });

      return { ok: true, accessToken, idToken };
    };

    const refuseReplayedCode = async (authCode: { id: string; userId: string }) => {
      // Mark first, then revoke: a redemption still minting its tokens sees
      // the mark when it finishes and revokes what it just issued.
      await prisma.oidcAuthCode.update({ where: { id: authCode.id }, data: { replayedAt: new Date() } });
      const revokedRefreshTokens = await invalidateFamily({ prisma, familyId: authCode.id });
      request.log.warn(
        { event: 'oidc.code.replay_detected', grantId: authCode.id, revokedRefreshTokens, clientId: client.clientId, userId: authCode.userId },
        'oidc.code.replay_detected — tokens issued from the first redemption revoked',
      );
      return tokenError(400, 'invalid_grant', 'authorization code already used');
    };

    // -------------------------------------------------------------------------
    // Grant dispatch: authorization_code (Slice 3b.2) + refresh_token (Slice 5).
    // -------------------------------------------------------------------------
    if (body.grant_type === 'authorization_code') {
      const code = body.code;
      const codeVerifier = body.code_verifier;
      const redirectUri = body.redirect_uri;
      if (!code || !redirectUri) {
        return tokenError(400, 'invalid_request', 'code and redirect_uri are required');
      }

      const submittedCodeHash = hashString(code);
      const authCode = await prisma.oidcAuthCode.findUnique({ where: { codeHash: submittedCodeHash } });
      if (!authCode) return tokenError(400, 'invalid_grant', 'invalid authorization code');
      if (authCode.oidcClientId !== client.id) return tokenError(400, 'invalid_grant', 'code was not issued to this client');

      if (!constantTimeEqualString(authCode.redirectUri, redirectUri)) {
        return tokenError(400, 'invalid_grant', 'redirect_uri mismatch');
      }
      // PKCE verification (timing-safe) — only when a challenge was issued at
      // /authorize (Slice 8.3: confidential clients may omit PKCE; the empty
      // codeChallenge sentinel means none was used). A stored challenge requires
      // a matching code_verifier.
      if (authCode.codeChallenge) {
        if (!codeVerifier) {
          return tokenError(400, 'invalid_request', 'code_verifier is required for this authorization code');
        }
        if (!constantTimeEqualString(base64urlSha256(codeVerifier), authCode.codeChallenge)) {
          return tokenError(400, 'invalid_grant', 'PKCE verification failed');
        }
      }

      // A code presented a second time means it leaked: end the grant the
      // first redemption started (RFC 6749 §4.1.2). Only a caller who also
      // passed the redirect_uri and PKCE checks above gets this far, so
      // someone who merely saw the code in a URL cannot use it to sign the
      // user out. Before the expiry check, so a late replay still revokes.
      if (authCode.usedAt !== null) return refuseReplayedCode(authCode);
      if (authCode.expiresAt.getTime() <= Date.now()) return tokenError(400, 'invalid_grant', 'authorization code expired');

      // Atomic single-use claim: exactly one concurrent redemption wins.
      const claim = await prisma.oidcAuthCode.updateMany({
        where: { codeHash: submittedCodeHash, usedAt: null },
        data: { usedAt: new Date() },
      });
      // Lost a race with a concurrent redemption of the same code.
      if (claim.count === 0) return refuseReplayedCode(authCode);

      const minted = await issueAccessAndIdToken({
        userId: authCode.userId,
        scope: authCode.scope,
        authTime: authCode.authTime,
        nonce: authCode.nonce,
        grantId: authCode.id,
      });
      if (!minted.ok) return tokenError(minted.status, minted.error, minted.description);

      // Issue a refresh token when offline_access was granted. RFC 6749 §5.1:
      // omit the field entirely when not issued (never empty/null).
      const grantedScopes = new Set(authCode.scope.split(/\s+/).filter(Boolean));
      let refreshTokenValue: string | undefined;
      if (grantedScopes.has('offline_access')) {
        const refresh = await mintRefreshToken({
          prisma,
          // The family is the grant: one id ties the code, its refresh
          // tokens and its access tokens together.
          familyId: authCode.id,
          oidcClientId: client.id,
          userId: authCode.userId,
          scope: authCode.scope,
          // Persist the original auth event so every refreshed ID token echoes
          // the SAME auth_time (OIDC Core §12.2).
          authTime: authCode.authTime,
        });
        refreshTokenValue = refresh.token;
      }

      // The same code may have been presented again while these tokens were
      // being issued; that replay could not revoke rows that did not exist
      // yet, so check for its mark now.
      const afterMint = await prisma.oidcAuthCode.findUnique({ where: { id: authCode.id }, select: { replayedAt: true } });
      if (afterMint?.replayedAt) {
        await invalidateFamily({ prisma, familyId: authCode.id });
        return tokenError(400, 'invalid_grant', 'authorization code already used');
      }

      return reply.type('application/json').send({
        access_token: minted.accessToken,
        token_type: 'Bearer',
        expires_in: ACCESS_TOKEN_TTL_SECONDS,
        id_token: minted.idToken,
        scope: authCode.scope,
        ...(refreshTokenValue ? { refresh_token: refreshTokenValue } : {}),
      });
    }

    if (body.grant_type === 'refresh_token') {
      const presented = body.refresh_token;
      if (!presented) return tokenError(400, 'invalid_request', 'refresh_token is required');

      // Hash-keyed unique lookup (AUDIT-FINDING-012: never a bare === on the hash).
      const presentedHash = hashString(presented);
      const existing = await prisma.oidcRefreshToken.findUnique({ where: { tokenHash: presentedHash } });
      if (!existing) return tokenError(400, 'invalid_grant', 'invalid refresh token');
      if (existing.oidcClientId !== client.id) return tokenError(400, 'invalid_grant', 'refresh token was not issued to this client');
      if (existing.revokedAt !== null) return tokenError(400, 'invalid_grant', 'refresh token revoked');
      if (existing.expiresAt.getTime() <= Date.now()) return tokenError(400, 'invalid_grant', 'refresh token expired');

      // Reuse detection (OAuth 2.1 §6.1): a rotated token presented again is a
      // replay — revoke the whole family and refuse. Mandatory security log.
      if (existing.rotatedAt !== null) {
        const revokedCount = await invalidateFamily({ prisma, familyId: existing.familyId });
        request.log.warn(
          {
            event: 'oidc.refresh.reuse_detected',
            familyId: existing.familyId,
            revokedCount,
            clientId: client.clientId,
            userId: existing.userId,
          },
          'oidc.refresh.reuse_detected — entire token family invalidated',
        );
        return tokenError(400, 'invalid_grant', 'refresh token reuse detected; family invalidated');
      }

      // Scope narrowing (RFC 6749 §6): the requested scope must be a subset of
      // the originally-granted scope. Wider → reject; narrower → honor.
      let grantedScope = existing.scope;
      if (typeof body.scope === 'string' && body.scope.length > 0) {
        const requested = body.scope.split(/\s+/).filter(Boolean);
        const original = new Set(existing.scope.split(/\s+/).filter(Boolean));
        for (const s of requested) {
          if (!original.has(s)) {
            return tokenError(400, 'invalid_scope', `scope ${s} was not granted in the original authorization`);
          }
        }
        // A narrowing that leaves out `openid` is a malformed request, not a
        // dead grant: refuse it without touching the family.
        if (!requested.includes('openid')) {
          return tokenError(400, 'invalid_scope', 'scope must include openid');
        }
        grantedScope = requested.join(' ');
      }

      // Re-check what this grant may still do (audit 2026-10 FINDING-011):
      // absolute family lifetime, the client's current allowedScopes and, for
      // non-FIRST_PARTY clients, the user's live consent. A grant that fails
      // is dead for good, so the whole family goes with it.
      const policy = await resolveRefreshGrant(prisma, { client, presented: existing, scope: grantedScope });
      if (!policy.ok) {
        const revokedCount = await invalidateFamily({ prisma, familyId: existing.familyId });
        request.log.info(
          { event: 'oidc.refresh.policy_refused', familyId: existing.familyId, revokedCount, clientId: client.clientId, userId: existing.userId },
          'oidc.refresh.policy_refused — family invalidated',
        );
        return tokenError(400, 'invalid_grant', policy.description);
      }
      grantedScope = policy.scope;

      // Rotate: mint the successor (inheriting the family), then atomically claim
      // the presented token. Mint-then-claim means a lost race leaves an orphan
      // successor, revoked in the race branch below.
      const successor = await mintRefreshToken({
        prisma,
        familyId: existing.familyId,
        oidcClientId: client.id,
        userId: existing.userId,
        scope: grantedScope,
        // Never past the family's absolute end.
        ttlSeconds: policy.ttlSeconds,
        // Carry the original auth event forward unchanged across rotations.
        authTime: existing.authTime,
      });

      const claimed = await claimRefreshToken({ prisma, tokenHash: presentedHash, successorRowId: successor.rowId });
      if (!claimed) {
        // A concurrent rotation already claimed the token — double-spend is a
        // leak signal. Invalidate the family and revoke the orphan successor.
        const revokedCount = await invalidateFamily({ prisma, familyId: existing.familyId });
        await prisma.oidcRefreshToken.update({ where: { id: successor.rowId }, data: { revokedAt: new Date() } });
        request.log.warn(
          {
            event: 'oidc.refresh.race_detected',
            familyId: existing.familyId,
            revokedCount,
            clientId: client.clientId,
            userId: existing.userId,
          },
          'oidc.refresh.race_detected — concurrent rotation; entire token family invalidated',
        );
        return tokenError(400, 'invalid_grant', 'refresh token race detected; family invalidated');
      }

      // auth_time provenance (OIDC Core §12.2): the refreshed ID token MUST echo
      // the SAME auth_time as the original. Slice 8.5 stores the exact event on
      // the token (inherited across rotations) — use it directly. For legacy
      // pre-migration tokens (authTime null) fall back to the family-root
      // createdAt approximation (stable across rotations, off by the
      // code-redemption delay).
      const authTime = existing.authTime ?? policy.familyStartedAt;

      // ID token on refresh carries NO nonce (OIDC Core §12 — nonce binds the
      // original /authorize request only). auth_time is the original event.
      const minted = await issueAccessAndIdToken({
        userId: existing.userId,
        scope: grantedScope,
        authTime,
        nonce: null,
        grantId: existing.familyId,
      });
      if (!minted.ok) return tokenError(minted.status, minted.error, minted.description);

      return reply.type('application/json').send({
        access_token: minted.accessToken,
        token_type: 'Bearer',
        expires_in: ACCESS_TOKEN_TTL_SECONDS,
        id_token: minted.idToken,
        scope: grantedScope,
        refresh_token: successor.token,
      });
    }

    return tokenError(400, 'unsupported_grant_type', 'only authorization_code and refresh_token are supported');
  });

  // ---------------------------------------------------------------------------
  // GET/POST /userinfo — OIDC UserInfo endpoint (OIDC Core §5.3, RFC 6750).
  //
  // Bearer-authenticated, JSON only. Returns `sub` (always) plus the claims
  // granted by the access token's scope. Read-only: the access token is never
  // mutated here (revocation is checked, not written).
  // ---------------------------------------------------------------------------
  const handleUserinfo = async (
    request: FastifyRequest,
    reply: FastifyReply,
  ): Promise<unknown> => {
    reply.header('Cache-Control', 'no-store');
    reply.header('Pragma', 'no-cache');

    // RFC 6750 §3.1: invalid/expired/revoked credentials → 401 + a challenge
    // carrying error="invalid_token".
    const invalidToken = (): FastifyReply => {
      reply.header('WWW-Authenticate', 'Bearer error="invalid_token"');
      return reply.status(401).type('application/json').send({ error: 'invalid_token' });
    };

    // Extract the bearer token: Authorization header (RFC 6750 §2.1) or, for a
    // POST, the `access_token` form param (§2.2).
    let presented: string | undefined;
    const authHeader = request.headers.authorization;
    if (authHeader?.startsWith('Bearer ')) {
      presented = authHeader.slice('Bearer '.length).trim();
    } else if (request.method === 'POST') {
      const body = (request.body ?? {}) as Record<string, string | undefined>;
      if (typeof body.access_token === 'string') presented = body.access_token.trim();
    }
    if (!presented) {
      // No credentials at all → bare challenge, no error code (RFC 6750 §3.1).
      reply.header('WWW-Authenticate', 'Bearer');
      return reply
        .status(401)
        .type('application/json')
        .send({ error: 'invalid_request', error_description: 'a bearer access token is required' });
    }

    // Unique-index lookup by hash — never a `===` on the crypto-named token
    // (AUDIT-FINDING-012); Prisma resolves it in constant index time.
    const accessToken = await prisma.oidcAccessToken.findUnique({
      where: { tokenHash: hashString(presented) },
    });
    if (!accessToken) return invalidToken();
    if (accessToken.revokedAt !== null) return invalidToken();
    if (accessToken.expiresAt.getTime() <= Date.now()) return invalidToken();

    const client = await prisma.oidcClient.findUnique({
      where: { id: accessToken.oidcClientId },
      select: { sectorHost: true },
    });
    if (!client) return invalidToken();

    const user = await prisma.user.findUnique({
      where: { id: accessToken.userId },
      select: { name: true, email: true, emailVerified: true, avatarUrl: true },
    });
    if (!user) return invalidToken();

    // `sub` MUST byte-equal the ID token's sub — same shared helper, same
    // stored sector host as /token.
    let sub: string;
    try {
      sub = computeSubForClient({
        userId: accessToken.userId,
        client,
        pairwiseSecret: config.oidc.pairwiseSecret,
      });
    } catch (err) {
      if (err instanceof OidcPairwiseSecretMissingError || err instanceof OidcSectorHostMissingError) {
        return reply
          .status(503)
          .type('application/json')
          .send({ error: 'temporarily_unavailable', error_description: 'OP not fully provisioned' });
      }
      throw err;
    }

    // Scope-gated claims (OIDC Core §5.4). `sub` is the only always-present
    // claim; everything else requires its granting scope.
    const scopes = new Set(accessToken.scope.split(/\s+/).filter(Boolean));
    const claims: Record<string, unknown> = { sub };
    if (scopes.has('email')) {
      claims.email = user.email;
      claims.email_verified = user.emailVerified;
    }
    if (scopes.has('profile')) {
      const name = profileNameClaim(user);
      if (name) claims.name = name;
      if (user.avatarUrl) claims.picture = user.avatarUrl;
    }
    if (scopes.has('qrauth:auth_method')) {
      const authMethod = await deriveAuthMethod(prisma, accessToken.userId, accessToken.createdAt);
      claims['qrauth:auth_method'] = authMethod.qrauthAuthMethod;
    }

    return reply.type('application/json').send(claims);
  };

  fastify.get('/userinfo', { config: { rateLimit: rateLimitOidcUserinfo } }, handleUserinfo);
  fastify.post('/userinfo', { config: { rateLimit: rateLimitOidcUserinfo } }, handleUserinfo);
}
