import { rateLimitOidcAuthorize } from '../middleware/rateLimit.js';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { OidcClient } from '@prisma/client';
import { readOpSessionCookie, readOpSessionWithMeta } from '../lib/oidc-session.js';
import {
  CONSENT_GRANTED_AUDIT_ACTION,
  createPendingConsent,
  consumePendingConsent,
  describeScope,
  grantConsent,
  type PendingConsentRequest,
} from '../lib/oidc-consent.js';
import { issueAuthorizationCode } from '../lib/oidc-auth-code.js';
import { renderConsentPage, renderConsentExpiredPage } from '../renderers/oidc/consent.js';
import { returnToClient, sendOpHtml } from './oidc-html.js';

/**
 * OP consent step (audit 2026-10 FINDING-002): the page /authorize renders
 * for a CUSTOMER-tier client, and the POST that answers it.
 */

type ConsentClient = Pick<OidcClient, 'id' | 'name'> & { organization: { name: string } };

/** Render the consent page for a validated authorization request. */
export async function sendConsentPage(
  fastify: FastifyInstance,
  httpRequest: FastifyRequest,
  reply: FastifyReply,
  params: { client: ConsentClient; request: PendingConsentRequest; opSessionToken: string },
): Promise<FastifyReply> {
  const { client, request, opSessionToken } = params;
  const user = await fastify.prisma.user.findUnique({
    where: { id: request.userId },
    select: { email: true },
  });
  const consentToken = await createPendingConsent(request, opSessionToken);

  return sendOpHtml(httpRequest, reply, 200, (nonce) =>
    renderConsentPage({
      nonce,
      clientName: client.name,
      organizationName: client.organization.name,
      redirectHost: new URL(request.redirectUri).host,
      scopeDescriptions: request.scopes.map(describeScope),
      accountEmail: user?.email ?? '',
      consentToken,
    }),
  );
}

export function registerConsentRoutes(fastify: FastifyInstance): void {
  const prisma = fastify.prisma;

  fastify.post('/authorize/consent', { config: { rateLimit: rateLimitOidcAuthorize } }, async (request: FastifyRequest, reply: FastifyReply) => {
    const refuse = (reason: string) => {
      request.log.warn({ event: 'oidc.consent.refused', reason }, 'consent form refused');
      return sendOpHtml(request, reply, 400, renderConsentExpiredPage);
    };

    const body = (request.body ?? {}) as Record<string, unknown>;
    const decision = body.decision;
    if (decision !== 'approve' && decision !== 'deny') return refuse('bad_decision');
    const consentToken = typeof body.consent_token === 'string' ? body.consent_token : undefined;

    // The OP session cookie is SameSite=Lax, so a cross-site POST arrives
    // without it and stops here; the token then ties the answer to the exact
    // request this browser was shown.
    const opCookie = readOpSessionCookie(request.cookies);
    const pending = await consumePendingConsent(consentToken, opCookie);
    if (!pending) return refuse('token_invalid');

    const op = await readOpSessionWithMeta(prisma, opCookie);
    if (!op || op.userId !== pending.userId) return refuse('session_invalid');

    // The registration may have changed while the page was open.
    const client = await prisma.oidcClient.findUnique({ where: { id: pending.oidcClientId } });
    if (!client) return refuse('client_gone');
    if (!client.redirectUris.includes(pending.redirectUri)) return refuse('redirect_uri_removed');
    if (pending.scopes.some((scope) => !client.allowedScopes.includes(scope))) return refuse('scope_removed');

    if (decision === 'deny') {
      request.log.info(
        { event: 'oidc.consent.denied', clientId: client.clientId, userId: op.userId },
        'consent denied',
      );
      return returnToClient(request, reply, pending.redirectUri, {
        error: 'access_denied',
        error_description: 'the user denied the request',
        state: pending.state,
      });
    }

    const grantedScopes = await grantConsent(prisma, {
      userId: op.userId,
      oidcClientId: client.id,
      scopes: pending.scopes,
    });

    // AuditLog rows are org-scoped. The consent is the user's own act, so it
    // is filed under the user's organization, never the client's: the client
    // owner must not learn which accounts stand behind its pairwise subs.
    const membership = await prisma.membership.findFirst({
      where: { userId: op.userId },
      orderBy: { joinedAt: 'desc' },
      select: { organizationId: true },
    });
    if (membership) {
      await prisma.auditLog.create({
        data: {
          organizationId: membership.organizationId,
          userId: op.userId,
          action: CONSENT_GRANTED_AUDIT_ACTION,
          resource: 'OidcClient',
          resourceId: client.id,
          metadata: { clientId: client.clientId, requestedScopes: pending.scopes, grantedScopes },
          ipAddress: null,
        },
      });
    }

    const code = await issueAuthorizationCode(prisma, {
      oidcClientId: client.id,
      userId: op.userId,
      redirectUri: pending.redirectUri,
      scopes: pending.scopes,
      codeChallenge: pending.codeChallenge,
      nonce: pending.nonce,
      authTime: op.authTime,
    });
    return returnToClient(request, reply, pending.redirectUri, { code, state: pending.state });
  });
}
