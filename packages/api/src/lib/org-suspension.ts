import type { FastifyReply, FastifyRequest } from 'fastify';
import type { PrismaClient } from '@prisma/client';

/**
 * A suspended organization (Organization.suspendedAt set by a superadmin)
 * keeps read access, so its members can see their state, but its mutating
 * API calls are refused with 403. The check runs in `authenticate`, so every
 * authenticated route is covered by default, including routes added later.
 *
 * Exempt: the superadmin routes, and personal account actions that change
 * the signed-in person rather than the organization.
 */

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

const EXEMPT_PREFIXES = ['/api/v1/admin/'];

const EXEMPT_ROUTES = new Set([
  // Move to another organization, or join one.
  'POST /api/v1/auth/switch-org',
  'POST /api/v1/organizations/invitations/:token/accept',
  // The person's own account, sessions, passkeys, devices and consents.
  'DELETE /api/v1/account/delete-account',
  'DELETE /api/v1/sessions',
  'DELETE /api/v1/sessions/:id',
  'POST /api/v1/webauthn/register/options',
  'POST /api/v1/webauthn/register/verify',
  'PATCH /api/v1/webauthn/passkeys/:id',
  'DELETE /api/v1/webauthn/passkeys/:id',
  'PATCH /api/v1/devices/:id',
  'DELETE /api/v1/devices/:id',
  'POST /api/v1/devices/:id/revoke',
  'POST /api/v1/devices/:id/reverify',
  'DELETE /api/v1/oidc/consents/:id',
  // The person's own decision on a sign-in request.
  'POST /api/v1/auth-sessions/:token/approve',
  'POST /api/v1/auth-sessions/:token/deny',
]);

export function isSuspensionExempt(method: string, routeUrl: string | undefined): boolean {
  if (SAFE_METHODS.has(method)) return true;
  if (!routeUrl) return false;
  const url = routeUrl.length > 1 ? routeUrl.replace(/\/+$/, '') : routeUrl;
  if (EXEMPT_PREFIXES.some((p) => url.startsWith(p) || `${url}/` === p)) return true;
  return EXEMPT_ROUTES.has(`${method} ${url}`);
}

export const ORG_SUSPENDED_ERROR = 'OrganizationSuspended';

/**
 * Sends 403 and returns the reply when the request mutates a suspended
 * organization; returns undefined otherwise.
 */
export async function refuseIfOrgSuspended(
  prisma: Pick<PrismaClient, 'organization'>,
  request: FastifyRequest,
  reply: FastifyReply,
): Promise<FastifyReply | undefined> {
  const orgId = request.user?.orgId;
  if (!orgId || isSuspensionExempt(request.method, request.routeOptions?.url)) return undefined;

  const org = await prisma.organization.findUnique({
    where: { id: orgId },
    select: { suspendedAt: true },
  });
  if (!org?.suspendedAt) return undefined;

  return reply.status(403).send({
    statusCode: 403,
    error: ORG_SUSPENDED_ERROR,
    message: 'This organization is suspended. Changes are disabled; contact QRAuth support.',
  });
}
