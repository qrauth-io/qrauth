import type { FastifyReply } from 'fastify';
import type { PrismaClient } from '@prisma/client';
import { API_KEY_PRINCIPAL_ID } from '../middleware/auth.js';
import type { UserContext } from '../types/fastify.js';

/**
 * Creating QR codes, and changing where one points, needs a verified email
 * behind the request:
 *
 * - a signed-in user: that user's email is verified (by the emailed link,
 *   or by an OAuth provider that vouched for the address);
 * - an API key: at least one OWNER of the key's organization has a
 *   verified email.
 */
export async function isActorEmailVerified(
  prisma: Pick<PrismaClient, 'user' | 'membership'>,
  actor: UserContext,
): Promise<boolean> {
  if (actor.id === API_KEY_PRINCIPAL_ID) {
    const verifiedOwner = await prisma.membership.findFirst({
      where: { organizationId: actor.orgId, role: 'OWNER', user: { emailVerified: true } },
      select: { id: true },
    });
    return verifiedOwner !== null;
  }
  const user = await prisma.user.findUnique({
    where: { id: actor.id },
    select: { emailVerified: true },
  });
  return user?.emailVerified === true;
}

/** Same shape as the login refusal, so clients can share the handling. */
export function sendEmailNotVerified(reply: FastifyReply, actor: UserContext): FastifyReply {
  return reply.status(403).send({
    statusCode: 403,
    error: 'EmailNotVerified',
    message:
      actor.id === API_KEY_PRINCIPAL_ID
        ? 'An owner of this organization must verify their email address before QR codes can be created or edited.'
        : 'Verify your email address before creating or editing QR codes.',
  });
}

/** preHandler: refuses the request (403) unless isActorEmailVerified(). */
export function verifiedEmailGuard(prisma: Pick<PrismaClient, 'user' | 'membership'>) {
  return async function requireVerifiedEmail(
    request: { user?: UserContext | null },
    reply: FastifyReply,
  ): Promise<void> {
    const actor = request.user;
    if (!actor) return; // authenticate already answered 401
    if (!(await isActorEmailVerified(prisma, actor))) {
      sendEmailNotVerified(reply, actor);
    }
  };
}
