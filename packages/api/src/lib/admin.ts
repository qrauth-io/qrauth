import type { FastifyReply, FastifyRequest } from 'fastify';
import type { PrismaClient } from '@prisma/client';

/**
 * Platform-level admin (superadmin) helpers.
 *
 * Superadmin status is determined by matching the authenticated user's email
 * against the `ADMIN_EMAILS` env var (comma-separated list) AND that address
 * being verified. This is a platform-level role, independent of
 * per-organization Membership.role.
 */

export function getAdminEmails(): string[] {
  return (process.env.ADMIN_EMAILS ?? '')
    .split(',')
    .map((e) => e.trim())
    .filter(Boolean);
}

/**
 * Whether the ADDRESS is on the admin list. On its own this grants nothing:
 * an account can hold an address it has not proven (emailVerified = false),
 * so use `isSuperAdmin` / `isVerifiedAdmin` to decide access.
 */
export function isAdminEmail(email: string | null | undefined): boolean {
  if (!email) return false;
  return getAdminEmails().includes(email);
}

/** Superadmin = an admin-list address the account has verified. */
export function isSuperAdmin(user: { email: string | null; emailVerified: boolean } | null | undefined): boolean {
  return !!user && user.emailVerified === true && isAdminEmail(user.email);
}

type AdminDb = { user: Pick<PrismaClient['user'], 'findUnique'> };

/**
 * Superadmin check for an authenticated request. The JWT carries the email
 * but not whether it is verified, so the account row decides.
 */
export async function isVerifiedAdmin(
  db: AdminDb,
  user: { id: string; email: string } | null | undefined,
): Promise<boolean> {
  if (!user || !isAdminEmail(user.email)) return false;
  const account = await db.user.findUnique({
    where: { id: user.id },
    select: { email: true, emailVerified: true },
  });
  return isSuperAdmin(account);
}

/**
 * preHandler guard — returns a 403 when the authenticated user is not a
 * superadmin. Must be placed after `authenticate` in the preHandler chain so
 * `request.user` is already populated. Fails closed when `ADMIN_EMAILS` is
 * unset.
 */
export async function requireAdmin(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  if (!(await isVerifiedAdmin(request.server.prisma, request.user))) {
    return reply.status(403).send({
      statusCode: 403,
      error: 'Forbidden',
      message: 'Admin access required',
    });
  }
}
