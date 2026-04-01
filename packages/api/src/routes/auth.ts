import type { FastifyInstance } from 'fastify';
import { zodValidator } from '../middleware/validate.js';
import { hashPassword, verifyPassword } from '../lib/password.js';
import { hashString } from '../lib/crypto.js';
import { SigningService } from '../services/signing.js';
import {
  signupSchema,
  loginSchema,
  switchOrgSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
} from '@vqr/shared';
import { randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

export default async function authRoutes(fastify: FastifyInstance): Promise<void> {
  const signingService = new SigningService(fastify.prisma);
  const authenticate = fastify.authenticate;

  // -------------------------------------------------------------------------
  // POST /signup — Create user + org
  // -------------------------------------------------------------------------

  fastify.post('/signup', {
    preValidation: zodValidator({ body: signupSchema }),
  }, async (request, reply) => {
    const body = request.body as {
      name: string;
      email: string;
      password: string;
      organizationName: string;
    };

    // Check email uniqueness.
    const existing = await fastify.prisma.user.findUnique({
      where: { email: body.email },
      select: { id: true },
    });

    if (existing) {
      return reply.status(409).send({
        statusCode: 409,
        error: 'Conflict',
        message: 'An account with that email address already exists.',
      });
    }

    // Derive URL-safe slug from organization name.
    let slug = body.organizationName
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '');

    // Ensure slug uniqueness — append 4 random hex chars on collision.
    const slugConflict = await fastify.prisma.organization.findUnique({
      where: { slug },
      select: { id: true },
    });

    if (slugConflict) {
      slug = `${slug}-${randomBytes(2).toString('hex')}`;
    }

    const passwordHash = await hashPassword(body.password);
    const emailVerifyToken = randomBytes(32).toString('hex');

    // Atomic creation of user, org, and membership.
    const { user, org, membership } = await fastify.prisma.$transaction(async (tx) => {
      const user = await tx.user.create({
        data: {
          name: body.name,
          email: body.email,
          passwordHash,
          emailVerifyToken,
        },
      });

      const org = await tx.organization.create({
        data: {
          name: body.organizationName,
          slug,
          email: body.email,
        },
      });

      const membership = await tx.membership.create({
        data: {
          userId: user.id,
          organizationId: org.id,
          role: 'OWNER',
        },
      });

      return { user, org, membership };
    });

    // Generate the first signing key pair for the new organization.
    await signingService.createKeyPair(org.id);

    const token = fastify.jwt.sign({
      userId: user.id,
      orgId: org.id,
      role: membership.role,
      email: user.email,
    });

    return reply.status(201).send({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
      organization: {
        id: org.id,
        name: org.name,
        slug: org.slug,
      },
    });
  });

  // -------------------------------------------------------------------------
  // POST /login
  // -------------------------------------------------------------------------

  fastify.post('/login', {
    preValidation: zodValidator({ body: loginSchema }),
  }, async (request, reply) => {
    const body = request.body as { email: string; password: string };

    const user = await fastify.prisma.user.findUnique({
      where: { email: body.email },
    });

    if (!user) {
      return reply.status(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        message: 'Invalid credentials.',
      });
    }

    const passwordValid = await verifyPassword(body.password, user.passwordHash);

    if (!passwordValid) {
      return reply.status(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        message: 'Invalid credentials.',
      });
    }

    const memberships = await fastify.prisma.membership.findMany({
      where: { userId: user.id },
      include: { organization: true },
      orderBy: { joinedAt: 'desc' },
    });

    if (memberships.length === 0) {
      return reply.status(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        message: 'No organization membership found.',
      });
    }

    const activeMembership = memberships[0];

    // Update last login timestamp without blocking the response.
    fastify.prisma.user
      .update({
        where: { id: user.id },
        data: { lastLoginAt: new Date() },
      })
      .catch((err: unknown) => {
        fastify.log.warn({ err, userId: user.id }, 'Failed to update lastLoginAt');
      });

    const token = fastify.jwt.sign({
      userId: user.id,
      orgId: activeMembership.organizationId,
      role: activeMembership.role,
      email: user.email,
    });

    return reply.send({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
      organization: {
        id: activeMembership.organization.id,
        name: activeMembership.organization.name,
        slug: activeMembership.organization.slug,
      },
      memberships: memberships.map((m) => ({
        id: m.id,
        organizationId: m.organizationId,
        organizationName: m.organization.name,
        role: m.role,
      })),
    });
  });

  // -------------------------------------------------------------------------
  // POST /switch-org — Exchange JWT for a new org context (authenticated)
  // -------------------------------------------------------------------------

  fastify.post('/switch-org', {
    preHandler: [authenticate],
    preValidation: zodValidator({ body: switchOrgSchema }),
  }, async (request, reply) => {
    const body = request.body as { organizationId: string };

    const membership = await fastify.prisma.membership.findUnique({
      where: {
        userId_organizationId: {
          userId: request.user!.id,
          organizationId: body.organizationId,
        },
      },
      include: { organization: true },
    });

    if (!membership) {
      return reply.status(403).send({
        statusCode: 403,
        error: 'Forbidden',
        message: 'You are not a member of this organization.',
      });
    }

    const token = fastify.jwt.sign({
      userId: request.user!.id,
      orgId: membership.organizationId,
      role: membership.role,
      email: request.user!.email,
    });

    return reply.send({
      token,
      organization: {
        id: membership.organization.id,
        name: membership.organization.name,
        slug: membership.organization.slug,
      },
    });
  });

  // -------------------------------------------------------------------------
  // POST /forgot-password
  // -------------------------------------------------------------------------

  fastify.post('/forgot-password', {
    preValidation: zodValidator({ body: forgotPasswordSchema }),
  }, async (request, reply) => {
    const { email } = request.body as { email: string };

    const user = await fastify.prisma.user.findUnique({
      where: { email },
      select: { id: true },
    });

    // Always return 200 to prevent email enumeration.
    if (!user) {
      return reply.send({
        message: 'If an account exists, a reset link has been sent.',
      });
    }

    const rawToken = randomBytes(32).toString('hex');
    const hashedToken = hashString(rawToken);
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    await fastify.prisma.user.update({
      where: { id: user.id },
      data: {
        passwordResetToken: hashedToken,
        passwordResetExpires: expiresAt,
      },
    });

    // In production this would be dispatched via email.
    console.log(`[vqr] Password reset token for ${email}: ${rawToken}`);

    return reply.send({
      message: 'If an account exists, a reset link has been sent.',
    });
  });

  // -------------------------------------------------------------------------
  // POST /reset-password
  // -------------------------------------------------------------------------

  fastify.post('/reset-password', {
    preValidation: zodValidator({ body: resetPasswordSchema }),
  }, async (request, reply) => {
    const { token, password } = request.body as { token: string; password: string };

    const hashedToken = hashString(token);

    const user = await fastify.prisma.user.findFirst({
      where: {
        passwordResetToken: hashedToken,
        passwordResetExpires: { gt: new Date() },
      },
      select: { id: true },
    });

    if (!user) {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: 'Invalid or expired reset token.',
      });
    }

    const passwordHash = await hashPassword(password);

    await fastify.prisma.user.update({
      where: { id: user.id },
      data: {
        passwordHash,
        passwordResetToken: null,
        passwordResetExpires: null,
      },
    });

    return reply.send({ message: 'Password reset successful.' });
  });

  // -------------------------------------------------------------------------
  // GET /verify-email/:token
  // -------------------------------------------------------------------------

  fastify.get('/verify-email/:token', async (request, reply) => {
    const { token } = request.params as { token: string };

    const user = await fastify.prisma.user.findUnique({
      where: { emailVerifyToken: token },
      select: { id: true },
    });

    if (!user) {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: 'Invalid verification token.',
      });
    }

    await fastify.prisma.user.update({
      where: { id: user.id },
      data: {
        emailVerified: true,
        emailVerifyToken: null,
      },
    });

    return reply.send({ message: 'Email verified successfully.' });
  });

  // -------------------------------------------------------------------------
  // GET /me — Current user profile (authenticated)
  // -------------------------------------------------------------------------

  fastify.get('/me', {
    preHandler: [authenticate],
  }, async (request, reply) => {
    const user = await fastify.prisma.user.findUnique({
      where: { id: request.user!.id },
      select: {
        id: true,
        name: true,
        email: true,
        emailVerified: true,
        lastLoginAt: true,
        createdAt: true,
        updatedAt: true,
        memberships: {
          include: { organization: true },
          orderBy: { joinedAt: 'desc' },
        },
      },
    });

    if (!user) {
      return reply.status(404).send({
        statusCode: 404,
        error: 'Not Found',
        message: 'User not found.',
      });
    }

    const currentOrgId = request.user!.orgId;
    const activeMembership =
      user.memberships.find((m) => m.organizationId === currentOrgId) ??
      user.memberships[0];

    return reply.send({
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        emailVerified: user.emailVerified,
        role: activeMembership?.role ?? null,
        organization: activeMembership
          ? {
              id: activeMembership.organization.id,
              name: activeMembership.organization.name,
              slug: activeMembership.organization.slug,
            }
          : null,
        memberships: user.memberships.map((m) => ({
          organizationId: m.organizationId,
          organizationName: m.organization.name,
          role: m.role,
        })),
      },
    });
  });
}
