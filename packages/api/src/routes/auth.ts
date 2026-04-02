import type { FastifyInstance } from 'fastify';
import { randomBytes } from 'node:crypto';
import { zodValidator } from '../middleware/validate.js';
import { hashPassword, verifyPassword } from '../lib/password.js';
import { hashString } from '../lib/crypto.js';
import { SigningService } from '../services/signing.js';
import { sendPasswordResetEmail } from '../lib/email.js';
import {
  signupSchema,
  loginSchema,
  switchOrgSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  ACCOUNT_LOCKOUT_MINUTES,
} from '@vqr/shared';
import { getEnabledProviderNames, buildAuthUrl, exchangeCodeForUser, generateOAuthState } from '../lib/oauth.js';
import { cacheSet, cacheGet, cacheDel } from '../lib/cache.js';
import { config } from '../lib/config.js';
import { collectRequestMetadata } from '../lib/metadata.js';
import { LoginEventService } from '../services/login-event.js';

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

export default async function authRoutes(fastify: FastifyInstance): Promise<void> {
  const signingService = new SigningService(fastify.prisma);
  const authenticate = fastify.authenticate;
  const loginEventService = new LoginEventService(fastify.prisma);

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

    const signupMeta = await collectRequestMetadata(request);
    await loginEventService.record(user.id, true, 'EMAIL', signupMeta);

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

    // Check account lockout
    const lockedUntil = await loginEventService.checkLockout(user.id);
    if (lockedUntil) {
      const meta = await collectRequestMetadata(request);
      await loginEventService.record(user.id, false, 'EMAIL', meta);
      return reply.status(429).send({
        statusCode: 429,
        error: 'Too Many Requests',
        message: `Account temporarily locked. Try again after ${lockedUntil.toISOString()}.`,
      });
    }

    const passwordValid = await verifyPassword(body.password, user.passwordHash);

    if (!passwordValid) {
      const meta = await collectRequestMetadata(request);
      await loginEventService.record(user.id, false, 'EMAIL', meta);
      const lockResult = await loginEventService.recordFailedAttempt(user.id);

      if (lockResult.locked) {
        return reply.status(429).send({
          statusCode: 429,
          error: 'Too Many Requests',
          message: `Too many failed attempts. Account locked for ${ACCOUNT_LOCKOUT_MINUTES} minutes.`,
        });
      }

      return reply.status(401).send({ statusCode: 401, error: 'Unauthorized', message: 'Invalid credentials' });
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

    const meta = await collectRequestMetadata(request);
    await loginEventService.resetFailedAttempts(user.id);
    await loginEventService.record(user.id, true, 'EMAIL', meta);

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

    sendPasswordResetEmail(email, rawToken).catch((err) => {
      fastify.log.error({ err, email }, 'Failed to send password reset email');
    });

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

  // -----------------------------------------------------------------------
  // OAuth — GET /oauth/:provider (redirect to provider)
  // -----------------------------------------------------------------------
  fastify.get('/oauth/:provider', async (request, reply) => {
    const { provider } = request.params as { provider: string };
    const query = request.query as { returnTo?: string; authSessionToken?: string };

    const enabledProviders = getEnabledProviderNames();
    if (!enabledProviders.includes(provider)) {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: `OAuth provider "${provider}" is not configured. Enabled: ${enabledProviders.join(', ') || 'none'}`,
      });
    }

    const baseUrl = process.env.WEBAUTHN_ORIGIN || `http://localhost:${config.server.port}`;
    const callbackUrl = `${baseUrl}/api/v1/auth/oauth/${provider}/callback`;

    // Encode returnTo and authSessionToken in state for CSRF protection + context passing
    const statePayload = JSON.stringify({
      csrf: generateOAuthState(),
      returnTo: query.returnTo || '',
      authSessionToken: query.authSessionToken || '',
    });
    const state = Buffer.from(statePayload).toString('base64url');

    // Store state in cache for verification (5 min TTL)
    await cacheSet(`oauth_state:${state}`, { valid: true }, 300);

    const authUrl = buildAuthUrl(provider, callbackUrl, state);
    return reply.redirect(authUrl);
  });

  // -----------------------------------------------------------------------
  // OAuth — GET+POST /oauth/:provider/callback (handle code exchange)
  // Apple uses POST with form_post response_mode; others use GET.
  // -----------------------------------------------------------------------
  const oauthCallbackHandler = async (request: import('fastify').FastifyRequest, reply: import('fastify').FastifyReply) => {
    const { provider } = request.params as { provider: string };
    // Apple sends code/state in POST body; others in query string
    const query = request.query as Record<string, string | undefined>;
    const body = (request.body as Record<string, string | undefined>) || {};
    const code = query.code || body.code;
    const state = query.state || body.state;

    if (!code || !state) {
      return reply.status(400).send({ statusCode: 400, error: 'Bad Request', message: 'Missing code or state' });
    }

    // Verify state to prevent CSRF
    const cachedState = await cacheGet(`oauth_state:${state}`);
    if (!cachedState) {
      return reply.status(400).send({ statusCode: 400, error: 'Bad Request', message: 'Invalid or expired OAuth state' });
    }
    await cacheDel(`oauth_state:${state}`);

    // Decode state payload
    let returnTo = '';
    let authSessionToken = '';
    try {
      const payload = JSON.parse(Buffer.from(state, 'base64url').toString());
      returnTo = payload.returnTo || '';
      authSessionToken = payload.authSessionToken || '';
    } catch {}

    const baseUrl = process.env.WEBAUTHN_ORIGIN || `http://localhost:${config.server.port}`;
    const callbackUrl = `${baseUrl}/api/v1/auth/oauth/${provider}/callback`;

    try {
      // Exchange code for user info
      const oauthUser = await exchangeCodeForUser(provider, code, callbackUrl);

      if (!oauthUser.email) {
        return reply.status(400).send({ statusCode: 400, error: 'Bad Request', message: 'Email not available from OAuth provider. Please grant email access.' });
      }

      // Find existing user by providerId or email
      let user = await fastify.prisma.user.findFirst({
        where: {
          OR: [
            { providerId: oauthUser.providerId, provider: provider.toUpperCase() as any },
            { email: oauthUser.email },
          ],
        },
        include: {
          memberships: {
            include: { organization: { select: { id: true, name: true, slug: true } } },
            orderBy: { joinedAt: 'desc' },
          },
        },
      });

      if (user) {
        // Link OAuth provider if user found by email but different provider
        if (!user.providerId || user.provider === 'EMAIL') {
          await fastify.prisma.user.update({
            where: { id: user.id },
            data: {
              provider: provider.toUpperCase() as any,
              providerId: oauthUser.providerId,
              avatarUrl: oauthUser.avatarUrl || user.avatarUrl,
              emailVerified: true, // OAuth emails are pre-verified
            },
          });
        }

        // Update lastLoginAt
        await fastify.prisma.user.update({
          where: { id: user.id },
          data: { lastLoginAt: new Date(), failedLoginAttempts: 0, lockedUntil: null },
        });
      } else {
        // Create new user + default organization
        const slug = oauthUser.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'my-org';
        const existingSlug = await fastify.prisma.organization.findUnique({ where: { slug } });
        const finalSlug = existingSlug ? `${slug}-${randomBytes(2).toString('hex')}` : slug;

        const result = await fastify.prisma.$transaction(async (tx) => {
          const newUser = await tx.user.create({
            data: {
              name: oauthUser.name,
              email: oauthUser.email,
              passwordHash: '', // No password for OAuth users
              provider: provider.toUpperCase() as any,
              providerId: oauthUser.providerId,
              avatarUrl: oauthUser.avatarUrl,
              emailVerified: true,
            },
          });

          const org = await tx.organization.create({
            data: {
              name: `${oauthUser.name}'s Organization`,
              slug: finalSlug,
              email: oauthUser.email,
            },
          });

          await tx.membership.create({
            data: {
              userId: newUser.id,
              organizationId: org.id,
              role: 'OWNER',
            },
          });

          return { user: newUser, org, membership: null as any };
        });

        // Reload user with memberships
        user = await fastify.prisma.user.findUnique({
          where: { id: result.user.id },
          include: {
            memberships: {
              include: { organization: { select: { id: true, name: true, slug: true } } },
              orderBy: { joinedAt: 'desc' },
            },
          },
        });
      }

      if (!user || user.memberships.length === 0) {
        return reply.status(500).send({ statusCode: 500, error: 'Internal Server Error', message: 'Failed to set up user account' });
      }

      const activeMembership = user.memberships[0];

      // Sign JWT
      const token = fastify.jwt.sign({
        userId: user.id,
        orgId: activeMembership.organizationId,
        role: activeMembership.role,
        email: user.email,
      });

      // If this OAuth flow was triggered from an auth session approval page,
      // store the JWT and redirect back to the approval page
      if (authSessionToken) {
        // Redirect to approval page with JWT passed via fragment (never sent to server)
        return reply.redirect(`${baseUrl}/a/${authSessionToken}#jwt=${token}`);
      }

      // For normal sign-in, redirect to dashboard with JWT in fragment
      const redirectTarget = returnTo || '/dashboard';
      return reply.redirect(`${baseUrl}${redirectTarget}#jwt=${token}`);

    } catch (err: any) {
      fastify.log.error({ err, provider }, 'OAuth callback failed');
      return reply.status(500).send({
        statusCode: 500,
        error: 'OAuth Error',
        message: err.message || 'Authentication failed',
      });
    }
  };

  fastify.get('/oauth/:provider/callback', oauthCallbackHandler);
  fastify.post('/oauth/:provider/callback', oauthCallbackHandler);

  // -----------------------------------------------------------------------
  // GET /providers — List enabled OAuth providers (public)
  // -----------------------------------------------------------------------
  fastify.get('/providers', async (_request, reply) => {
    const providers = getEnabledProviderNames();
    return reply.send({ providers });
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

  // -------------------------------------------------------------------------
  // GET /login-history — Recent login events for the current user
  // -------------------------------------------------------------------------

  fastify.get('/login-history', {
    preHandler: [authenticate],
  }, async (request, reply) => {
    const events = await loginEventService.getHistory(request.user!.id, 50);
    return reply.send({ data: events });
  });
}
