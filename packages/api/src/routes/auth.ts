import type { FastifyInstance } from 'fastify';
import { randomBytes } from 'node:crypto';
import { zodValidator } from '../middleware/validate.js';
import { rateLimitSensitive, rateLimitPublic, rateLimitAuth } from '../middleware/rateLimit.js';
import { hashPassword, verifyPassword } from '../lib/password.js';
import { hashString } from '../lib/crypto.js';
import { isAdminEmail } from '../lib/admin.js';
import { sendPasswordResetEmail, sendWelcomeVerificationEmail, sendPasswordChangedEmail, sendSuspiciousLoginEmail } from '../lib/email.js';
import {
  signupSchema,
  loginSchema,
  switchOrgSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  resendVerificationSchema,
  onboardingCompleteSchema,
  ACCOUNT_LOCKOUT_MINUTES,
} from '@qrauth/shared';
import { getEnabledProviderNames, buildAuthUrl, exchangeCodeForUser, generateOAuthState } from '../lib/oauth.js';
import { cacheSet, cacheGet, cacheDel } from '../lib/cache.js';
import { config } from '../lib/config.js';
import { collectRequestMetadata } from '../lib/metadata.js';
import { LoginEventService } from '../services/login-event.js';
import { DeviceService } from '../services/device.js';
import { AuditLogService } from '../services/audit.js';
import {
  createRefreshToken,
  rotateRefreshToken,
  revokeTokenFamily,
  revokeAllUserTokens,
  REFRESH_COOKIE_NAME,
  getRefreshCookieOptions,
  getClearCookieOptions,
} from '../lib/refresh-token.js';

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

export default async function authRoutes(fastify: FastifyInstance): Promise<void> {
  const signingService = fastify.signingService;
  const authenticate = fastify.authenticate;
  const loginEventService = new LoginEventService(fastify.prisma);
  const deviceService = new DeviceService(fastify.prisma);
  const auditService = new AuditLogService(fastify.prisma);

  // -------------------------------------------------------------------------
  // POST /signup — Create user + org
  // -------------------------------------------------------------------------

  fastify.post('/signup', {
    config: { rateLimit: rateLimitSensitive },
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
      // Return generic error to prevent email enumeration.
      // Don't reveal that the email is already registered.
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: 'Unable to create account. Please try a different email or sign in.',
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
    // User is created with emailVerified=false and cannot sign in until
    // they click the verification link (see POST /login below).
    const { user, org } = await fastify.prisma.$transaction(async (tx) => {
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

      await tx.membership.create({
        data: {
          userId: user.id,
          organizationId: org.id,
          role: 'OWNER',
        },
      });

      return { user, org };
    });

    // Generate the first signing key pair for the new organization.
    await signingService.createKeyPair(org.id);

    // Fire the welcome + verification email. Still awaited-via-catch so we
    // log failures but don't block the 202 response on slow SMTP.
    sendWelcomeVerificationEmail(user.email, user.name, org.name, emailVerifyToken).catch((err) => {
      fastify.log.error({ err, email: user.email }, 'Failed to send welcome email');
    });

    // 202 Accepted: account created, but access is pending email verification.
    // We intentionally do NOT issue a JWT, set a refresh cookie, or register a
    // device here — the user has to prove they own the mailbox first.
    return reply.status(202).send({
      message: 'Account created. Check your email to verify your address and sign in.',
      email: user.email,
      requiresVerification: true,
    });
  });

  // -------------------------------------------------------------------------
  // POST /login
  // -------------------------------------------------------------------------

  fastify.post('/login', {
    config: { rateLimit: rateLimitSensitive },
    preValidation: zodValidator({ body: loginSchema }),
  }, async (request, reply) => {
    const body = request.body as { email: string; password: string };

    const user = await fastify.prisma.user.findUnique({
      where: { email: body.email },
    });

    // Always run password verification to prevent timing-based email enumeration.
    // For non-existent users we hash against a dummy value so the response time
    // is indistinguishable from a real password check.
    const dummyHash = 'a'.repeat(32) + ':' + 'b'.repeat(128);
    const passwordValid = await verifyPassword(body.password, user?.passwordHash || dummyHash);

    if (!user || !passwordValid) {
      if (user) {
        // Only record failed attempt + lockout for real users
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
      }

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
        message: 'Account temporarily locked. Please try again later.',
      });
    }

    // Block unverified accounts. The frontend looks at `error` to show a
    // resend-verification prompt and pre-fills the email from the payload.
    if (!user.emailVerified) {
      return reply.status(403).send({
        statusCode: 403,
        error: 'EmailNotVerified',
        message: 'Please verify your email address to sign in. Check your inbox or request a new verification link.',
        email: user.email,
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

    // Issue refresh token cookie
    const refresh = await createRefreshToken(fastify.prisma, user.id);
    reply.setCookie(REFRESH_COOKIE_NAME, refresh.rawToken, getRefreshCookieOptions(refresh.expiresAt));

    const meta = await collectRequestMetadata(request);
    await loginEventService.resetFailedAttempts(user.id);
    await loginEventService.record(user.id, true, 'EMAIL', meta);

    // Register/update the login device
    const { device: loginDevice, isNew: isNewDevice } = await deviceService.identifyDevice(user.id, meta);

    // Suspicious login check (non-blocking) — also check device trust
    loginEventService.isSuspiciousLogin(user.id, meta).then((suspicious) => {
      if (suspicious || (loginDevice?.revokedAt)) {
        sendSuspiciousLoginEmail(user.email, user.name || 'there', {
          country: meta.ipCountry,
          city: meta.ipCity,
          device: meta.deviceType,
          browser: meta.browser,
          os: meta.os,
          time: new Date().toISOString(),
        }).catch((err) => {
          fastify.log.error({ err, userId: user.id }, 'Failed to send suspicious login email');
        });
      }
    }).catch(() => {});

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
      device: loginDevice ? {
        id: loginDevice.id,
        trustLevel: loginDevice.trustLevel,
        isNew: isNewDevice,
      } : undefined,
    });
  });

  // -------------------------------------------------------------------------
  // POST /switch-org — Exchange JWT for a new org context (authenticated)
  // -------------------------------------------------------------------------

  fastify.post('/switch-org', {
    config: { rateLimit: rateLimitAuth },
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

    // Issue new refresh token cookie for the new org context
    const refresh = await createRefreshToken(fastify.prisma, request.user!.id);
    reply.setCookie(REFRESH_COOKIE_NAME, refresh.rawToken, getRefreshCookieOptions(refresh.expiresAt));

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
    config: { rateLimit: rateLimitSensitive },
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
    config: { rateLimit: rateLimitSensitive },
    preValidation: zodValidator({ body: resetPasswordSchema }),
  }, async (request, reply) => {
    const { token, password } = request.body as { token: string; password: string };

    const hashedToken = hashString(token);

    const user = await fastify.prisma.user.findFirst({
      where: {
        passwordResetToken: hashedToken,
        passwordResetExpires: { gt: new Date() },
      },
      select: { id: true, email: true, name: true },
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

    // Revoke all refresh tokens on password change
    await revokeAllUserTokens(fastify.prisma, user.id);

    // Audit: password change is a sensitive operation
    const membership = await fastify.prisma.membership.findFirst({
      where: { userId: user.id },
      select: { organizationId: true },
    });
    if (membership) {
      await auditService.log({
        organizationId: membership.organizationId,
        userId: user.id,
        action: 'user.password_reset',
        resource: 'User',
        resourceId: user.id,
      });
    }

    if (user.email) {
      sendPasswordChangedEmail(user.email, user.name || 'there').catch((err) => {
        fastify.log.error({ err, userId: user.id }, 'Failed to send password changed email');
      });
    }

    return reply.send({ message: 'Password reset successful.' });
  });

  // -------------------------------------------------------------------------
  // GET /verify-email/:token
  // -------------------------------------------------------------------------
  //
  // Hit directly by the browser when the user clicks the link in the welcome
  // email. On success or failure we redirect to a frontend landing page so
  // the user sees a polished UI instead of a raw JSON blob. Clients that
  // need the JSON response (tests, SDKs) can send `Accept: application/json`.

  fastify.get('/verify-email/:token', { config: { rateLimit: rateLimitPublic } }, async (request, reply) => {
    const { token } = request.params as { token: string };
    const wantsJson = (request.headers.accept || '').includes('application/json');
    const landingBase = process.env.WEBAUTHN_ORIGIN || `http://localhost:${config.server.port}`;
    const landing = (status: 'success' | 'invalid') => `${landingBase}/auth/jwt/verify-email?status=${status}`;

    const user = await fastify.prisma.user.findUnique({
      where: { emailVerifyToken: token },
      select: { id: true, emailVerified: true },
    });

    if (!user) {
      if (wantsJson) {
        return reply.status(400).send({
          statusCode: 400,
          error: 'Bad Request',
          message: 'Invalid or expired verification token.',
        });
      }
      return reply.redirect(landing('invalid'));
    }

    if (!user.emailVerified) {
      await fastify.prisma.user.update({
        where: { id: user.id },
        data: {
          emailVerified: true,
          emailVerifyToken: null,
        },
      });
    }

    if (wantsJson) {
      return reply.send({ message: 'Email verified successfully.' });
    }
    return reply.redirect(landing('success'));
  });

  // -------------------------------------------------------------------------
  // POST /resend-verification
  // -------------------------------------------------------------------------
  //
  // Resend the welcome + verification email to an unverified user. Rate-limited
  // and enumeration-safe: the response is always 200 with the same generic
  // message regardless of whether the email exists, is already verified, or
  // actually triggered a send. This prevents attackers from probing which
  // addresses have accounts.
  fastify.post('/resend-verification', {
    config: { rateLimit: rateLimitSensitive },
    preValidation: zodValidator({ body: resendVerificationSchema }),
  }, async (request, reply) => {
    const body = request.body as { email: string };

    const genericResponse = {
      message: 'If an unverified account exists for that email, a new verification link has been sent.',
    };

    const user = await fastify.prisma.user.findUnique({
      where: { email: body.email },
      include: {
        memberships: {
          include: { organization: true },
          orderBy: { joinedAt: 'asc' },
          take: 1,
        },
      },
    });

    // Silent no-op for non-existent users and already-verified accounts.
    if (!user || user.emailVerified || !user.memberships[0]) {
      return reply.send(genericResponse);
    }

    // Rotate the token so any previous link is invalidated.
    const newToken = randomBytes(32).toString('hex');
    await fastify.prisma.user.update({
      where: { id: user.id },
      data: { emailVerifyToken: newToken },
    });

    const orgName = user.memberships[0].organization.name;
    sendWelcomeVerificationEmail(user.email, user.name, orgName, newToken).catch((err) => {
      fastify.log.error({ err, email: user.email }, 'Failed to resend verification email');
    });

    return reply.send(genericResponse);
  });

  // -------------------------------------------------------------------------
  // POST /_test/mark-verified (DEV/TEST ONLY)
  // -------------------------------------------------------------------------
  //
  // E2E tests sign up real users and need them verified without an inbox
  // roundtrip. This endpoint is only mounted when NODE_ENV !== 'production'
  // so it cannot exist on the prod server. Kept intentionally minimal —
  // takes {email}, flips the flag, no auth.
  if (!config.server.isProd) {
    fastify.post('/_test/mark-verified', {
      config: { rateLimit: rateLimitPublic },
    }, async (request, reply) => {
      const body = request.body as { email?: string };
      if (!body?.email) {
        return reply.status(400).send({ error: 'email required' });
      }
      const updated = await fastify.prisma.user.updateMany({
        where: { email: body.email },
        data: { emailVerified: true, emailVerifyToken: null },
      });
      return reply.send({ verified: updated.count });
    });
  }

  // -----------------------------------------------------------------------
  // OAuth — GET /oauth/:provider (redirect to provider)
  // -----------------------------------------------------------------------
  fastify.get('/oauth/:provider', { config: { rateLimit: rateLimitPublic } }, async (request, reply) => {
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
      // Validate payload structure
      if (typeof payload === 'object' && payload !== null) {
        returnTo = typeof payload.returnTo === 'string' ? payload.returnTo : '';
        authSessionToken = typeof payload.authSessionToken === 'string' ? payload.authSessionToken : '';
      }
      // Validate returnTo against allowed prefixes (prevent open redirect)
      const allowedRedirects = ['/dashboard', '/onboarding', '/settings', '/'];
      if (returnTo && !allowedRedirects.some((p) => returnTo === p || returnTo.startsWith(p + '/'))) {
        returnTo = '/dashboard';
      }
    } catch {
      // Invalid state — continue with empty values
    }

    const baseUrl = process.env.WEBAUTHN_ORIGIN || `http://localhost:${config.server.port}`;
    const callbackUrl = `${baseUrl}/api/v1/auth/oauth/${provider}/callback`;

    try {
      // Exchange code for user info
      const oauthUser = await exchangeCodeForUser(provider, code, callbackUrl);

      if (!oauthUser.email) {
        return reply.status(400).send({ statusCode: 400, error: 'Bad Request', message: 'Email not available from OAuth provider. Please grant email access.' });
      }

      // Find existing user by providerId or email
      let isNewUser = false;
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
        // Check account lockout — OAuth should NOT bypass it
        if (user.lockedUntil && user.lockedUntil > new Date()) {
          return reply.status(429).send({
            statusCode: 429,
            error: 'Too Many Requests',
            message: 'Account temporarily locked. Please try again later.',
          });
        }

        // Update avatar + verify email, but DON'T overwrite provider/providerId
        // so the user can sign in via any OAuth provider that matches their email
        // Note: do NOT reset failedLoginAttempts or lockedUntil here
        await fastify.prisma.user.update({
          where: { id: user.id },
          data: {
            avatarUrl: oauthUser.avatarUrl || user.avatarUrl || undefined,
            emailVerified: true,
            lastLoginAt: new Date(),
            // Only set provider if user was email-only (first OAuth link)
            ...(!user.providerId ? {
              provider: provider.toUpperCase() as any,
              providerId: oauthUser.providerId,
            } : {}),
          },
        });

        // Reload memberships after update
        user = await fastify.prisma.user.findUnique({
          where: { id: user.id },
          include: {
            memberships: {
              include: { organization: { select: { id: true, name: true, slug: true } } },
              orderBy: { joinedAt: 'desc' },
            },
          },
        });
      } else {
        isNewUser = true;
        // Create new user + default organization
        // Use the user's name for the org, cleaned up
        const orgName = `${oauthUser.name}'s Organization`;
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
              name: orgName,
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

        // Auto-create signing key for the new org
        const signingService = fastify.signingService;
        await signingService.createKeyPair(result.org.id).catch(() => {});

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

      // Issue refresh token cookie
      const refresh = await createRefreshToken(fastify.prisma, user.id);
      reply.setCookie(REFRESH_COOKIE_NAME, refresh.rawToken, getRefreshCookieOptions(refresh.expiresAt));

      // If this OAuth flow was triggered from an auth session approval page,
      // store the JWT and redirect back to the approval page
      if (authSessionToken) {
        // Redirect to approval page with JWT passed via fragment (never sent to server)
        return reply.redirect(`${baseUrl}/a/${authSessionToken}#jwt=${token}`);
      }

      // For normal sign-in, redirect to dashboard with JWT in fragment
      const redirectTarget = returnTo || (isNewUser ? '/onboarding' : '/dashboard');
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

  fastify.get('/oauth/:provider/callback', { config: { rateLimit: rateLimitPublic } }, oauthCallbackHandler);
  fastify.post('/oauth/:provider/callback', { config: { rateLimit: rateLimitPublic } }, oauthCallbackHandler);

  // -----------------------------------------------------------------------
  // GET /providers — List enabled OAuth providers (public)
  // -----------------------------------------------------------------------
  fastify.get('/providers', { config: { rateLimit: rateLimitPublic } }, async (_request, reply) => {
    const providers = getEnabledProviderNames();
    return reply.send({ providers });
  });

  // -------------------------------------------------------------------------
  // GET /me — Current user profile (authenticated)
  // -------------------------------------------------------------------------

  fastify.get('/me', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate],
  }, async (request, reply) => {
    const user = await fastify.prisma.user.findUnique({
      where: { id: request.user!.id },
      select: {
        id: true,
        name: true,
        email: true,
        emailVerified: true,
        onboardedAt: true,
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
        onboardedAt: user.onboardedAt,
        role: activeMembership?.role ?? null,
        isSuperAdmin: isAdminEmail(user.email),
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

  // -----------------------------------------------------------------------
  // POST /onboarding/complete — Finish onboarding (set org name + use case)
  // -----------------------------------------------------------------------
  fastify.post('/onboarding/complete', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate],
    preValidation: zodValidator({ body: onboardingCompleteSchema }),
  }, async (request, reply) => {
    const { organizationName, useCase } = request.body as { organizationName: string; useCase: string };
    const userId = request.user!.id;
    const orgId = request.user!.orgId;

    // Map use case to trust level
    const trustLevelMap: Record<string, string> = {
      MUNICIPALITY: 'GOVERNMENT',
      PARKING: 'GOVERNMENT',
      FINANCE: 'BUSINESS',
      RESTAURANT: 'BUSINESS',
      DEVELOPER: 'INDIVIDUAL',
      OTHER: 'INDIVIDUAL',
    };
    const trustLevel = trustLevelMap[useCase] || 'INDIVIDUAL';

    // Generate slug from org name
    const baseSlug = organizationName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
    const existingSlug = await fastify.prisma.organization.findFirst({
      where: { slug: baseSlug, id: { not: orgId } },
    });
    const slug = existingSlug ? `${baseSlug}-${randomBytes(2).toString('hex')}` : baseSlug;

    // Update org
    await fastify.prisma.organization.update({
      where: { id: orgId },
      data: {
        name: organizationName,
        slug,
        trustLevel: trustLevel as any,
      },
    });

    // Auto-create signing key if org doesn't have one
    const existingKey = await fastify.prisma.signingKey.findFirst({
      where: { organizationId: orgId, status: 'ACTIVE' },
    });
    if (!existingKey) {
      const signingService = fastify.signingService;
      await signingService.createKeyPair(orgId);
    }

    // Mark user as onboarded
    await fastify.prisma.user.update({
      where: { id: userId },
      data: { onboardedAt: new Date() },
    });

    return reply.send({ success: true });
  });

  // -------------------------------------------------------------------------
  // GET /login-history — Recent login events for the current user
  // -------------------------------------------------------------------------

  fastify.get('/login-history', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate],
  }, async (request, reply) => {
    const events = await loginEventService.getHistory(request.user!.id, 50);
    return reply.send({ data: events });
  });

  // -------------------------------------------------------------------------
  // POST /refresh — Exchange refresh token cookie for a new access token
  // -------------------------------------------------------------------------

  fastify.post('/refresh', {
    config: { rateLimit: rateLimitSensitive },
  }, async (request, reply) => {
    const rawToken = request.cookies?.[REFRESH_COOKIE_NAME];

    if (!rawToken) {
      return reply.status(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        message: 'No refresh token provided.',
      });
    }

    const result = await rotateRefreshToken(fastify.prisma, rawToken);

    if (!result) {
      // Clear the invalid cookie
      reply.clearCookie(REFRESH_COOKIE_NAME, getClearCookieOptions());
      return reply.status(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        message: 'Invalid or expired refresh token.',
      });
    }

    // Look up user + active membership to build the new access token
    const user = await fastify.prisma.user.findUnique({
      where: { id: result.userId },
      include: {
        memberships: {
          include: { organization: true },
          orderBy: { joinedAt: 'desc' },
        },
      },
    });

    if (!user || user.memberships.length === 0) {
      reply.clearCookie(REFRESH_COOKIE_NAME, getClearCookieOptions());
      return reply.status(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        message: 'User not found or has no organization.',
      });
    }

    const activeMembership = user.memberships[0];

    const token = fastify.jwt.sign({
      userId: user.id,
      orgId: activeMembership.organizationId,
      role: activeMembership.role,
      email: user.email,
    });

    // Set rotated refresh cookie
    reply.setCookie(REFRESH_COOKIE_NAME, result.rawToken, getRefreshCookieOptions(result.expiresAt));

    return reply.send({ token });
  });

  // -------------------------------------------------------------------------
  // POST /logout — Revoke refresh token family + clear cookie
  // -------------------------------------------------------------------------

  fastify.post('/logout', {
    config: { rateLimit: rateLimitAuth },
  }, async (request, reply) => {
    const rawToken = request.cookies?.[REFRESH_COOKIE_NAME];

    if (rawToken) {
      await revokeTokenFamily(fastify.prisma, rawToken);
    }

    reply.clearCookie(REFRESH_COOKIE_NAME, getClearCookieOptions());
    return reply.send({ message: 'Logged out successfully.' });
  });
}
