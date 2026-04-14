import type { FastifyInstance } from 'fastify';
import { zodValidator } from '../middleware/validate.js';
import { rateLimitAuth, rateLimitSensitive } from '../middleware/rateLimit.js';
import { WebAuthnService } from '../services/webauthn.js';
import { DeviceService } from '../services/device.js';
import { LoginEventService } from '../services/login-event.js';
import { collectRequestMetadata } from '../lib/metadata.js';
import { registerPasskeySchema, updatePasskeySchema } from '@qrauth/shared';
import {
  createRefreshToken,
  REFRESH_COOKIE_NAME,
  getRefreshCookieOptions,
} from '../lib/refresh-token.js';

export default async function webauthnRoutes(fastify: FastifyInstance): Promise<void> {
  const authenticate = fastify.authenticate;
  const webauthnService = new WebAuthnService(fastify.prisma);
  const deviceService = new DeviceService(fastify.prisma);
  const loginEventService = new LoginEventService(fastify.prisma);

  // =========================================================================
  // REGISTRATION (authenticated — adding passkeys to account)
  // =========================================================================

  // -------------------------------------------------------------------------
  // POST /register/options — Generate registration challenge
  // -------------------------------------------------------------------------

  fastify.post('/register/options', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate],
  }, async (request, reply) => {
    const options = await webauthnService.generateRegistrationOpts(request.user!.id);
    return reply.send(options);
  });

  // -------------------------------------------------------------------------
  // POST /register/verify — Verify registration and store passkey
  // -------------------------------------------------------------------------

  fastify.post('/register/verify', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate],
  }, async (request, reply) => {
    const body = request.body as {
      credential: any;
      name?: string;
    };

    // Optionally link to the current device
    const meta = await collectRequestMetadata(request);
    const { device } = await deviceService.identifyDevice(request.user!.id, meta);

    try {
      const { passkey, credentialDeviceType, bridge } = await webauthnService.verifyRegistration(
        request.user!.id,
        body.credential,
        body.name,
        device?.id,
      );

      // The bridge private key is returned exactly once — the client must
      // persist it to IndexedDB before the response is consumed. The
      // server holds no copy. If the client misses this response (network
      // glitch, page refresh during registration), the user will need to
      // re-register the passkey to recreate the bridge half.
      return reply.status(201).send({
        passkey: {
          id: passkey.id,
          name: passkey.name,
          credentialId: passkey.credentialId,
          createdAt: passkey.createdAt,
        },
        credentialDeviceType,
        bridge,
      });
    } catch (err: any) {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: err.message,
      });
    }
  });

  // =========================================================================
  // AUTHENTICATION (public — sign in with passkey)
  // =========================================================================

  // -------------------------------------------------------------------------
  // POST /authenticate/options — Generate authentication challenge
  // -------------------------------------------------------------------------

  fastify.post('/authenticate/options', {
    config: { rateLimit: rateLimitSensitive },
  }, async (request, reply) => {
    const body = request.body as { email?: string };

    let userId: string | undefined;

    if (body.email) {
      const user = await fastify.prisma.user.findUnique({
        where: { email: body.email },
        select: { id: true },
      });

      if (!user) {
        // Don't reveal whether the email exists
        return reply.status(400).send({
          statusCode: 400,
          error: 'Bad Request',
          message: 'No passkeys registered for this account.',
        });
      }

      userId = user.id;
    }

    try {
      const { options, challengeKey } = await webauthnService.generateAuthenticationOpts(userId);
      return reply.send({ options, challengeKey });
    } catch (err: any) {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: err.message,
      });
    }
  });

  // -------------------------------------------------------------------------
  // POST /authenticate/verify — Verify authentication and issue JWT
  // -------------------------------------------------------------------------

  fastify.post('/authenticate/verify', {
    config: { rateLimit: rateLimitSensitive },
  }, async (request, reply) => {
    const body = request.body as {
      credential: any;
      challengeKey: string;
      bridgeSignature?: string;
    };

    try {
      const { user } = await webauthnService.verifyAuthentication(
        body.credential,
        body.challengeKey,
        body.bridgeSignature,
      );

      // Check lockout
      const lockedUntil = await loginEventService.checkLockout(user.id);
      if (lockedUntil) {
        return reply.status(429).send({
          statusCode: 429,
          error: 'Too Many Requests',
          message: 'Account temporarily locked. Please try again later.',
        });
      }

      // Get memberships
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

      // Issue JWT
      const token = fastify.jwt.sign({
        userId: user.id,
        orgId: activeMembership.organizationId,
        role: activeMembership.role,
        email: user.email,
      });

      // Issue refresh token
      const refresh = await createRefreshToken(fastify.prisma, user.id);
      reply.setCookie(REFRESH_COOKIE_NAME, refresh.rawToken, getRefreshCookieOptions(refresh.expiresAt));

      // Record login event + device (non-blocking — don't let this fail the auth)
      const meta = await collectRequestMetadata(request);
      let device: Awaited<ReturnType<typeof deviceService.identifyDevice>>['device'] = null;
      try {
        await loginEventService.resetFailedAttempts(user.id);
        await loginEventService.record(user.id, true, 'PASSKEY', meta);
        ({ device } = await deviceService.identifyDevice(user.id, meta));
      } catch (err) {
        fastify.log.warn({ err, userId: user.id }, 'Failed to record passkey login event');
      }

      // Update last login
      fastify.prisma.user.update({
        where: { id: user.id },
        data: { lastLoginAt: new Date() },
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
        device: device ? {
          id: device.id,
          trustLevel: device.trustLevel,
        } : undefined,
      });
    } catch (err: any) {
      return reply.status(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        message: err.message,
      });
    }
  });

  // =========================================================================
  // PASSKEY MANAGEMENT (authenticated)
  // =========================================================================

  // -------------------------------------------------------------------------
  // GET /passkeys — List user's passkeys
  // -------------------------------------------------------------------------

  fastify.get('/passkeys', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate],
  }, async (request, reply) => {
    const passkeys = await webauthnService.listPasskeys(request.user!.id);
    return reply.send({ data: passkeys });
  });

  // -------------------------------------------------------------------------
  // PATCH /passkeys/:id — Rename a passkey
  // -------------------------------------------------------------------------

  fastify.patch('/passkeys/:id', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate],
    preValidation: zodValidator({ body: updatePasskeySchema }),
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const { name } = request.body as { name: string };

    const passkey = await webauthnService.updatePasskey(id, request.user!.id, name);

    if (!passkey) {
      return reply.status(404).send({
        statusCode: 404,
        error: 'Not Found',
        message: 'Passkey not found.',
      });
    }

    return reply.send({ passkey });
  });

  // -------------------------------------------------------------------------
  // DELETE /passkeys/:id — Revoke a passkey
  // -------------------------------------------------------------------------

  fastify.delete('/passkeys/:id', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };

    const result = await webauthnService.revokePasskey(id, request.user!.id);

    if (!result) {
      return reply.status(404).send({
        statusCode: 404,
        error: 'Not Found',
        message: 'Passkey not found.',
      });
    }

    return reply.send({ message: 'Passkey revoked.' });
  });
}
