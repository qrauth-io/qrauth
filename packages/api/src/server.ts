// Side-effect import: hard-fails the process if Node is older than the
// minimum we support. MUST be the first import so it runs before any
// crypto/PQC code paths can crash with a less obvious error.
import './lib/node-version-check.js';

import Fastify, { type FastifyError, type FastifyInstance } from 'fastify';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { config } from './lib/config.js';
import { db, disconnectDb } from './lib/db.js';
import { redis, disconnectCache } from './lib/cache.js';
import { closeQueues } from './lib/queue.js';
import { classifyStaticPath, cacheControlFor } from './lib/static-cache.js';

// Middleware plugins
import { authMiddleware } from './middleware/auth.js';
import ecdsaSignerPlugin from './plugins/ecdsa-signer.js';
import batchSignerPlugin from './plugins/batch-signer.js';
import macSignerPlugin from './plugins/mac-signer.js';
import { rateLimitMiddleware } from './middleware/rateLimit.js';

// Route plugins
import authRoutes from './routes/auth.js';
import organizationRoutes from './routes/organizations.js';
import securityWebhookRoutes from './routes/organizations/security-webhook.js';
import appRoutes from './routes/apps.js';
import qrcodeRoutes from './routes/qrcodes.js';
import verifyRoutes from './routes/verify.js';
import analyticsRoutes from './routes/analytics.js';
import transparencyRoutes from './routes/transparency.js';
import authSessionRoutes from './routes/auth-sessions.js';
import ephemeralRoutes from './routes/ephemeral.js';
import proximityRoutes from './routes/proximity.js';
import animatedQRRoutes from './routes/animated-qr.js';
import approvalRoutes from './routes/approval.js';
import apiKeyRoutes from './routes/api-keys.js';
import usageRoutes from './routes/usage.js';
import webhookDeliveryRoutes from './routes/webhook-deliveries.js';
import billingRoutes from './routes/billing.js';
import adminRoutes from './routes/admin.js';
import deviceRoutes from './routes/devices.js';
import webauthnRoutes from './routes/webauthn.js';
import gdprRoutes from './routes/gdpr.js';
import sessionRoutes from './routes/sessions.js';
import demoRoutes from './routes/demo.js';
import internalMacStatsRoutes from './routes/internal-mac-stats.js';

// Workers
import { registerWorkers, closeWorkers } from './workers/index.js';

// ---------------------------------------------------------------------------
// Server factory (exported for testing)
// ---------------------------------------------------------------------------

export async function buildServer(): Promise<FastifyInstance> {
  // -------------------------------------------------------------------------
  // 1. Create Fastify instance with structured pino logger.
  // -------------------------------------------------------------------------
  const app = Fastify({
    bodyLimit: 1048576, // 1MB — prevents oversized payloads
    logger: {
      level: config.server.isDev ? 'debug' : 'info',
      ...(config.server.isDev && {
        transport: {
          target: 'pino-pretty',
          options: {
            translateTime: 'HH:MM:ss Z',
            ignore: 'pid,hostname',
          },
        },
      }),
    },
    // Expose the raw body so webhook signature verification can read it.
    // Individual routes that need it should read request.rawBody.
    disableRequestLogging: false,
    trustProxy: true,
  });

  // -------------------------------------------------------------------------
  // 2. Global error handler — structured error responses + logging for all routes
  // -------------------------------------------------------------------------

  app.setErrorHandler((error: FastifyError, request, reply) => {
    const statusCode = error.statusCode ?? 500;
    const isServerError = statusCode >= 500;

    // Log server errors at error level, client errors at warn level.
    const logPayload = {
      err: error,
      req: {
        method: request.method,
        url: request.url,
        params: request.params,
        query: request.query,
        userId: request.user?.id,
        orgId: request.user?.orgId,
      },
    };

    if (isServerError) {
      request.log.error(logPayload, `${request.method} ${request.url} → ${statusCode}`);
    } else {
      request.log.warn(logPayload, `${request.method} ${request.url} → ${statusCode}`);
    }

    // Build response — never leak internal details in production.
    const response: Record<string, unknown> = {
      statusCode,
      error: error.name || 'Error',
      message: isServerError && !config.server.isDev
        ? 'Internal server error'
        : error.message,
    };

    // Include Zod / Fastify validation details when present.
    const errAsRecord = error as unknown as Record<string, unknown>;
    if (errAsRecord.validation) {
      response.message = 'Validation Error';
      response.details = errAsRecord.validation;
    }

    // Expose stack trace only in development.
    if (config.server.isDev && error.stack) {
      response.stack = error.stack;
    }

    return reply.status(statusCode).send(response);
  });

  // -------------------------------------------------------------------------
  // 3. Request / response lifecycle hooks for observability
  // -------------------------------------------------------------------------

  app.addHook('onRequest', (request, _reply, done) => {
    request.log.info(
      {
        method: request.method,
        url: request.url,
        orgId: request.user?.orgId,
      },
      `${request.method} ${request.url}`,
    );
    done();
  });

  app.addHook('onResponse', (request, reply, done) => {
    const elapsed = reply.elapsedTime;
    // Only log non-2xx responses and requests that took longer than 1 second,
    // to keep steady-state logs clean.
    if (reply.statusCode >= 400 || elapsed > 1000) {
      request.log.warn(
        {
          method: request.method,
          url: request.url,
          statusCode: reply.statusCode,
          responseTime: Math.round(elapsed),
          userId: request.user?.id,
          orgId: request.user?.orgId,
        },
        `${request.method} ${request.url} → ${reply.statusCode} (${Math.round(elapsed)}ms)`,
      );
    }
    done();
  });

  // -------------------------------------------------------------------------
  // 4. Security plugins
  // -------------------------------------------------------------------------

  // Parse application/x-www-form-urlencoded (needed for Apple OAuth form_post)
  app.addContentTypeParser('application/x-www-form-urlencoded', function (request, payload, done) {
    let body = '';
    payload.on('data', (chunk: Buffer) => { body += chunk.toString(); });
    payload.on('end', () => {
      done(null, Object.fromEntries(new URLSearchParams(body)));
    });
  });

  await app.register(import('@fastify/cors'), {
    origin: (config.server.isDev || config.server.isTest)
      ? true
      : (origin, cb) => {
          const allowed = [
            process.env.WEBAUTHN_ORIGIN || 'https://qrauth.io',
            process.env.DASHBOARD_URL || 'https://qrauth.io',
          ];
          // Allow requests with no origin (server-to-server, mobile apps)
          if (!origin || allowed.includes(origin)) {
            cb(null, true);
          } else {
            cb(null, false);
          }
        },
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  });

  await app.register(import('@fastify/helmet'), {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'https://api.qrserver.com'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
      },
    },
    strictTransportSecurity: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
    crossOriginResourcePolicy: false,
    crossOriginOpenerPolicy: false,
  });

  // Permissions-Policy: restrict powerful browser features (ISO 27001 A.14.1.2)
  app.addHook('onSend', (request, reply, _payload, done) => {
    reply.header(
      'Permissions-Policy',
      'camera=(), microphone=(), geolocation=(self), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()',
    );

    // Allow cross-origin loading of SDK files. Cache-Control on bundle
    // files is set by the @fastify/static setHeaders callback below so it
    // can distinguish versioned (immutable) from pointer (short TTL) paths.
    if (request.url.startsWith('/sdk/')) {
      reply.header('Cross-Origin-Resource-Policy', 'cross-origin');
      reply.header('Access-Control-Allow-Origin', '*');
    }
    done();
  });

  // -------------------------------------------------------------------------
  // 5. Sensible HTTP error helpers (reply.notFound(), reply.badRequest(), …)
  // -------------------------------------------------------------------------

  await app.register(import('@fastify/sensible'));

  // -------------------------------------------------------------------------
  // Cookie support (for refresh tokens)
  // -------------------------------------------------------------------------

  await app.register(import('@fastify/cookie'));

  // -------------------------------------------------------------------------
  // Static SDK files (/sdk/*)
  // -------------------------------------------------------------------------

  const staticRoot = join(dirname(fileURLToPath(import.meta.url)), '..', 'public');
  await app.register(import('@fastify/static'), {
    root: staticRoot,
    prefix: '/',
    decorateReply: false,
    // Two-tier cache-control on /sdk/v1/* — mirrors cdn.qrauth.io/v1/.
    // Versioned bundle paths get immutable + 1y. Pointer paths
    // (components.js, components.esm.js) get 60s + must-revalidate so
    // refreshes propagate to consumers within a minute.
    setHeaders: (res, filePath) => {
      const urlPath = '/' + filePath.slice(staticRoot.length).replace(/^\/+/, '');
      const cacheControl = cacheControlFor(classifyStaticPath(urlPath));
      if (cacheControl) {
        res.setHeader('Cache-Control', cacheControl);
        res.setHeader('Vary', 'Accept-Encoding');
      }
    },
  });

  // -------------------------------------------------------------------------
  // 6. Decorate the Fastify instance with shared singletons.
  //    These decorators must be registered before any plugin that reads them
  //    (e.g. authMiddleware accesses fastify.prisma).
  // -------------------------------------------------------------------------

  app.decorate('prisma', db);
  app.decorate('redis', redis);

  // -------------------------------------------------------------------------
  // 7. Auth & rate-limiting middleware
  //    Rate-limiting must be registered before routes so its onRoute hook
  //    fires for every registered route.
  // -------------------------------------------------------------------------

  await app.register(rateLimitMiddleware);
  await app.register(authMiddleware);
  await app.register(ecdsaSignerPlugin);
  await app.register(batchSignerPlugin);
  await app.register(macSignerPlugin);

  // -------------------------------------------------------------------------
  // 8. Route plugins
  // -------------------------------------------------------------------------

  await app.register(authRoutes, { prefix: '/api/v1/auth' });
  await app.register(organizationRoutes, { prefix: '/api/v1/organizations' });
  // AUDIT-2 M-13: register/rotate/unregister the org's security
  // webhook endpoint — separate file so the monolithic organizations
  // route module stays unchanged for this PR.
  await app.register(securityWebhookRoutes, { prefix: '/api/v1/organizations' });
  await app.register(appRoutes, { prefix: '/api/v1/apps' });
  await app.register(qrcodeRoutes, { prefix: '/api/v1/qrcodes' });

  // The verify endpoint is exposed on two paths:
  //   • /v/:token        – short public URL embedded in the QR code image
  //   • /api/v1/verify   – REST API path for programmatic verification
  await app.register(verifyRoutes, { prefix: '/v' });
  await app.register(verifyRoutes, { prefix: '/api/v1/verify' });

  await app.register(analyticsRoutes, { prefix: '/api/v1/analytics' });
  await app.register(transparencyRoutes, { prefix: '/api/v1/transparency' });

  await app.register(authSessionRoutes, { prefix: '/api/v1/auth-sessions' });
  await app.register(ephemeralRoutes, { prefix: '/api/v1/ephemeral' });
  await app.register(proximityRoutes, { prefix: '/api/v1/proximity' });
  await app.register(animatedQRRoutes, { prefix: '/api/v1/animated-qr' });
  await app.register(approvalRoutes, { prefix: '/a' });
  await app.register(apiKeyRoutes, { prefix: '/api/v1/api-keys' });
  await app.register(usageRoutes, { prefix: '/api/v1/usage' });
  await app.register(webhookDeliveryRoutes, { prefix: '/api/v1/webhook-deliveries' });
  await app.register(billingRoutes, { prefix: '/api/v1/billing' });
  await app.register(adminRoutes, { prefix: '/api/v1/admin' });
  await app.register(deviceRoutes, { prefix: '/api/v1/devices' });
  await app.register(webauthnRoutes, { prefix: '/api/v1/webauthn' });
  await app.register(gdprRoutes, { prefix: '/api/v1/account' });
  await app.register(sessionRoutes, { prefix: '/api/v1/sessions' });
  await app.register(demoRoutes, { prefix: '/api/v1/demo' });
  await app.register(internalMacStatsRoutes, { prefix: '/internal' });

  // -------------------------------------------------------------------------
  // 9. Health check
  // -------------------------------------------------------------------------

  app.get(
    '/health',
    {
      config: {
        // Health probes are called very frequently by orchestrators — give
        // them a generous per-IP limit so they never get throttled.
        rateLimit: { max: 300, timeWindow: '1 minute' },
      },
    },
    async (_request, reply) => {
      return reply.send({
        status: 'ok',
        timestamp: new Date().toISOString(),
      });
    },
  );

  // -------------------------------------------------------------------------
  // 10. Graceful shutdown hook
  //    app.close() triggers this, which is called during SIGTERM / SIGINT.
  // -------------------------------------------------------------------------

  app.addHook('onClose', async () => {
    app.log.info('Closing database connection…');
    await disconnectDb();

    app.log.info('Closing cache connection…');
    await disconnectCache();

    app.log.info('Closing BullMQ queues…');
    await closeQueues();
  });

  return app;
}

// ---------------------------------------------------------------------------
// Process entry point
// ---------------------------------------------------------------------------

const start = async (): Promise<void> => {
  const app = await buildServer();
  const _workers = registerWorkers(app.batchSigner);

  // -------------------------------------------------------------------------
  // Graceful shutdown
  // -------------------------------------------------------------------------

  const shutdown = async (): Promise<void> => {
    app.log.info('Shutting down…');

    try {
      // app.close() will trigger the onClose hook which handles db/cache/queue
      // teardown; we then close the workers separately because they maintain
      // their own Redis connections that are not tracked by the Fastify scope.
      await app.close();
      await closeWorkers();
    } catch (err) {
      console.error('Error during shutdown:', err);
    } finally {
      process.exit(0);
    }
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);

  // -------------------------------------------------------------------------
  // Listen
  // -------------------------------------------------------------------------

  await app.listen({
    port: config.server.port,
    host: config.server.host,
  });
};

start().catch((err) => {
  console.error('Fatal error during server startup:', err);
  process.exit(1);
});
