import Fastify, { type FastifyError, type FastifyInstance } from 'fastify';
import { config } from './lib/config.js';
import { db, disconnectDb } from './lib/db.js';
import { redis, disconnectCache } from './lib/cache.js';
import { closeQueues } from './lib/queue.js';

// Middleware plugins
import { authMiddleware } from './middleware/auth.js';
import { rateLimitMiddleware } from './middleware/rateLimit.js';

// Route plugins
import authRoutes from './routes/auth.js';
import organizationRoutes from './routes/organizations.js';
import appRoutes from './routes/apps.js';
import qrcodeRoutes from './routes/qrcodes.js';
import verifyRoutes from './routes/verify.js';
import analyticsRoutes from './routes/analytics.js';
import transparencyRoutes from './routes/transparency.js';
import authSessionRoutes from './routes/auth-sessions.js';
import approvalRoutes from './routes/approval.js';

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

  await app.register(import('@fastify/cors'), {
    // In development allow any origin for convenience. In production this
    // should be locked down to the issuer dashboard domain.
    origin: config.server.isDev ? true : (process.env.CORS_ORIGIN ?? false),
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  });

  await app.register(import('@fastify/helmet'), {
    // Content-Security-Policy is intentionally relaxed here because the API
    // returns JSON, not HTML. Tighten this when serving any embedded UI.
    contentSecurityPolicy: false,
  });

  // -------------------------------------------------------------------------
  // 5. Sensible HTTP error helpers (reply.notFound(), reply.badRequest(), …)
  // -------------------------------------------------------------------------

  await app.register(import('@fastify/sensible'));

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

  // -------------------------------------------------------------------------
  // 8. Route plugins
  // -------------------------------------------------------------------------

  await app.register(authRoutes, { prefix: '/api/v1/auth' });
  await app.register(organizationRoutes, { prefix: '/api/v1/organizations' });
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
  await app.register(approvalRoutes, { prefix: '/a' });

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
  const _workers = registerWorkers();

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
