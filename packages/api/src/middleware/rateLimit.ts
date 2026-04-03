import type { FastifyInstance, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';
import { redis } from '../lib/cache.js';

// ---------------------------------------------------------------------------
// Rate-limit tiers
// ---------------------------------------------------------------------------

/**
 * Named tiers with their limits and key-generation strategy.
 *
 * - `public`   — unauthenticated endpoints, keyed by IP
 * - `auth`     — authenticated read/write, keyed by org ID
 * - `generate` — QR-code generation, keyed by org ID
 * - `bulk`     — bulk generation, keyed by org ID
 */
const TIERS = {
  public: {
    timeWindow: '1 minute',
    max: 100,
    byIssuer: false,
  },
  auth: {
    timeWindow: '1 minute',
    max: 60,
    byIssuer: true,
  },
  generate: {
    timeWindow: '1 minute',
    max: 30,
    byIssuer: true,
  },
  bulk: {
    timeWindow: '1 minute',
    max: 5,
    byIssuer: true,
  },
} as const;

export type RateLimitTier = keyof typeof TIERS;

// ---------------------------------------------------------------------------
// Route-config helper
// ---------------------------------------------------------------------------

/**
 * Returns a `config.rateLimit` object for use in Fastify route definitions.
 *
 * @fastify/rate-limit reads `config.rateLimit` on the route options at
 * registration time (via its `onRoute` hook), so this is the only correct
 * place to configure per-route limits. Do NOT attempt to set these values
 * inside a `preHandler` — the plugin will have already evaluated the config
 * by then.
 *
 * Usage:
 * ```ts
 * fastify.post('/qr-codes', {
 *   config: { rateLimit: rateLimitConfig('generate') },
 *   preHandler: [fastify.authenticate],
 * }, handler);
 *
 * fastify.get('/verify/:token', {
 *   config: { rateLimit: rateLimitConfig('public') },
 * }, handler);
 * ```
 *
 * The named convenience exports (`rateLimitPublic`, `rateLimitAuth`, etc.)
 * are pre-built config objects for the four standard tiers and are the
 * preferred way to apply limits without repeating tier names in route files.
 */
export function rateLimitConfig(
  tier: RateLimitTier,
  overrides?: { max?: number; timeWindow?: string },
) {
  const base = TIERS[tier];

  return {
    max: overrides?.max ?? base.max,
    timeWindow: overrides?.timeWindow ?? base.timeWindow,
    keyGenerator: base.byIssuer
      ? (request: FastifyRequest): string => request.user?.orgId ?? request.ip
      : (request: FastifyRequest): string => request.ip,
  };
}

// ---------------------------------------------------------------------------
// Pre-built tier configs
// ---------------------------------------------------------------------------

/**
 * 100 req/min per IP.
 * For public verify endpoints that do not require authentication.
 *
 * ```ts
 * fastify.get('/verify/:token', {
 *   config: { rateLimit: rateLimitPublic },
 * }, handler);
 * ```
 */
export const rateLimitPublic = rateLimitConfig('public');

/**
 * 60 req/min per org ID (falls back to IP when user is absent).
 * For general authenticated endpoints.
 *
 * ```ts
 * fastify.get('/qr-codes', {
 *   config: { rateLimit: rateLimitAuth },
 *   preHandler: [fastify.authenticate],
 * }, handler);
 * ```
 */
export const rateLimitAuth = rateLimitConfig('auth');

/**
 * 30 req/min per org ID.
 * For QR-code generation endpoints.
 *
 * ```ts
 * fastify.post('/qr-codes', {
 *   config: { rateLimit: rateLimitGenerate },
 *   preHandler: [fastify.authenticate],
 * }, handler);
 * ```
 */
export const rateLimitGenerate = rateLimitConfig('generate');

/**
 * 5 req/min per org ID.
 * For bulk QR-code generation endpoints.
 *
 * ```ts
 * fastify.post('/qr-codes/bulk', {
 *   config: { rateLimit: rateLimitBulk },
 *   preHandler: [fastify.authenticate],
 * }, handler);
 * ```
 */
export const rateLimitBulk = rateLimitConfig('bulk');

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

/**
 * Registers @fastify/rate-limit with the shared Redis client as the backing
 * store. The plugin global default (100 req/min per IP) applies to any route
 * that does not supply a `config.rateLimit` route option.
 *
 * Must be registered before any route plugins so that the `onRoute` hook
 * that reads per-route configs fires for every registered route.
 */
async function rateLimitPlugin(fastify: FastifyInstance): Promise<void> {
  await fastify.register(import('@fastify/rate-limit'), {
    // Global default.
    max: TIERS.public.max,
    timeWindow: TIERS.public.timeWindow,

    // Shared Redis client — ensures limits are enforced across all process
    // instances in a horizontally scaled deployment.
    redis,

    // Namespace all keys to avoid collisions with application data.
    nameSpace: 'qrauth:rl:',

    // Default key: client IP.
    keyGenerator(request: FastifyRequest): string {
      return request.ip;
    },

    // RFC 7807-compatible error body on limit breach.
    errorResponseBuilder(
      _request: FastifyRequest,
      context: { max: number; ttl: number },
    ) {
      return {
        statusCode: 429,
        error: 'Too Many Requests',
        message: `Rate limit exceeded. Maximum ${context.max} requests per window. Retry after ${Math.ceil(context.ttl / 1000)} seconds.`,
        retryAfter: Math.ceil(context.ttl / 1000),
      };
    },

    // Expose standard rate-limit headers to clients.
    addHeaders: {
      'x-ratelimit-limit': true,
      'x-ratelimit-remaining': true,
      'x-ratelimit-reset': true,
      'retry-after': true,
    },
  });
}

export const rateLimitMiddleware = fp(rateLimitPlugin, {
  name: 'qrauth-rate-limit',
});
