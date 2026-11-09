import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';
import type { FastifyRateLimitStoreCtor } from '@fastify/rate-limit';
import { redis } from '../lib/cache.js';
import { config } from '../lib/config.js';
import { networkKey, principalKey } from '../lib/rate-limit-key.js';
import { RateLimitRedisStore } from './rate-limit-store.js';

// ---------------------------------------------------------------------------
// Rate-limit tiers
// ---------------------------------------------------------------------------

const isDev = config.server.isDev || config.server.isTest;

/** Dev and test get headroom: the E2E suite runs from a single IP. */
const DEV_MAX = 1000;
const limit = (production: number): number => (isDev ? DEV_MAX : production);

type KeyStrategy =
  /** The caller's network: IPv4 address, or IPv6 /64. */
  | 'network'
  /** The organization of a verified JWT or API key; the network otherwise. */
  | 'organization'
  /** The OP login attempt being polled; the network when no id is given. */
  | 'loginAttempt';

interface Tier {
  timeWindow: string;
  max: number;
  key: KeyStrategy;
  /**
   * What happens when Redis cannot be reached. Open: the request goes
   * through unlimited. Closed: it is refused with 503. The authentication
   * routes fail closed (they are the ones worth guessing at), and so does QR
   * generation, so an outage cannot lift the issuance limits.
   */
  onStoreError: 'open' | 'closed';
}

/**
 * Named tiers.
 *
 * - `public`    — unauthenticated endpoints; also the global default
 * - `auth`      — authenticated read/write, per organization
 * - `generate`  — QR-code generation, per organization, fails closed
 * - `bulk`      — bulk generation, per organization, fails closed
 * - `render`    — QR image exports, per organization, fails closed
 * - `sensitive` — signup/login/reset, per network, fails closed
 * - `demo`      — unauthenticated demo issuance, 5/min per network, fails closed
 * - `report`    — public abuse reports, 10/hour per network, fails closed
 * - `oidc*`     — the OpenID Provider endpoints, each with its own bucket so
 *                 one cannot starve another (audit 2026-10 FINDING-012)
 */
const TIERS = {
  // Dev/test headroom here matters most: this is the default for every route
  // without its own tier, and a single-IP E2E run passes 100/min.
  public: { timeWindow: '1 minute', max: limit(100), key: 'network', onStoreError: 'open' },
  auth: { timeWindow: '1 minute', max: 60, key: 'organization', onStoreError: 'open' },
  generate: { timeWindow: '1 minute', max: 30, key: 'organization', onStoreError: 'closed' },
  bulk: { timeWindow: '1 minute', max: 5, key: 'organization', onStoreError: 'closed' },
  // GET /qrcodes/:token/image (ADR-0005 D7). PNG work is also capped by an
  // in-process semaphore; this bounds how often one organization asks.
  render: { timeWindow: '1 minute', max: 60, key: 'organization', onStoreError: 'closed' },
  sensitive: { timeWindow: '1 minute', max: isDev ? 100 : 10, key: 'network', onStoreError: 'closed' },
  // Unauthenticated demo issuance (routes/demo.ts), per network, fails closed.
  demo: { timeWindow: '1 minute', max: 5, key: 'network', onStoreError: 'closed' },
  // Public "Report this code" form (routes/abuse-reports.ts), per network, fails closed.
  report: { timeWindow: '1 hour', max: 10, key: 'network', onStoreError: 'closed' },
  // Browser-facing. Several people can sit behind one address, so these are
  // sized for an office, not for one person.
  oidcAuthorize: { timeWindow: '1 minute', max: limit(120), key: 'network', onStoreError: 'open' },
  // Every GET /login creates an auth session and renders a QR code.
  oidcLogin: { timeWindow: '1 minute', max: limit(60), key: 'network', onStoreError: 'open' },
  // The login page polls every 1.5 s (40/min) for as long as it is open.
  oidcLoginStatus: { timeWindow: '1 minute', max: limit(90), key: 'loginAttempt', onStoreError: 'open' },
  oidcLogout: { timeWindow: '1 minute', max: limit(60), key: 'network', onStoreError: 'open' },
  // Called by relying-party servers: one address, many users.
  oidcToken: { timeWindow: '1 minute', max: limit(300), key: 'network', onStoreError: 'open' },
  oidcUserinfo: { timeWindow: '1 minute', max: limit(300), key: 'network', onStoreError: 'open' },
  oidcRevoke: { timeWindow: '1 minute', max: limit(60), key: 'network', onStoreError: 'open' },
} as const satisfies Record<string, Tier>;

export type RateLimitTier = keyof typeof TIERS;

/** Shape of an OP login attempt id (16 random bytes, base64url). */
const LOGIN_ATTEMPT_ID = /^[A-Za-z0-9_-]{22}$/;

function keyGeneratorFor(strategy: KeyStrategy): (request: FastifyRequest) => string | Promise<string> {
  if (strategy === 'organization') {
    return (request) => principalKey(request.server, request);
  }
  if (strategy === 'loginAttempt') {
    return (request) => {
      const id = (request.query as { id?: unknown } | undefined)?.id;
      return typeof id === 'string' && LOGIN_ATTEMPT_ID.test(id) ? `login-attempt:${id}` : networkKey(request.ip);
    };
  }
  return (request) => networkKey(request.ip);
}

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
  const base: Tier = TIERS[tier];

  return {
    max: overrides?.max ?? base.max,
    timeWindow: overrides?.timeWindow ?? base.timeWindow,
    keyGenerator: keyGeneratorFor(base.key),
    skipOnError: base.onStoreError === 'open',
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

/** QR image exports, per organization, fails closed (ADR-0005 D7). */
export const rateLimitRender = rateLimitConfig('render');

export const rateLimitSensitive = rateLimitConfig('sensitive');

export const rateLimitDemo = rateLimitConfig('demo');

export const rateLimitReport = rateLimitConfig('report');

// OpenID Provider endpoints (audit 2026-10 FINDING-012).
export const rateLimitOidcAuthorize = rateLimitConfig('oidcAuthorize');
export const rateLimitOidcLogin = rateLimitConfig('oidcLogin');
/** Per login attempt, so people behind one address do not share a bucket. */
export const rateLimitOidcLoginStatus = rateLimitConfig('oidcLoginStatus');
export const rateLimitOidcLogout = rateLimitConfig('oidcLogout');
export const rateLimitOidcToken = rateLimitConfig('oidcToken');
export const rateLimitOidcUserinfo = rateLimitConfig('oidcUserinfo');
export const rateLimitOidcRevoke = rateLimitConfig('oidcRevoke');

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

/**
 * Registers @fastify/rate-limit with the shared Redis client as the backing
 * store. The plugin global default (100 req/min per network) applies to any route
 * that does not supply a `config.rateLimit` route option.
 *
 * Must be registered before any route plugins so that the `onRoute` hook
 * that reads per-route configs fires for every registered route.
 */
async function rateLimitPlugin(fastify: FastifyInstance): Promise<void> {
  RateLimitRedisStore.configure({ redis, log: fastify.log });

  await fastify.register(import('@fastify/rate-limit'), {
    // Global default.
    max: TIERS.public.max,
    timeWindow: TIERS.public.timeWindow,

    // Shared Redis client (limits hold across processes), wrapped so that a
    // Redis failure is logged and counted. Keys are namespaced `qrauth:rl:`.
    // (The plugin's type for a store omits the timeWindow and max arguments
    // it passes to incr.)
    store: RateLimitRedisStore as unknown as FastifyRateLimitStoreCtor,

    // A Redis outage must not become an outage of the whole API: by default
    // the request goes through. Tiers that fail closed say so themselves.
    skipOnError: TIERS.public.onStoreError === 'open',

    // Default key: the caller's network.
    keyGenerator(request: FastifyRequest): string {
      return networkKey(request.ip);
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

/** Requests per minute one network may make to /login/status, whatever ids it sends. */
const LOGIN_STATUS_NETWORK_MAX = limit(600);

/**
 * `onRequest` hook for /login/status, in front of its per-attempt tier. The
 * per-attempt bucket alone can be sidestepped by sending a new made-up id
 * with every request; this caps the network as a whole, high enough for a
 * dozen people behind one address to have the login page open.
 */
export function loginStatusNetworkGuard(fastify: FastifyInstance) {
  // Without the limiter plugin (route unit tests) per-route tiers do nothing
  // either; server.ts registers the plugin before any route.
  if (!fastify.hasDecorator('createRateLimit')) return async (): Promise<void> => undefined;
  const check = fastify.createRateLimit({
    max: LOGIN_STATUS_NETWORK_MAX,
    timeWindow: '1 minute',
    keyGenerator: (request: FastifyRequest) => `login-status-network:${networkKey(request.ip)}`,
    skipOnError: true,
  });
  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    const result = await check(request);
    if (result.isAllowed || !result.isExceeded) return;
    const retryAfter = result.ttlInSeconds;
    reply.header('retry-after', retryAfter);
    return reply.status(429).send({
      statusCode: 429,
      error: 'Too Many Requests',
      message: `Rate limit exceeded. Retry after ${retryAfter} seconds.`,
      retryAfter,
    });
  };
}

export const rateLimitMiddleware = fp(rateLimitPlugin, {
  name: 'qrauth-rate-limit',
});
