import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify, { type FastifyError, type FastifyInstance } from 'fastify';
import rateLimit, { type FastifyRateLimitStoreCtor } from '@fastify/rate-limit';

/**
 * When Redis is unreachable, the QR generation tiers (`generate`, `bulk`), QR image exports (`render`)
 * refuse with 503 while the other tiers let requests through.
 */

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

const { RateLimitRedisStore, isRateLimitStoreUnavailable, STORE_UNAVAILABLE_RETRY_AFTER_SECONDS } =
  await import('../rate-limit-store.js');
const { rateLimitGenerate, rateLimitBulk, rateLimitRender, rateLimitAuth, rateLimitPublic, rateLimitSensitive, rateLimitDemo, rateLimitReport } =
  await import('../rateLimit.js');

// A Redis client whose rate-limit command always fails, as during an outage.
const downRedis = {
  rateLimit: (...args: unknown[]) => {
    const cb = args[args.length - 1] as (err: Error | null) => void;
    cb(new Error('connect ECONNREFUSED'));
  },
  defineCommand: () => undefined,
};

let app: FastifyInstance;

beforeAll(async () => {
  app = Fastify();
  RateLimitRedisStore.configure({ redis: downRedis as never, log: app.log });
  await app.register(rateLimit, {
    store: RateLimitRedisStore as unknown as FastifyRateLimitStoreCtor,
    skipOnError: true,
    max: 100,
    timeWindow: '1 minute',
  });
  // Same mapping as the global error handler in server.ts.
  app.setErrorHandler((error: FastifyError, _request, reply) => {
    if (isRateLimitStoreUnavailable(error)) {
      return reply.status(503).header('Retry-After', STORE_UNAVAILABLE_RETRY_AFTER_SECONDS).send({ statusCode: 503 });
    }
    return reply.status(error.statusCode ?? 500).send({ statusCode: error.statusCode ?? 500 });
  });
  const ok = async () => ({ ok: true });
  app.post('/generate', { config: { rateLimit: rateLimitGenerate } }, ok);
  app.post('/bulk', { config: { rateLimit: rateLimitBulk } }, ok);
  app.get('/render', { config: { rateLimit: rateLimitRender } }, ok);
  app.post('/auth', { config: { rateLimit: rateLimitAuth } }, ok);
  app.get('/public', { config: { rateLimit: rateLimitPublic } }, ok);
  app.post('/sensitive', { config: { rateLimit: rateLimitSensitive } }, ok);
  app.post('/demo', { config: { rateLimit: rateLimitDemo } }, ok);
  app.post('/report', { config: { rateLimit: rateLimitReport } }, ok);
  await app.ready();
});

afterAll(async () => {
  await app.close();
});

describe('rate-limit store outage', () => {
  it.each([
    ['POST', '/generate'],
    ['POST', '/bulk'],
    ['GET', '/render'],
    ['POST', '/sensitive'],
    ['POST', '/demo'],
    ['POST', '/report'],
  ])('%s %s fails closed with 503', async (method, url) => {
    const res = await app.inject({ method: method as 'POST', url });

    expect(res.statusCode).toBe(503);
    expect(res.headers['retry-after']).toBe(String(STORE_UNAVAILABLE_RETRY_AFTER_SECONDS));
  });

  it.each([
    ['POST', '/auth'],
    ['GET', '/public'],
  ])('%s %s still fails open', async (method, url) => {
    const res = await app.inject({ method: method as 'POST' | 'GET', url });

    expect(res.statusCode).toBe(200);
  });
});

describe('tier configuration', () => {
  it('generate and bulk do not skip on store errors', () => {
    expect(rateLimitGenerate.skipOnError).toBe(false);
    expect(rateLimitBulk.skipOnError).toBe(false);
    expect(rateLimitAuth.skipOnError).toBe(true);
  });

  it('demo is 5/min and does not skip on store errors', () => {
    expect(rateLimitDemo.max).toBe(5);
    expect(rateLimitDemo.skipOnError).toBe(false);
  });
});
