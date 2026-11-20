import type { FastifyInstance } from 'fastify';
import { timingSafeEqual } from 'node:crypto';
import { config } from '../lib/config.js';

/**
 * GET /internal/mac-stats (ADR-0001 A4-M2 Phase 1).
 *
 * Returns the current MAC signer counters. Consumed by the daily agent
 * during the Phase 1 observation window to verify zero divergence and a
 * healthy resilience posture before the Phase 2 cutover.
 *
 * Auth: bearer via `INTERNAL_STATS_TOKEN`. If the env var is missing the
 * route is registered but returns 503 — this avoids silently exposing
 * counters in a misconfigured environment.
 */
export default async function internalMacStatsRoutes(
  fastify: FastifyInstance,
): Promise<void> {
  fastify.get(
    '/mac-stats',
    {
      // Internal debugging surface — don't let rate limiting starve the
      // daily agent, but also don't bypass authentication.
      config: { rateLimit: { max: 60, timeWindow: '1 minute' } },
    },
    async (request, reply) => {
      const expected = config.internalStats.token;
      if (!expected) {
        return reply.status(503).send({
          statusCode: 503,
          error: 'Service Unavailable',
          message: 'INTERNAL_STATS_TOKEN is not configured.',
        });
      }

      const header = request.headers.authorization ?? '';
      const match = header.match(/^Bearer (.+)$/);
      if (!match) {
        return reply.status(401).send({
          statusCode: 401,
          error: 'Unauthorized',
          message: 'Bearer token required.',
        });
      }
      const provided = Buffer.from(match[1], 'utf8');
      const expectedBuf = Buffer.from(expected, 'utf8');
      const ok =
        provided.length === expectedBuf.length &&
        timingSafeEqual(provided, expectedBuf);
      if (!ok) {
        return reply.status(401).send({
          statusCode: 401,
          error: 'Unauthorized',
          message: 'Invalid token.',
        });
      }

      return reply.send(fastify.macSignerStats());
    },
  );
}
