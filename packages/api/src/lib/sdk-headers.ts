import type { FastifyReply } from 'fastify';

/**
 * Cross-origin headers for the public SDK files under /sdk/ (served by
 * @fastify/static). Third-party sites load these bundles, so they are
 * readable from any origin. This hook is the only place that sets
 * Access-Control-Allow-Origin for /sdk/: nginx proxies the path without
 * adding CORS headers (deploy/nginx-qrauth-io.conf). Runs in onSend, after
 * @fastify/cors, and replaces any per-origin value it set.
 */
export function applySdkHeaders(url: string, reply: FastifyReply): void {
  if (!url.startsWith('/sdk/')) return;
  reply.header('Cross-Origin-Resource-Policy', 'cross-origin');
  reply.header('Access-Control-Allow-Origin', '*');
}
