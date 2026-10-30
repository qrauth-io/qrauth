import type { FastifyReply, FastifyRequest } from 'fastify';
import { randomBytes } from 'node:crypto';
import { renderReturnPage } from '../renderers/oidc/return.js';

/**
 * Shared plumbing for the OP's script-free HTML pages (consent, sign-out):
 * one strict CSP, sent the only way server.ts honours, and one way back to
 * the relying party after a form POST.
 */

/** Nothing loads, nothing runs, nothing frames the page; forms post home only. */
function strictPageCsp(nonce: string): string {
  return [
    "default-src 'none'",
    `style-src 'nonce-${nonce}'`,
    "script-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join('; ');
}

/**
 * Send a page with the strict CSP. The policy goes through
 * `request.cspOverride`: server.ts rewrites the CSP header on every response
 * in an onSend hook, and that field is the only thing it honours.
 */
export function sendOpHtml(
  request: FastifyRequest,
  reply: FastifyReply,
  status: number,
  render: (nonce: string) => string,
): FastifyReply {
  const nonce = randomBytes(16).toString('base64');
  (request as unknown as { cspOverride?: string }).cspOverride = strictPageCsp(nonce);
  reply.header('Content-Security-Policy', strictPageCsp(nonce));
  reply.header('X-Frame-Options', 'DENY');
  reply.header('Cache-Control', 'no-store');
  reply.header('Referrer-Policy', 'no-referrer');
  return reply.status(status).type('text/html').send(render(nonce));
}

/**
 * Hand the browser back to the relying party after a form POST.
 *
 * Not a 302: Chromium applies the page's `form-action` to every redirect in
 * the navigation a form submission starts, including redirects the relying
 * party's own endpoint makes afterwards. A redirect would therefore need
 * `form-action` opened to origins this OP cannot know. A page that navigates
 * by meta refresh starts a new, ordinary navigation and keeps
 * `form-action 'self'` intact.
 */
export function returnToClient(
  request: FastifyRequest,
  reply: FastifyReply,
  targetUri: string,
  params: Record<string, string>,
): FastifyReply {
  const target = new URL(targetUri);
  for (const [key, value] of Object.entries(params)) target.searchParams.set(key, value);
  return sendOpHtml(request, reply, 200, (nonce) =>
    renderReturnPage({ nonce, targetUrl: target.toString(), targetHost: target.host }),
  );
}
