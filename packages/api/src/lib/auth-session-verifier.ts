import type { FastifyRequest } from 'fastify';

/**
 * Where a client puts the PKCE `code_verifier` when it polls an auth session
 * (`GET /api/v1/auth-sessions/:id`).
 *
 * The header is the documented way: headers are not written to access logs,
 * a query string is (audit 2026-10 FINDING-013). The `code_verifier` query
 * parameter is still accepted, because web components already embedded on
 * customer sites send it that way, and because the SSE endpoint is opened
 * with EventSource, which cannot set headers. Request logs redact it.
 */
export const CODE_VERIFIER_HEADER = 'x-qrauth-code-verifier';

const nonEmptyString = (value: unknown): string | undefined =>
  typeof value === 'string' && value.length > 0 ? value : undefined;

export function readCodeVerifier(request: FastifyRequest): string | undefined {
  return (
    nonEmptyString(request.headers[CODE_VERIFIER_HEADER]) ??
    nonEmptyString((request.query as { code_verifier?: unknown } | undefined)?.code_verifier)
  );
}
