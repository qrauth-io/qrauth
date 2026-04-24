import type { FastifyReply, FastifyRequest } from 'fastify';
import type { ZodSchema, ZodError } from 'zod';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ValidationSchemas {
  body?: ZodSchema;
  params?: ZodSchema;
  querystring?: ZodSchema;
}

type PreValidationHook = (
  request: FastifyRequest,
  reply: FastifyReply,
) => Promise<void>;

// ---------------------------------------------------------------------------
// Zod validator factory
// ---------------------------------------------------------------------------

/**
 * Returns a Fastify `preValidation` hook that validates and coerces the
 * indicated parts of the request using the supplied Zod schemas.
 *
 * On validation success the parsed (and defaulted/coerced) values replace
 * the raw request properties, so handlers always receive well-typed data.
 *
 * On failure a 400 response is sent immediately with the structured list of
 * Zod issues, and Fastify's own schema validation is bypassed for that part.
 *
 * Usage:
 * ```ts
 * fastify.post('/qr-codes', {
 *   preValidation: zodValidator({ body: createQRCodeSchema }),
 * }, handler);
 * ```
 */
export function zodValidator(schemas: ValidationSchemas): PreValidationHook {
  return async function validate(
    request: FastifyRequest,
    reply: FastifyReply,
  ): Promise<void> {
    // Collect all failures before responding so the caller sees every issue
    // in a single round-trip rather than one at a time.
    const allIssues: ZodError['issues'] = [];

    if (schemas.body !== undefined) {
      const result = schemas.body.safeParse(request.body);

      if (!result.success) {
        allIssues.push(
          ...result.error.issues.map((issue) => ({
            ...issue,
            path: ['body', ...issue.path],
          })),
        );
      } else {
        // Replace with parsed data so defaults and coercions take effect.
        (request as FastifyRequest & { body: unknown }).body = result.data;
      }
    }

    if (schemas.params !== undefined) {
      const result = schemas.params.safeParse(request.params);

      if (!result.success) {
        allIssues.push(
          ...result.error.issues.map((issue) => ({
            ...issue,
            path: ['params', ...issue.path],
          })),
        );
      } else {
        (request as FastifyRequest & { params: unknown }).params = result.data;
      }
    }

    if (schemas.querystring !== undefined) {
      const result = schemas.querystring.safeParse(request.query);

      if (!result.success) {
        allIssues.push(
          ...result.error.issues.map((issue) => ({
            ...issue,
            path: ['querystring', ...issue.path],
          })),
        );
      } else {
        (request as FastifyRequest & { query: unknown }).query = result.data;
      }
    }

    if (allIssues.length > 0) {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Validation Error',
        message: allIssues,
      });
    }
  };
}
