import type { FastifyReply, FastifyRequest } from 'fastify';
import type { ZodError, ZodSchema } from 'zod';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ValidationSchemas {
  body?: ZodSchema;
  params?: ZodSchema;
  querystring?: ZodSchema;
}

/**
 * Stable, public shape of a single validation failure. This is the contract
 * the API exposes in the 400 envelope's `details[]` — deliberately decoupled
 * from Zod's internal issue object so the wire format does NOT shift when Zod
 * changes its internals (as it did on the v3 → v4 upgrade). server.ts mirrors
 * this exact shape for Fastify's own schema-validation errors.
 */
export interface ValidationIssue {
  /** Path to the offending value, prefixed with the request part (e.g. `['body', 'email']`). */
  path: string[];
  /** Machine-readable issue code (e.g. Zod's `invalid_type`). */
  code: string;
  /** Human-readable message for this single issue. */
  message: string;
}

/**
 * Map a Zod error's issues to the stable {@link ValidationIssue} shape,
 * prefixing each path with the request part it came from.
 */
function toValidationIssues(error: ZodError, scope: 'body' | 'params' | 'querystring'): ValidationIssue[] {
  return error.issues.map((issue) => {
    const scanRule = scanRuleOf(issue);
    return {
      path: [scope, ...issue.path.map((segment) => String(segment))],
      // A scan-rule failure reports the rule's code (e.g. contrast-too-low).
      code: scanRule ?? String(issue.code),
      message: issue.message,
    };
  });
}

/**
 * Marker for a well-formed value that breaks a QR scannability rule (ADR-0005
 * D4): a refinement adds it as `params` on a custom issue. When every issue
 * of a request carries it, the request is answered 422 instead of 400.
 */
export interface ScanRuleIssueParams {
  readonly scanRule: string;
}

function scanRuleOf(issue: ZodError['issues'][number]): string | undefined {
  if (issue.code !== 'custom') return undefined;
  const params = (issue as { params?: Partial<ScanRuleIssueParams> }).params;
  return typeof params?.scanRule === 'string' ? params.scanRule : undefined;
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
    const allIssues: ValidationIssue[] = [];
    const scanRules: string[] = [];
    const collect = (error: ZodError, scope: 'body' | 'params' | 'querystring'): void => {
      allIssues.push(...toValidationIssues(error, scope));
      for (const issue of error.issues) {
        const rule = scanRuleOf(issue);
        if (rule) scanRules.push(rule);
      }
    };

    if (schemas.body !== undefined) {
      const result = schemas.body.safeParse(request.body);

      if (!result.success) {
        collect(result.error, 'body');
      } else {
        // Replace with parsed data so defaults and coercions take effect.
        (request as FastifyRequest & { body: unknown }).body = result.data;
      }
    }

    if (schemas.params !== undefined) {
      const result = schemas.params.safeParse(request.params);

      if (!result.success) {
        collect(result.error, 'params');
      } else {
        (request as FastifyRequest & { params: unknown }).params = result.data;
      }
    }

    if (schemas.querystring !== undefined) {
      const result = schemas.querystring.safeParse(request.query);

      if (!result.success) {
        collect(result.error, 'querystring');
      } else {
        (request as FastifyRequest & { query: unknown }).query = result.data;
      }
    }

    if (allIssues.length > 0 && scanRules.length === allIssues.length) {
      // Well-formed, but breaks a scannability rule: 422 with the rule's code.
      return reply.status(422).send({
        statusCode: 422,
        error: 'Unprocessable Entity',
        code: scanRules[0],
        message: summarizeIssues(allIssues),
        details: allIssues,
      });
    }

    if (allIssues.length > 0) {
      // Canonical validation envelope (matches server.ts setErrorHandler):
      // `message` is a human-readable one-liner; `details` carries the
      // structured issues for programmatic consumers. Sending the raw issue
      // array as `message` made clients render "[object Object]".
      return reply.status(400).send({
        statusCode: 400,
        error: 'Validation Error',
        message: summarizeIssues(allIssues),
        details: allIssues,
      });
    }
  };
}

/** Build a human-readable one-line summary (`path: message; ...`) from the issues. */
function summarizeIssues(issues: ValidationIssue[]): string {
  return issues
    .map((issue) => {
      const path = issue.path.join('.');
      return path ? `${path}: ${issue.message}` : issue.message;
    })
    .join('; ');
}
