/**
 * Base error class for all QRAuth SDK errors.
 */
export class QRAuthError extends Error {
  public readonly statusCode: number;
  public readonly code: string;

  constructor(message: string, statusCode: number, code: string) {
    super(message);
    this.name = 'QRAuthError';
    this.statusCode = statusCode;
    this.code = code;
  }
}

export class AuthenticationError extends QRAuthError {
  constructor(message = 'Invalid or missing API key') {
    super(message, 401, 'AUTHENTICATION_ERROR');
    this.name = 'AuthenticationError';
  }
}

export class AuthorizationError extends QRAuthError {
  constructor(message = 'Insufficient permissions') {
    super(message, 403, 'AUTHORIZATION_ERROR');
    this.name = 'AuthorizationError';
  }
}

export class NotFoundError extends QRAuthError {
  constructor(message = 'Resource not found') {
    super(message, 404, 'NOT_FOUND');
    this.name = 'NotFoundError';
  }
}

export class RateLimitError extends QRAuthError {
  public readonly retryAfter?: number;

  constructor(message = 'Rate limit exceeded', retryAfter?: number) {
    super(message, 429, 'RATE_LIMIT_EXCEEDED');
    this.name = 'RateLimitError';
    this.retryAfter = retryAfter;
  }
}

export class QuotaExceededError extends QRAuthError {
  constructor(message = 'Plan quota exceeded') {
    super(message, 429, 'QUOTA_EXCEEDED');
    this.name = 'QuotaExceededError';
  }
}

export class ValidationError extends QRAuthError {
  constructor(message = 'Validation failed') {
    super(message, 400, 'VALIDATION_ERROR');
    this.name = 'ValidationError';
  }
}

/**
 * Coerce the API's error body into a single human-readable string.
 *
 * The API sends `message` as a plain string for most errors, but as an array
 * of Zod issues for validation failures (`{ message: [{ path, message }, ...] }`).
 * Stringifying that array naively yields "[object Object]", so callers must run
 * the body through this before surfacing it. Falls back to `fallback` (usually
 * the HTTP status text) when no usable message is present.
 */
export function formatApiErrorMessage(body: unknown, fallback: string): string {
  if (body && typeof body === 'object') {
    const { message, error } = body as { message?: unknown; error?: unknown };
    return errorField(message) ?? errorField(error) ?? fallback;
  }
  return fallback;
}

/** Extract a string from a `message`/`error` field that may be a string or an array of Zod issues. */
function errorField(field: unknown): string | undefined {
  if (typeof field === 'string') {
    return field.trim() ? field : undefined;
  }
  if (Array.isArray(field)) {
    const parts = field.map(issueToString).filter((part): part is string => Boolean(part));
    return parts.length > 0 ? parts.join('; ') : undefined;
  }
  return undefined;
}

/** Render a single Zod issue (or string) as `path: message`, tolerating partial shapes. */
function issueToString(issue: unknown): string | undefined {
  if (typeof issue === 'string') return issue;
  if (issue && typeof issue === 'object') {
    const { path, message } = issue as { path?: unknown; message?: unknown };
    const fieldPath = Array.isArray(path) ? path.join('.') : undefined;
    const msg = typeof message === 'string' ? message : undefined;
    if (fieldPath && msg) return `${fieldPath}: ${msg}`;
    return msg ?? fieldPath;
  }
  return undefined;
}
