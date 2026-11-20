/** Details of the API response an error came from. */
export interface QRAuthErrorOptions {
  /** The response's `X-Request-Id` header. */
  requestId?: string;
}

/**
 * Base error class for all QRAuth SDK errors.
 *
 * `requestId` is the API's `X-Request-Id` for the failed request, when the
 * API sent one. Quote it to QRAuth support to identify the request.
 */
export class QRAuthError extends Error {
  public readonly statusCode: number;
  public readonly code: string;
  public readonly requestId?: string;

  constructor(message: string, statusCode: number, code: string, options: QRAuthErrorOptions = {}) {
    super(message);
    this.name = 'QRAuthError';
    this.statusCode = statusCode;
    this.code = code;
    this.requestId = options.requestId;
  }
}

export class AuthenticationError extends QRAuthError {
  constructor(message = 'Invalid or missing API key', options?: QRAuthErrorOptions) {
    super(message, 401, 'AUTHENTICATION_ERROR', options);
    this.name = 'AuthenticationError';
  }
}

export interface AuthorizationErrorOptions extends QRAuthErrorOptions {
  /** The API's machine-readable `code`, when it sends one. */
  reason?: string;
}

/**
 * 403 Forbidden. `reason` is the API's machine-readable `code` when it sends
 * one, e.g. `'governance-plan-required'` (the plan does not include the
 * feature) or `'audit-role-required'` (the key's role may not read the
 * audit log).
 */
export class AuthorizationError extends QRAuthError {
  public readonly reason?: string;

  constructor(message = 'Insufficient permissions', options: AuthorizationErrorOptions = {}) {
    super(message, 403, 'AUTHORIZATION_ERROR', options);
    this.name = 'AuthorizationError';
    this.reason = options.reason;
  }
}

export class NotFoundError extends QRAuthError {
  constructor(message = 'Resource not found', options?: QRAuthErrorOptions) {
    super(message, 404, 'NOT_FOUND', options);
    this.name = 'NotFoundError';
  }
}

export class RateLimitError extends QRAuthError {
  public readonly retryAfter?: number;

  constructor(message = 'Rate limit exceeded', retryAfter?: number, options?: QRAuthErrorOptions) {
    super(message, 429, 'RATE_LIMIT_EXCEEDED', options);
    this.name = 'RateLimitError';
    this.retryAfter = retryAfter;
  }
}

export class QuotaExceededError extends QRAuthError {
  constructor(message = 'Plan quota exceeded', options?: QRAuthErrorOptions) {
    super(message, 429, 'QUOTA_EXCEEDED', options);
    this.name = 'QuotaExceededError';
  }
}

/**
 * 409 Conflict. `reason` is the API's machine-readable `code` when it sends
 * one, e.g. `'name-taken'` or `'limit-reached'` for tags and folders.
 */
export class ConflictError extends QRAuthError {
  public readonly reason?: string;

  constructor(message = 'Conflict', reason?: string, options?: QRAuthErrorOptions) {
    super(message, 409, 'CONFLICT', options);
    this.name = 'ConflictError';
    this.reason = reason;
  }
}

export class ValidationError extends QRAuthError {
  constructor(message = 'Validation failed', options?: QRAuthErrorOptions) {
    super(message, 400, 'VALIDATION_ERROR', options);
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
