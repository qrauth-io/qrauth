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
