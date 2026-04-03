export { QRAuth } from './client.js';
export type {
  QRAuthOptions,
  CreateQRCodeOptions,
  QRCodeResponse,
  ListQRCodesOptions,
  QRCodeDetail,
  PaginatedResponse,
  VerifyOptions,
  VerificationResult,
  BulkCreateItem,
  BulkCreateResponse,
  DomainWarning,
} from './types.js';
export {
  QRAuthError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  RateLimitError,
  QuotaExceededError,
  ValidationError,
} from './errors.js';
