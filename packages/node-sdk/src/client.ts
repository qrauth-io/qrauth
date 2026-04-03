import {
  QRAuthError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  RateLimitError,
  ValidationError,
} from './errors.js';
import type {
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
} from './types.js';

const DEFAULT_BASE_URL = 'https://qrauth.io';

/**
 * QRAuth Node.js SDK client.
 *
 * @example
 * ```ts
 * import { QRAuth } from '@qrauth/node';
 *
 * const qrauth = new QRAuth({ apiKey: process.env.QRAUTH_API_KEY! });
 *
 * const qr = await qrauth.create({
 *   destination: 'https://parking.gr/pay',
 *   location: { lat: 40.63, lng: 22.94 },
 *   expiresIn: '1y',
 * });
 *
 * console.log(qr.verification_url);
 * ```
 */
export class QRAuth {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(options: QRAuthOptions) {
    if (!options.apiKey) {
      throw new Error('QRAuth: apiKey is required');
    }
    this.apiKey = options.apiKey;
    this.baseUrl = (options.baseUrl || DEFAULT_BASE_URL).replace(/\/+$/, '');
  }

  // -------------------------------------------------------------------------
  // QR Code — create
  // -------------------------------------------------------------------------

  /**
   * Generate a cryptographically signed QR code.
   */
  async create(options: CreateQRCodeOptions): Promise<QRCodeResponse> {
    const body: Record<string, unknown> = {
      destinationUrl: options.destination,
    };

    if (options.label) body.label = options.label;
    if (options.contentType) body.contentType = options.contentType;
    if (options.content) body.content = options.content;

    if (options.location) {
      body.location = {
        lat: options.location.lat,
        lng: options.location.lng,
        radiusM: options.location.radiusM ?? 50,
      };
    }

    if (options.expiresIn) {
      body.expiresAt = parseDuration(options.expiresIn);
    }

    return this.request<QRCodeResponse>('POST', '/api/v1/qrcodes', body);
  }

  // -------------------------------------------------------------------------
  // QR Code — verify
  // -------------------------------------------------------------------------

  /**
   * Verify a QR code token and get its trust score and metadata.
   */
  async verify(token: string, options?: VerifyOptions): Promise<VerificationResult> {
    const params = new URLSearchParams();
    if (options?.clientLat !== undefined) params.set('clientLat', String(options.clientLat));
    if (options?.clientLng !== undefined) params.set('clientLng', String(options.clientLng));

    const qs = params.toString();
    const path = `/api/v1/verify/${encodeURIComponent(token)}${qs ? `?${qs}` : ''}`;

    return this.request<VerificationResult>('GET', path, undefined, {
      Accept: 'application/json',
    });
  }

  // -------------------------------------------------------------------------
  // QR Code — list
  // -------------------------------------------------------------------------

  /**
   * List QR codes for your organization.
   */
  async list(options?: ListQRCodesOptions): Promise<PaginatedResponse<QRCodeDetail>> {
    const params = new URLSearchParams();
    if (options?.page) params.set('page', String(options.page));
    if (options?.pageSize) params.set('pageSize', String(options.pageSize));
    if (options?.status) params.set('status', options.status);

    const qs = params.toString();
    return this.request<PaginatedResponse<QRCodeDetail>>('GET', `/api/v1/qrcodes${qs ? `?${qs}` : ''}`);
  }

  // -------------------------------------------------------------------------
  // QR Code — get
  // -------------------------------------------------------------------------

  /**
   * Get details of a specific QR code by token.
   */
  async get(token: string): Promise<QRCodeDetail> {
    return this.request<QRCodeDetail>('GET', `/api/v1/qrcodes/${encodeURIComponent(token)}`);
  }

  // -------------------------------------------------------------------------
  // QR Code — revoke
  // -------------------------------------------------------------------------

  /**
   * Revoke a QR code. It will no longer verify successfully.
   */
  async revoke(token: string): Promise<{ message: string }> {
    return this.request<{ message: string }>('DELETE', `/api/v1/qrcodes/${encodeURIComponent(token)}`);
  }

  // -------------------------------------------------------------------------
  // QR Code — bulk create
  // -------------------------------------------------------------------------

  /**
   * Generate multiple signed QR codes in a single request (max 100).
   */
  async bulk(items: BulkCreateItem[]): Promise<BulkCreateResponse> {
    const body = {
      items: items.map((item) => ({
        destinationUrl: item.destination,
        label: item.label,
        location: item.location
          ? { lat: item.location.lat, lng: item.location.lng, radiusM: item.location.radiusM ?? 50 }
          : undefined,
        expiresAt: item.expiresIn ? parseDuration(item.expiresIn) : undefined,
      })),
    };

    return this.request<BulkCreateResponse>('POST', '/api/v1/qrcodes/bulk', body);
  }

  // -------------------------------------------------------------------------
  // Internal HTTP client
  // -------------------------------------------------------------------------

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    extraHeaders?: Record<string, string>,
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;

    const headers: Record<string, string> = {
      'X-API-Key': this.apiKey,
      'User-Agent': 'qrauth-node/0.1.0',
      ...extraHeaders,
    };

    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
    }

    const res = await fetch(url, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });

    if (!res.ok) {
      await this.handleError(res);
    }

    return res.json() as Promise<T>;
  }

  private async handleError(res: Response): Promise<never> {
    let message: string;
    try {
      const body = await res.json() as { message?: string; error?: string };
      message = body.message || body.error || res.statusText;
    } catch {
      message = res.statusText;
    }

    switch (res.status) {
      case 400:
        throw new ValidationError(message);
      case 401:
        throw new AuthenticationError(message);
      case 403:
        throw new AuthorizationError(message);
      case 404:
        throw new NotFoundError(message);
      case 429: {
        const retryAfter = res.headers.get('retry-after');
        throw new RateLimitError(message, retryAfter ? parseInt(retryAfter, 10) : undefined);
      }
      default:
        throw new QRAuthError(message, res.status, 'API_ERROR');
    }
  }
}

// ---------------------------------------------------------------------------
// Duration parser
// ---------------------------------------------------------------------------

/**
 * Parse a human-readable duration string into an ISO 8601 datetime string.
 * Supports: `30s`, `5m`, `6h`, `30d`, `1y`, or raw ISO 8601 datetimes.
 */
function parseDuration(input: string): string {
  // If it's already an ISO datetime, return as-is
  if (input.includes('T') || input.includes('-')) {
    return input;
  }

  const match = input.match(/^(\d+)(s|m|h|d|w|mo|y)$/);
  if (!match) {
    throw new Error(`Invalid duration: "${input}". Use formats like 30s, 5m, 6h, 30d, 1y or an ISO datetime.`);
  }

  const value = parseInt(match[1], 10);
  const unit = match[2];
  const now = new Date();

  switch (unit) {
    case 's':
      now.setSeconds(now.getSeconds() + value);
      break;
    case 'm':
      now.setMinutes(now.getMinutes() + value);
      break;
    case 'h':
      now.setHours(now.getHours() + value);
      break;
    case 'd':
      now.setDate(now.getDate() + value);
      break;
    case 'w':
      now.setDate(now.getDate() + value * 7);
      break;
    case 'mo':
      now.setMonth(now.getMonth() + value);
      break;
    case 'y':
      now.setFullYear(now.getFullYear() + value);
      break;
  }

  return now.toISOString();
}
