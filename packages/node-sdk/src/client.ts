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
  CreateAuthSessionOptions,
  AuthSessionResponse,
  AuthSessionStatus,
  GetAuthSessionOptions,
  AuthSessionVerifyResult,
  CreateEphemeralSessionOptions,
  EphemeralSessionResponse,
  ClaimEphemeralSessionOptions,
  EphemeralSessionClaimResult,
  ListEphemeralSessionsOptions,
  EphemeralSessionDetail,
  ProximityAttestationResult,
  ProximityVerifyResult,
} from './types.js';

const DEFAULT_BASE_URL = 'https://qrauth.io';

/**
 * QRAuth Node.js SDK client.
 *
 * Supports two authentication modes:
 * - **API key** — for QR code management (create, verify, list, revoke, bulk)
 * - **Client credentials** — for auth-session flows (create session, poll, verify result)
 *
 * You can provide both to use all features from a single instance.
 *
 * @example
 * ```ts
 * import { QRAuth } from '@qrauth/node';
 *
 * // QR code management only
 * const qrauth = new QRAuth({ apiKey: process.env.QRAUTH_API_KEY! });
 *
 * // Auth sessions only
 * const qrauth = new QRAuth({
 *   clientId: process.env.QRAUTH_CLIENT_ID!,
 *   clientSecret: process.env.QRAUTH_CLIENT_SECRET!,
 * });
 *
 * // Both
 * const qrauth = new QRAuth({
 *   apiKey: process.env.QRAUTH_API_KEY!,
 *   clientId: process.env.QRAUTH_CLIENT_ID!,
 *   clientSecret: process.env.QRAUTH_CLIENT_SECRET!,
 * });
 * ```
 */
export class QRAuth {
  private readonly apiKey?: string;
  private readonly clientId?: string;
  private readonly clientSecret?: string;
  private readonly baseUrl: string;

  constructor(options: QRAuthOptions) {
    if (!options.apiKey && !options.clientId) {
      throw new Error('QRAuth: provide at least apiKey or clientId');
    }
    this.apiKey = options.apiKey;
    this.clientId = options.clientId;
    this.clientSecret = options.clientSecret;
    this.baseUrl = (options.baseUrl || DEFAULT_BASE_URL).replace(/\/+$/, '');
  }

  // -------------------------------------------------------------------------
  // QR Code — create
  // -------------------------------------------------------------------------

  /**
   * Generate a cryptographically signed QR code.
   *
   * Tokens are issued in signed batches via a Merkle tree whose root is
   * signed with the tenant's SLH-DSA-SHA2-128s key (FIPS 205). The
   * returned `merkle_batch_id` identifies the batch the token belongs
   * to; individual token authenticity is provable via the Merkle
   * inclusion proof stored server-side. The per-token ECDSA-P256
   * `signature` field is retained for classical-verifier compatibility.
   *
   * Default `alg_version` is `HYBRID_ECDSA_SLHDSA_V1` — both legs must
   * verify at scan time.
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
   *
   * The returned `security` object includes `algVersion`,
   * `algVersionStatus`, `pqcProtected`, `merkleProofValid`, and
   * `merkleBatchId` for audit purposes. Both the ECDSA and the
   * SLH-DSA/Merkle legs must pass for hybrid-signed tokens; a
   * `merkleProofValid: false` means the PQC leg failed even if the
   * classical leg succeeded, and the verifier rejects the token.
   *
   * If `warnings` is present and non-empty, at least one deprecation
   * or advisory condition was detected — surface these to operators
   * via your dashboard, not to end users. See `isAlgDeprecated` for
   * the most common case (a token signed under a sunsetting
   * algorithm version).
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
   * Generate multiple signed QR codes in a single request (max 64).
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
  // Auth Sessions — create
  // -------------------------------------------------------------------------

  /**
   * Create an auth session for QR-based login.
   *
   * Requires `clientId` and `clientSecret` to be configured.
   *
   * @example
   * ```ts
   * const session = await qrauth.createAuthSession({
   *   scopes: ['identity', 'email'],
   * });
   * // session.qrUrl  — encode this in a QR code
   * // session.sessionId — use to poll status or verify result
   * ```
   */
  async createAuthSession(options: CreateAuthSessionOptions = {}): Promise<AuthSessionResponse> {
    return this.request<AuthSessionResponse>('POST', '/api/v1/auth-sessions', options, {}, 'client');
  }

  // -------------------------------------------------------------------------
  // Auth Sessions — poll status
  // -------------------------------------------------------------------------

  /**
   * Get the current status of an auth session.
   *
   * For PKCE sessions, provide `codeVerifier` to access the user data
   * once the session is approved.
   *
   * @example
   * ```ts
   * const status = await qrauth.getAuthSession(sessionId);
   * if (status.status === 'APPROVED') {
   *   console.log(status.user);
   * }
   * ```
   */
  async getAuthSession(sessionId: string, options?: GetAuthSessionOptions): Promise<AuthSessionStatus> {
    const params = new URLSearchParams();
    if (options?.codeVerifier) params.set('code_verifier', options.codeVerifier);

    const qs = params.toString();
    const path = `/api/v1/auth-sessions/${encodeURIComponent(sessionId)}${qs ? `?${qs}` : ''}`;

    return this.request<AuthSessionStatus>('GET', path, undefined, {}, 'client');
  }

  // -------------------------------------------------------------------------
  // Auth Sessions — verify result
  // -------------------------------------------------------------------------

  /**
   * Verify an approved auth session from your backend callback.
   *
   * Call this after your frontend receives `onSuccess` from the browser SDK.
   * Confirms the session is genuinely approved and the signature is valid.
   *
   * @example
   * ```ts
   * // In your backend callback handler:
   * const result = await qrauth.verifyAuthResult(sessionId, signature);
   * if (result.valid) {
   *   const user = result.session.user;
   *   // Issue your own JWT / session for the user
   * }
   * ```
   */
  async verifyAuthResult(sessionId: string, signature: string): Promise<AuthSessionVerifyResult> {
    return this.request<AuthSessionVerifyResult>(
      'POST',
      '/api/v1/auth-sessions/verify-result',
      { sessionId, signature },
      {},
      'client',
    );
  }

  // -------------------------------------------------------------------------
  // Auth Sessions — proxy handlers
  // -------------------------------------------------------------------------

  /**
   * Returns framework-agnostic handlers for proxying auth-session requests.
   *
   * The browser SDK needs to call QRAuth's auth-session endpoints, but
   * browsers can't send client credentials directly. These handlers let you
   * set up proxy routes in 3 lines instead of writing raw fetch + Basic auth.
   *
   * @example
   * ```ts
   * // Fastify
   * const proxy = qrauth.authSessionHandlers();
   *
   * app.post('/api/v1/auth-sessions', async (req, reply) => {
   *   const { status, body } = await proxy.createSession(req.body);
   *   reply.status(status).send(body);
   * });
   *
   * app.get('/api/v1/auth-sessions/:id', async (req, reply) => {
   *   const { status, body } = await proxy.getSession(req.params.id, req.query);
   *   reply.status(status).send(body);
   * });
   * ```
   */
  authSessionHandlers() {
    const self = this;

    return {
      /**
       * Proxy: create an auth session. Pass the request body through.
       */
      async createSession(body: unknown): Promise<{ status: number; body: unknown }> {
        return self.proxyRequest('POST', '/api/v1/auth-sessions', body);
      },

      /**
       * Proxy: poll session status. Pass query params (e.g. code_verifier) through.
       */
      async getSession(
        sessionId: string,
        query?: Record<string, string>,
      ): Promise<{ status: number; body: unknown }> {
        const params = new URLSearchParams(query);
        const qs = params.toString();
        const path = `/api/v1/auth-sessions/${encodeURIComponent(sessionId)}${qs ? `?${qs}` : ''}`;
        return self.proxyRequest('GET', path);
      },

      /**
       * Verify an auth result (sessionId + signature). Equivalent to verifyAuthResult()
       * but returns the raw status + body for proxy use.
       */
      async verifyResult(
        sessionId: string,
        signature: string,
      ): Promise<{ status: number; body: unknown }> {
        return self.proxyRequest('POST', '/api/v1/auth-sessions/verify-result', { sessionId, signature });
      },
    };
  }

  // -------------------------------------------------------------------------
  // Ephemeral Sessions — create
  // -------------------------------------------------------------------------

  /**
   * Create an ephemeral session for time-limited, scope-constrained access.
   * No account creation required — the scanned user gets a scoped JWT.
   *
   * @example
   * ```ts
   * const session = await qrauth.createEphemeralSession({
   *   scopes: ['read:menu', 'write:order'],
   *   ttl: '30m',
   *   maxUses: 1,
   *   deviceBinding: true,
   *   metadata: { table: 'A12' },
   * });
   * // session.claimUrl — encode in QR code
   * ```
   */
  async createEphemeralSession(options: CreateEphemeralSessionOptions): Promise<EphemeralSessionResponse> {
    return this.request<EphemeralSessionResponse>('POST', '/api/v1/ephemeral', options, {}, 'client');
  }

  // -------------------------------------------------------------------------
  // Ephemeral Sessions — claim
  // -------------------------------------------------------------------------

  /**
   * Claim an ephemeral session. Called when a user scans the QR code.
   */
  async claimEphemeralSession(
    token: string,
    options?: ClaimEphemeralSessionOptions,
  ): Promise<EphemeralSessionClaimResult> {
    return this.request<EphemeralSessionClaimResult>(
      'POST',
      `/api/v1/ephemeral/${encodeURIComponent(token)}/claim`,
      options || {},
    );
  }

  // -------------------------------------------------------------------------
  // Ephemeral Sessions — revoke
  // -------------------------------------------------------------------------

  /**
   * Revoke an ephemeral session immediately. The session can no longer be claimed.
   */
  async revokeEphemeralSession(sessionId: string): Promise<{ status: string }> {
    return this.request<{ status: string }>('DELETE', `/api/v1/ephemeral/${encodeURIComponent(sessionId)}`, undefined, {}, 'client');
  }

  // -------------------------------------------------------------------------
  // Ephemeral Sessions — list
  // -------------------------------------------------------------------------

  /**
   * List ephemeral sessions for the authenticated app.
   */
  async listEphemeralSessions(
    options?: ListEphemeralSessionsOptions,
  ): Promise<PaginatedResponse<EphemeralSessionDetail>> {
    const params = new URLSearchParams();
    if (options?.status) params.set('status', options.status);
    if (options?.page) params.set('page', String(options.page));
    if (options?.pageSize) params.set('pageSize', String(options.pageSize));

    const qs = params.toString();
    return this.request<PaginatedResponse<EphemeralSessionDetail>>(
      'GET',
      `/api/v1/ephemeral${qs ? `?${qs}` : ''}`,
      undefined,
      {},
      'client',
    );
  }

  // -------------------------------------------------------------------------
  // Proximity Attestation
  // -------------------------------------------------------------------------

  async getProximityAttestation(
    token: string,
    args: {
      clientLat: number;
      clientLng: number;
      /** Relying-party identifier the attestation is bound to (AUDIT-FINDING-006). */
      rpId: string;
      /** Caller-supplied device identity — SHA3-256 hashed into the `device` claim. */
      deviceFingerprint: string;
    },
  ): Promise<ProximityAttestationResult> {
    return this.request<ProximityAttestationResult>(
      'POST',
      `/api/v1/proximity/${encodeURIComponent(token)}`,
      args,
    );
  }

  async verifyProximityAttestation(
    jwt: string,
    publicKey?: string,
  ): Promise<ProximityVerifyResult> {
    return this.request<ProximityVerifyResult>(
      'POST',
      '/api/v1/proximity/verify',
      { jwt, ...(publicKey ? { publicKey } : {}) },
    );
  }

  // -------------------------------------------------------------------------
  // Internal HTTP client
  // -------------------------------------------------------------------------

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    extraHeaders?: Record<string, string>,
    auth: 'apikey' | 'client' = 'apikey',
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;

    const headers: Record<string, string> = {
      'User-Agent': 'qrauth-node/0.1.0',
      ...extraHeaders,
    };

    // Set auth header based on mode
    if (auth === 'client') {
      if (!this.clientId || !this.clientSecret) {
        throw new Error('QRAuth: clientId and clientSecret are required for auth-session methods');
      }
      headers['Authorization'] = `Basic ${Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64')}`;
    } else {
      if (!this.apiKey) {
        throw new Error('QRAuth: apiKey is required for QR code management methods');
      }
      headers['X-API-Key'] = this.apiKey;
    }

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

  /**
   * Low-level proxy request: returns raw { status, body } instead of throwing on errors.
   * Used by authSessionHandlers() to forward responses as-is to the caller's client.
   */
  private async proxyRequest(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<{ status: number; body: unknown }> {
    if (!this.clientId || !this.clientSecret) {
      throw new Error('QRAuth: clientId and clientSecret are required for auth-session proxy');
    }

    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = {
      'User-Agent': 'qrauth-node/0.1.0',
      'Authorization': `Basic ${Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64')}`,
    };

    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
    }

    const res = await fetch(url, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });

    const responseBody = await res.json().catch(() => ({}));
    return { status: res.status, body: responseBody };
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
