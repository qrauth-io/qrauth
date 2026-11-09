import {
  QRAuthError,
  AuthenticationError,
  AuthorizationError,
  ConflictError,
  NotFoundError,
  RateLimitError,
  ValidationError,
  formatApiErrorMessage,
} from './errors.js';
import type {
  QRAuthOptions,
  CreateQRCodeOptions,
  QRCodeResponse,
  ListQRCodesOptions,
  QRCodeDetail,
  QRCodeImage,
  QRCodeImageOptions,
  GetHistoryOptions,
  QRCodeHistory,
  UpdatedQRCode,
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
  Tag,
  CreateTagOptions,
  UpdateTagOptions,
  Folder,
  ListFoldersResponse,
  BulkTagOptions,
  BulkOrganizeResult,
  AuditEntry,
  AuditExportParams,
  AuditFilterParams,
  AuditListParams,
  AuditPage,
  AllowlistEntryInput,
  OrgPolicy,
  PolicyPreview,
  UpdatePolicyOptions,
  BulkDryRun,
  BulkExportLink,
  BulkExportOptions,
  BulkJob,
} from './types.js';

/** Sent as User-Agent on every request; keep in step with package.json. */
export const SDK_VERSION = '0.6.0';
const USER_AGENT = `qrauth-node/${SDK_VERSION}`;

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
    const body: Record<string, unknown> = {};

    if (options.destination !== undefined) body.destinationUrl = options.destination;
    if (options.label) body.label = options.label;
    if (options.contentType) body.contentType = options.contentType;
    if (options.content) body.content = options.content;
    if (options.scanMode) body.scanMode = options.scanMode;

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
   * List QR codes for your organization, newest first. `q`, `contentType`,
   * `tagIds` and `folderId` narrow the list; they combine with each other
   * and with `status`. A tag or folder id that is not your organization's
   * is a `NotFoundError`.
   *
   * @example
   * const { data } = await qrauth.list({ q: 'menu', folderId: 'unfiled' });
   */
  async list(options?: ListQRCodesOptions): Promise<PaginatedResponse<QRCodeDetail>> {
    const params = new URLSearchParams();
    if (options?.page) params.set('page', String(options.page));
    if (options?.pageSize) params.set('pageSize', String(options.pageSize));
    if (options?.status) params.set('status', options.status);
    if (options?.q) params.set('q', options.q);
    if (options?.contentType) params.set('contentType', options.contentType);
    if (options?.tagIds?.length) params.set('tagIds', options.tagIds.join(','));
    if (options?.folderId) params.set('folderId', options.folderId);
    if (options?.outsidePolicy !== undefined) params.set('outsidePolicy', String(options.outsidePolicy));

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
  // QR Code — image
  // -------------------------------------------------------------------------

  /**
   * Download a code's image: PNG or SVG at a screen size, or a print-size
   * PNG or vector PDF (paid plans). See `QRCodeImageOptions` for the limits.
   *
   * @example
   * const pdf = await qrauth.image('abc123', { format: 'pdf', sizeMm: 50 });
   * await writeFile(pdf.filename ?? 'code.pdf', pdf.data);
   */
  async image(token: string, options: QRCodeImageOptions = {}): Promise<QRCodeImage> {
    const query = new URLSearchParams();
    const params: Array<[string, string | number | undefined]> = [
      ['format', options.format],
      ['px', options.px],
      ['size_mm', options.sizeMm],
      ['size_in', options.sizeIn],
      ['dpi', options.dpi],
      ['margin_mm', options.marginMm],
    ];
    for (const [name, value] of params) {
      if (value !== undefined) query.set(name, String(value));
    }
    const qs = query.toString();
    const res = await this.fetchRaw('GET', `/api/v1/qrcodes/${encodeURIComponent(token)}/image${qs ? `?${qs}` : ''}`);
    const px = Number(res.headers.get('x-qrauth-image-px'));
    const disposition = res.headers.get('content-disposition');
    return {
      data: Buffer.from(await res.arrayBuffer()),
      contentType: res.headers.get('content-type') ?? 'application/octet-stream',
      etag: res.headers.get('etag'),
      filename: disposition ? (/filename="([^"]+)"/.exec(disposition)?.[1] ?? null) : null,
      ...(px > 0 ? { px } : {}),
    };
  }

  // -------------------------------------------------------------------------
  // QR Code — revoke
  // -------------------------------------------------------------------------

  /**
   * Revoke a QR code. It will no longer verify successfully.
   *
   * The API replies 204 No Content, so there is no response body to return.
   */
  async revoke(token: string): Promise<void> {
    await this.request<void>('DELETE', `/api/v1/qrcodes/${encodeURIComponent(token)}`);
  }

  // -------------------------------------------------------------------------
  // QR Code — edit history
  // -------------------------------------------------------------------------

  /**
   * A code's edit history, newest first: one revision per change to its
   * destination, content, style, expiry, scan mode or status. Every role
   * can read it. Another organization's code is a `NotFoundError`.
   *
   * @example
   * const { data } = await qrauth.getHistory('abc123', { pageSize: 50 });
   * for (const rev of data) console.log(rev.revision, rev.kind, Object.keys(rev.changes));
   */
  async getHistory(token: string, options?: GetHistoryOptions): Promise<QRCodeHistory> {
    const params = new URLSearchParams();
    if (options?.page) params.set('page', String(options.page));
    if (options?.pageSize) params.set('pageSize', String(options.pageSize));

    const qs = params.toString();
    return this.request<QRCodeHistory>('GET', `/api/v1/qrcodes/${encodeURIComponent(token)}/history${qs ? `?${qs}` : ''}`);
  }

  /**
   * Restore the destination (URL codes) or content (other types) a code had
   * right after `revision`. The restored value must meet the rules a
   * PATCH meets today; the code is re-signed and a `RESTORED` revision is
   * recorded. Needs an OWNER, ADMIN or MANAGER key.
   *
   * A 409 (`statusCode` 409) means the value is already current, the code
   * is revoked, or that revision's value is no longer in the history; a 422
   * means the value no longer meets the rules or its destination is flagged.
   *
   * @example
   * const qr = await qrauth.restoreDestination('abc123', 3);
   */
  async restoreDestination(token: string, revision: number): Promise<UpdatedQRCode> {
    if (!Number.isInteger(revision) || revision < 1) {
      throw new Error(`QRAuth: revision must be a positive integer, got ${revision}`);
    }
    return this.request<UpdatedQRCode>(
      'POST',
      `/api/v1/qrcodes/${encodeURIComponent(token)}/history/${revision}/restore`,
    );
  }

  // -------------------------------------------------------------------------
  // QR Code — bulk create
  // -------------------------------------------------------------------------

  /**
   * Generate multiple signed URL QR codes in a single request (max 64).
   * Bulk create makes URL codes only; use `create()` for other content types.
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
        scanMode: item.scanMode,
      })),
    };

    return this.request<BulkCreateResponse>('POST', '/api/v1/qrcodes/bulk', body);
  }

  // -------------------------------------------------------------------------
  // QR Code — tags
  //
  // Tags are organization-wide labels; a code can carry many. Every role can
  // read them; OWNER, ADMIN, MANAGER and MEMBER keys can change them (a
  // VIEWER key gets `AuthorizationError`). Another organization's tag id is
  // a `NotFoundError`.
  // -------------------------------------------------------------------------

  /** List your organization's tags, sorted by name, with their code counts. */
  async listTags(): Promise<Tag[]> {
    const res = await this.request<{ data: Tag[] }>('GET', '/api/v1/tags');
    return res.data;
  }

  /**
   * Create a tag (up to 100 per organization). A name already used (ignoring
   * case) or the limit reached is a `ConflictError` with `reason`
   * `'name-taken'` or `'limit-reached'`.
   */
  async createTag(options: CreateTagOptions): Promise<Tag> {
    return this.request<Tag>('POST', '/api/v1/tags', options);
  }

  /** Rename a tag or change its colour. */
  async updateTag(tagId: string, options: UpdateTagOptions): Promise<Tag> {
    return this.request<Tag>('PATCH', `/api/v1/tags/${encodeURIComponent(tagId)}`, options);
  }

  /** Delete a tag. It is removed from every code that carries it. */
  async deleteTag(tagId: string): Promise<void> {
    await this.request<void>('DELETE', `/api/v1/tags/${encodeURIComponent(tagId)}`);
  }

  // -------------------------------------------------------------------------
  // QR Code — folders
  //
  // Folders are flat; a code is in at most one folder, or unfiled. Same
  // roles and errors as tags.
  // -------------------------------------------------------------------------

  /** List your organization's folders, sorted by name, and the number of unfiled codes. */
  async listFolders(): Promise<ListFoldersResponse> {
    return this.request<ListFoldersResponse>('GET', '/api/v1/folders');
  }

  /**
   * Create a folder (up to 200 per organization). A name already used
   * (ignoring case) or the limit reached is a `ConflictError`.
   */
  async createFolder(name: string): Promise<Folder> {
    return this.request<Folder>('POST', '/api/v1/folders', { name });
  }

  /** Rename a folder. */
  async renameFolder(folderId: string, name: string): Promise<Folder> {
    return this.request<Folder>('PATCH', `/api/v1/folders/${encodeURIComponent(folderId)}`, { name });
  }

  /** Delete a folder. Its codes become unfiled; they are not deleted. */
  async deleteFolder(folderId: string): Promise<void> {
    await this.request<void>('DELETE', `/api/v1/folders/${encodeURIComponent(folderId)}`);
  }

  // -------------------------------------------------------------------------
  // QR Code — bulk tag and move
  // -------------------------------------------------------------------------

  /**
   * Add and/or remove tags on up to 100 codes. Tokens that are not your
   * organization's come back in `notFound`; the others are updated. Adding a
   * tag a code already has is not an error.
   *
   * @example
   * await qrauth.bulkTag(['abc123', 'def456'], { add: [tag.id] });
   */
  async bulkTag(tokens: string[], options: BulkTagOptions): Promise<BulkOrganizeResult> {
    return this.request<BulkOrganizeResult>('POST', '/api/v1/qrcodes/bulk-tag', { tokens, ...options });
  }

  /** Move up to 100 codes into a folder, or out of any folder with `null`. */
  async bulkMove(tokens: string[], folderId: string | null): Promise<BulkOrganizeResult> {
    return this.request<BulkOrganizeResult>('POST', '/api/v1/qrcodes/bulk-move', { tokens, folderId });
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
  // Audit log
  // -------------------------------------------------------------------------

  /**
   * One page of your organization's audit log, newest first: changes to
   * settings, members, API keys, sign-in clients and QR codes. Needs an
   * OWNER or ADMIN key and the Business plan or above; otherwise an
   * `AuthorizationError` with `reason` `'audit-role-required'` or
   * `'governance-plan-required'`.
   *
   * @example
   * const page = await qrauth.listAuditEntries({ action: 'apiKey.revoke', limit: 20 });
   * if (page.nextCursor) await qrauth.listAuditEntries({ cursor: page.nextCursor });
   */
  async listAuditEntries(params: AuditListParams = {}): Promise<AuditPage> {
    const query = auditQuery(params);
    if (params.cursor) query.set('cursor', params.cursor);
    if (params.limit !== undefined) query.set('limit', String(params.limit));
    const qs = query.toString();
    return this.request<AuditPage>('GET', `/api/v1/audit${qs ? `?${qs}` : ''}`);
  }

  /**
   * Every matching audit entry, newest first, fetching pages as needed.
   * `limit` sets the page size; `cursor` starts after a known page.
   *
   * @example
   * for await (const entry of qrauth.iterateAuditEntries({ actorType: 'API_KEY' })) {
   *   console.log(entry.createdAt, entry.label);
   * }
   */
  async *iterateAuditEntries(params: AuditListParams = {}): AsyncGenerator<AuditEntry, void, undefined> {
    let cursor = params.cursor;
    do {
      const page = await this.listAuditEntries({ ...params, cursor });
      yield* page.data;
      cursor = page.nextCursor ?? undefined;
    } while (cursor);
  }

  /**
   * Every matching audit entry as CSV text (header row first, CRLF line
   * endings), from `GET /api/v1/audit/export.csv`. Columns: time, action,
   * description, actor_type, actor_id, actor, resource_type, resource_id,
   * resource_name, request_id, ip_address, user_agent, details (JSON). Cells
   * starting with `=`, `+`, `-`, `@`, tab or carriage return are prefixed
   * with an apostrophe so spreadsheets do not read them as formulas. Same
   * role and plan requirements as `listAuditEntries()`.
   *
   * @example
   * await writeFile('audit.csv', await qrauth.exportAuditCsv({ from: '2026-10-01T00:00:00Z', to: '2026-10-31T23:59:59Z' }));
   */
  async exportAuditCsv(params: AuditExportParams): Promise<string> {
    const qs = auditQuery(params).toString();
    const res = await this.fetchRaw('GET', `/api/v1/audit/export.csv${qs ? `?${qs}` : ''}`);
    return res.text();
  }

  // -------------------------------------------------------------------------
  // Organization policies
  // -------------------------------------------------------------------------

  /**
   * The organization's policy: the destination allowlist and the lowest
   * role that may change a code's destination. Needs an OWNER or ADMIN key.
   */
  async getPolicy(): Promise<OrgPolicy> {
    return this.request<OrgPolicy>('GET', '/api/v1/policies');
  }

  /**
   * Replaces the organization's policy and returns it. Domains are reduced
   * to their registrable domain (Public Suffix List) and stored in punycode;
   * invalid entries are refused with status 422 and nothing changes. When the
   * allowlist is enforced, codes outside it keep working and are marked
   * `outsidePolicy`. Needs an OWNER or ADMIN key and the Business plan or
   * above; below it a policy in force can only be switched off
   * (`AuthorizationError`, `reason` `'governance-plan-required'`).
   *
   * @example
   * await qrauth.updatePolicy({
   *   allowlistMode: 'ENFORCE',
   *   allowlist: [{ domain: 'example.com' }],
   *   destinationEditMinRole: 'MANAGER',
   * });
   */
  async updatePolicy(options: UpdatePolicyOptions): Promise<OrgPolicy> {
    return this.request<OrgPolicy>('PUT', '/api/v1/policies', options);
  }

  /**
   * How an allowlist would be stored and which active codes it would leave
   * outside, without changing anything. Business plan and above.
   */
  async previewPolicy(allowlist: AllowlistEntryInput[]): Promise<PolicyPreview> {
    return this.request<PolicyPreview>('POST', '/api/v1/policies/preview', { allowlist });
  }

  // -------------------------------------------------------------------------
  // Bulk import and export (Business plan and above)
  // -------------------------------------------------------------------------

  /** The CSV import template (columns url, label, folder, tags, expiresAt, scanMode). */
  async getBulkImportTemplate(): Promise<string> {
    const res = await this.fetchRaw('GET', '/api/v1/bulk/imports/template.csv');
    return res.text();
  }

  /**
   * Checks a CSV file (UTF-8, `,` or `;` delimited, at most 1 MB and 1,000
   * rows) with the rules of `create()` and returns every row's status; nothing
   * is created. Commit the result with `commitBulkImport(dryRun.id)` within an
   * hour, with the same API key. A refused file (unknown columns, more than
   * 1,000 rows, not UTF-8) is a `QRAuthError` with `statusCode` 422 and the
   * reason in its message. Needs a MEMBER key or higher. A date-only
   * `expiresAt` (`2027-12-31`) ends at 23:59:59 that day in
   * `options.timezone` (an IANA name such as `'Europe/Athens'`; default UTC).
   *
   * @example
   * const dryRun = await qrauth.bulkImportDryRun(await readFile('codes.csv'));
   * if (dryRun.totals.error === 0) await qrauth.commitBulkImport(dryRun.id);
   */
  async bulkImportDryRun(csv: string | Uint8Array, options: { timezone?: string } = {}): Promise<BulkDryRun> {
    const qs = options.timezone ? `?timezone=${encodeURIComponent(options.timezone)}` : '';
    return this.request<BulkDryRun>('POST', `/api/v1/bulk/imports/dry-run${qs}`, csv, { 'Content-Type': 'text/csv' }, 'apikey', 'raw');
  }

  /** A dry run made with this API key, while it is still valid (an hour). */
  async getBulkImportDryRun(dryRunId: string): Promise<BulkDryRun> {
    return this.request<BulkDryRun>('GET', `/api/v1/bulk/imports/dry-run/${encodeURIComponent(dryRunId)}`);
  }

  /**
   * Starts the import of a dry run's valid rows. Rows are checked again when
   * the job runs (policy, quota and Web Risk may have changed); rows that fail
   * are skipped. One import runs at a time per organization: another one is a
   * `ConflictError` with `reason` `'bulk-job-active'`.
   */
  async commitBulkImport(dryRunId: string): Promise<BulkJob> {
    return this.request<BulkJob>('POST', `/api/v1/bulk/imports/dry-run/${encodeURIComponent(dryRunId)}/commit`);
  }

  /** An import or export job started with this API key. */
  async getBulkJob(jobId: string): Promise<BulkJob> {
    return this.request<BulkJob>('GET', `/api/v1/bulk/jobs/${encodeURIComponent(jobId)}`);
  }

  /** Polls a job until it is SUCCEEDED or FAILED (default every 2 s, for up to 10 minutes). */
  async waitForBulkJob(jobId: string, options: { intervalMs?: number; timeoutMs?: number } = {}): Promise<BulkJob> {
    const intervalMs = options.intervalMs ?? 2000;
    const deadline = Date.now() + (options.timeoutMs ?? 10 * 60 * 1000);
    for (;;) {
      const job = await this.getBulkJob(jobId);
      if (job.status === 'SUCCEEDED' || job.status === 'FAILED') return job;
      if (Date.now() + intervalMs > deadline) throw new Error(`QRAuth: bulk job ${jobId} did not finish in time`);
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }
  }

  /**
   * An import's results as CSV text: row, status (created, skipped, failed),
   * token, verifyUrl, url, label, error. Starts with a UTF-8 BOM so
   * spreadsheet apps read non-Latin text correctly; formula-looking cells are
   * prefixed with an apostrophe.
   */
  async getBulkImportResultsCsv(jobId: string): Promise<string> {
    const res = await this.fetchRaw('GET', `/api/v1/bulk/imports/${encodeURIComponent(jobId)}/results.csv`);
    return res.text();
  }

  /**
   * Starts a ZIP export of up to 1,000 codes as SVG and/or PNG, with a
   * manifest.csv. Poll it with `waitForBulkJob()`, then `downloadBulkExport()`.
   * One export runs at a time per organization (`ConflictError`, `reason` `'bulk-job-active'`).
   *
   * @example
   * const job = await qrauth.createBulkExport({ selection: { importJobId }, formats: ['svg', 'png'], png: { px: 512 } });
   * await qrauth.waitForBulkJob(job.id);
   * await writeFile('codes.zip', await qrauth.downloadBulkExport(job.id));
   */
  async createBulkExport(options: BulkExportOptions): Promise<BulkJob> {
    return this.request<BulkJob>('POST', '/api/v1/bulk/exports', options);
  }

  /** A download link for a finished export, valid 5 minutes. The ZIP is deleted 24 hours after the export finished. */
  async createBulkExportLink(jobId: string): Promise<BulkExportLink> {
    return this.request<BulkExportLink>('POST', `/api/v1/bulk/exports/${encodeURIComponent(jobId)}/link`);
  }

  /** The ZIP of a finished export (creates a link and downloads it). */
  async downloadBulkExport(jobId: string): Promise<Buffer> {
    const { url } = await this.createBulkExportLink(jobId);
    // The link is the credential: the API key is not sent with it.
    const res = await fetch(url, { headers: { 'User-Agent': USER_AGENT } });
    if (!res.ok) await this.handleError(res);
    return Buffer.from(await res.arrayBuffer());
  }

  // -------------------------------------------------------------------------
  // Internal HTTP client
  // -------------------------------------------------------------------------

  /** An API-key request whose response body is not JSON (images); throws on an error status. */
  private async fetchRaw(method: string, path: string): Promise<Response> {
    if (!this.apiKey) {
      throw new Error('QRAuth: apiKey is required for QR code management methods');
    }
    const res = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers: { 'User-Agent': USER_AGENT, 'X-API-Key': this.apiKey },
    });
    if (!res.ok) {
      await this.handleError(res);
    }
    return res;
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    extraHeaders?: Record<string, string>,
    auth: 'apikey' | 'client' = 'apikey',
    bodyEncoding: 'json' | 'raw' = 'json',
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;

    const headers: Record<string, string> = {
      'User-Agent': USER_AGENT,
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

    if (body !== undefined && bodyEncoding === 'json') {
      headers['Content-Type'] = 'application/json';
    }

    const res = await fetch(url, {
      method,
      headers,
      body: body === undefined ? undefined : bodyEncoding === 'raw' ? (body as BodyInit) : JSON.stringify(body),
    });

    if (!res.ok) {
      await this.handleError(res);
    }

    // Endpoints like DELETE /qrcodes/:token reply 204 with no body; calling
    // res.json() on an empty body throws "Unexpected end of JSON input".
    if (res.status === 204) {
      return undefined as T;
    }
    const text = await res.text();
    return (text ? JSON.parse(text) : undefined) as T;
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
      'User-Agent': USER_AGENT,
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
    let reason: string | undefined;
    try {
      const body = await res.json();
      message = formatApiErrorMessage(body, res.statusText);
      reason = typeof body?.code === 'string' ? body.code : undefined;
    } catch {
      message = res.statusText;
    }

    const options = { requestId: res.headers.get('x-request-id') ?? undefined };
    switch (res.status) {
      case 400:
        throw new ValidationError(message, options);
      case 401:
        throw new AuthenticationError(message, options);
      case 403:
        throw new AuthorizationError(message, { ...options, reason });
      case 404:
        throw new NotFoundError(message, options);
      case 409:
        throw new ConflictError(message, reason, options);
      case 429: {
        const retryAfter = res.headers.get('retry-after');
        throw new RateLimitError(message, retryAfter ? parseInt(retryAfter, 10) : undefined, options);
      }
      default:
        throw new QRAuthError(message, res.status, 'API_ERROR', options);
    }
  }
}

// ---------------------------------------------------------------------------
// Audit log query
// ---------------------------------------------------------------------------

/** Query parameters shared by the audit list and the CSV export. */
function auditQuery(params: AuditFilterParams): URLSearchParams {
  const query = new URLSearchParams();
  const fields: Array<[string, string | undefined]> = [
    ['actor', params.actor],
    ['actorType', params.actorType],
    ['action', params.action],
    ['resourceType', params.resourceType],
    ['resourceId', params.resourceId],
    ['from', toIsoString(params.from)],
    ['to', toIsoString(params.to)],
  ];
  for (const [name, value] of fields) {
    if (value) query.set(name, value);
  }
  return query;
}

function toIsoString(value: Date | string | undefined): string | undefined {
  return value instanceof Date ? value.toISOString() : value;
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
