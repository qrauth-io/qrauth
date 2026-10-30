import type { FastifyInstance, FastifyReply } from 'fastify';
import {
  createQRCodeSchema,
  updateQRCodeSchema,
  bulkCreateQRCodeSchema,
  paginationSchema,
  generateToken,
  getContentType,
  httpUrl,
  isIssuerVerified,
} from '@qrauth/shared';
import { zodValidator, type ScanRuleIssueParams } from '../middleware/validate.js';
import {
  canonicalStyleJson,
  checkStyle,
  parseStoredStyle,
  parseStyle,
  qrStyleV2Schema,
  type QrStyleV2,
} from '@qrauth/shared/qr-render';
import { authorize } from '../middleware/authorize.js';
import {
  rateLimitAuth,
  rateLimitGenerate,
  rateLimitBulk,
  rateLimitPublic,
} from '../middleware/rateLimit.js';
import { SigningService } from '../services/signing.js';
import { HybridSigningService } from '../services/hybrid-signing.js';
import { MacService } from '../services/mac.js';
import { WebhookService } from '../services/webhook.js';
import {
  canonicalizeCore,
  canonicalGeoHash,
  computeDestHash,
  checkAlgVersion,
  ALG_VERSION_POLICY,
} from '@qrauth/shared';
import { GeoService } from '../services/geo.js';
import { TransparencyLogService } from '../services/transparency.js';
import type { MerkleNode } from '../services/merkle-signing.js';
import { DomainService } from '../services/domain.js';
import { cacheDel } from '../lib/cache.js';
import { config } from '../lib/config.js';
import { assertOwnership, buildVerificationUrl } from '../lib/qrcode-access.js';
import { qrImageDataUrl, RENDER_RETRY_AFTER_SECONDS, RenderUnavailableError } from '../services/qr-render.js';
import { assertLogoScans, LogoUnreadableError } from '../services/logo-decode.js';
import { LogoLibrary, LogoNotFoundError, type LogoTx } from '../services/logo-library.js';
import { paginationSkip } from '../lib/pagination.js';
import { notFoundError } from '../lib/responses.js';
import { QuotaUnavailableError, UsageService } from '../services/usage.js';
import {
  CUSTOMER_LOGO_ORG_SELECT,
  contentTypeGateMessage,
  gateRefusalBody,
  logoEligibility,
  qrStyleGate,
} from '../config/plan-limits.js';
import { createHash, randomBytes } from 'node:crypto';
import { stableStringify } from '../lib/crypto.js';
import { isActorEmailVerified, sendEmailNotVerified, verifiedEmailGuard } from '../lib/verified-actor.js';
import { revokeTokensForOrg } from '../services/qr-revocation.js';
import type { ScanMode } from '../services/scan-mode.js';
import {
  DESTINATION_FLAGGED_ERROR,
  destinationFlaggedBody,
  enqueueDestinationRecheck,
  screenDestination,
} from '../services/destination-screening.js';
import { z } from 'zod';

// ---------------------------------------------------------------------------
// Local schemas
// ---------------------------------------------------------------------------

const tokenParamsSchema = z.object({
  token: z.string().min(1, 'Token is required'),
});

// Dashboard QR style (issue #4, ADR-0005 D2). Validated shape, NOT arbitrary
// JSON, so a malformed or oversized style can never reach the `style`
// column. Only v2 bodies are accepted: the window for v1 bodies (one release
// after the dashboard sent v2, PR 3) closed in PR 6. Stored v1 rows still
// render and are upgraded on read. Kept API-side only (off the shared SDK
// createQRCodeSchema contract).
export const STYLE_V1_REJECTED_MESSAGE =
  'Style version 1 (templateId, fgColor, bgColor, showLogo, captionText) is no longer accepted; send a version 2 style ("version": 2).';

/** A body without `version` is the v1 shape (D2): refused with one clear issue instead of v2's field errors. */
const isV1StyleBody = (input: unknown): boolean =>
  typeof input === 'object' && input !== null && !Array.isArray(input) && !('version' in input);

const qrStyleInputSchema = z
  .unknown()
  .superRefine((input, ctx) => {
    if (isV1StyleBody(input)) ctx.addIssue({ code: 'custom', message: STYLE_V1_REJECTED_MESSAGE });
  })
  .pipe(qrStyleV2Schema);

export const qrStyleSchema = qrStyleInputSchema
  // Scannability rules (ADR-0005 D4) on every write that carries a style:
  // the contrast floors (3:1, 3.5:1 with a logo, 7:1 light-on-dark with a
  // logo), polarity, the EC floor and the rest of checkStyle. A failure is
  // 422 with the rule's code (middleware/validate.ts). Stored styles are
  // never re-checked on read.
  .superRefine((input, ctx) => {
    // zod still runs this after a field failed; those failures are reported
    // already, and the rules need a well-formed style.
    if (!qrStyleInputSchema.safeParse(input).success) return;
    const style = parseStyle(input);
    for (const issue of checkStyle(style).errors) {
      const params: ScanRuleIssueParams = { scanRule: issue.code };
      ctx.addIssue({ code: 'custom', message: issue.message, params });
    }
  })
  .transform((input): QrStyleV2 => parseStyle(input));

export type QrStyle = z.output<typeof qrStyleSchema>;

// ---------------------------------------------------------------------------
// Customer logos in styles (ADR-0005 PR 4)
// ---------------------------------------------------------------------------

export const LOGO_NOT_FOUND_MESSAGE = 'The logo was not found in this organization’s logo library.';
/** The 422 message for a logo that did not read back, naming the raster that failed. */
export function logoUnreadableMessage(raster: string): string {
  return `The code could not be read back with this logo at ${raster}. Use a smaller logo, a simpler logo or higher contrast.`;
}

/** 422 for a style's logo, in the scan-rule envelope (middleware/validate.ts). */
function sendStyleLogoRejected(reply: FastifyReply, code: 'logo-not-found' | 'logo-unreadable', message: string): FastifyReply {
  return reply.status(422).send({
    statusCode: 422,
    error: 'Unprocessable Entity',
    code,
    message,
    details: [{ path: ['body', 'qrStyle', 'logo'], code, message }],
  });
}

function sendRenderUnavailable(reply: FastifyReply): FastifyReply {
  return reply
    .status(503)
    .header('Retry-After', String(RENDER_RETRY_AFTER_SECONDS))
    .send({ statusCode: 503, error: 'Service Unavailable', message: 'QR image rendering is unavailable; retry shortly. No code was created.' });
}

/**
 * True when `submitted` is the code's stored style (v1 upgraded, none read
 * as DEFAULT_STYLE), compared canonically (sorted keys, upper-case colours).
 * A stored style that cannot be read is never equal.
 */
export function isSameAsStoredStyle(stored: unknown, submitted: QrStyleV2): boolean {
  try {
    return canonicalStyleJson(parseStoredStyle(stored)) === canonicalStyleJson(submitted);
  } catch {
    return false;
  }
}

/**
 * The frame of the code's stored style (v1 `captionText` upgraded to a
 * caption frame), or null when it has none or cannot be read. A stored
 * caption is grandfathered on FREE (ADR-0005 D9, 2026-10-30).
 */
export function storedFrameOf(stored: unknown): QrStyleV2['frame'] | null {
  try {
    return parseStoredStyle(stored).frame ?? null;
  } catch {
    return null;
  }
}

/**
 * The save-time decode round trip for a style with a customer logo: throws
 * LogoUnreadableError when a raster does not read back, and
 * RenderUnavailableError when rendering itself fails (queue busy).
 */
async function checkLogoScans(token: string, style: QrStyle, assetLogo: Uint8Array): Promise<void> {
  try {
    await assertLogoScans(buildVerificationUrl(token), style, assetLogo);
  } catch (err) {
    if (err instanceof LogoUnreadableError) throw err;
    throw new RenderUnavailableError(err);
  }
}

const listQRCodesQuerySchema = paginationSchema.extend({
  status: z.enum(['ACTIVE', 'EXPIRED', 'REVOKED']).optional(),
});

// Extends the shared createQRCodeSchema with optional content-type fields.
// `destinationUrl` is made optional so non-URL content types (vCard, event,
// …) can omit it — their destination is the verify page. The superRefine
// then re-requires it for URL-type QRs; without that guard an empty URL
// reaches prisma.qRCode.create() as undefined and 500s on the required column.
export const extendedCreateSchema = createQRCodeSchema
  .extend({
    destinationUrl: httpUrl().optional(), // Override: optional for content types; http(s) only, same as PATCH
    contentType: z.string().optional(),
    content: z.any().optional(),
    qrStyle: qrStyleSchema.optional(), // Dashboard style prefs (#4) — API-side only.
  })
  .superRefine((data, ctx) => {
    // contentType defaults to 'url' downstream when unset, so treat unset as url.
    if ((data.contentType ?? 'url') === 'url' && !data.destinationUrl) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['destinationUrl'],
        message: 'Destination URL is required for URL QR codes',
      });
    }
  });

// POST /bulk-revoke body: 1–100 tokens of the caller's organization.
export const bulkRevokeSchema = z
  .object({ tokens: z.array(z.string().min(1).max(64)).min(1).max(100) })
  .strict();

// Extends the shared updateQRCodeSchema with the optional API-side `qrStyle`
// field (#4), so dashboard style edits persist without leaking the field onto
// the shared SDK update contract. Style is presentational only — it is NOT part
// of the signed payload, so updating it never triggers a re-sign.
export const extendedUpdateSchema = updateQRCodeSchema.extend({
  qrStyle: qrStyleSchema.optional(),
});

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Recompute the symmetric MAC fast path (ALGORITHM.md §7, AUDIT-FINDING-011)
 * over the SAME canonical core string the ECDSA/Merkle legs sign, then sign
 * it. Shared by QR create and update so both paths stay byte-for-byte in
 * agreement.
 *
 * Best-effort: if the MAC signer is unavailable the caller persists the row
 * without a fast-path MAC (this returns nulls) rather than failing the whole
 * operation. Stored server-side only — never embedded in the QR.
 */
async function recomputeAndSignMac(
  macService: MacService,
  log: FastifyInstance['log'],
  params: {
    algVersion: string;
    token: string;
    organizationId: string;
    contentType: string;
    destinationUrl: string;
    contentHashHex: string;
    lat: number | null;
    lng: number | null;
    radiusM: number | null;
    expiresAt: string;
  },
): Promise<{ mac: string | null; keyVersion: number | null }> {
  const destHash = await computeDestHash(
    params.contentType,
    params.destinationUrl,
    params.contentHashHex,
  );
  const geoHash = await canonicalGeoHash(params.lat, params.lng, params.radiusM);
  const canonical = canonicalizeCore({
    algVersion: params.algVersion,
    token: params.token,
    tenantId: params.organizationId,
    destHash,
    geoHash,
    expiresAt: params.expiresAt,
  });
  try {
    const result = await macService.signCanonical(params.organizationId, canonical);
    return { mac: result.mac, keyVersion: result.keyVersion };
  } catch (err) {
    log.warn(
      { err, organizationId: params.organizationId },
      'MAC signing unavailable, QR row will lack the fast-path MAC',
    );
    return { mac: null, keyVersion: null };
  }
}

const QUOTA_REPLIED = Symbol('quota-replied');
const QUOTA_UNAVAILABLE_RETRY_AFTER_SECONDS = 30;

/**
 * QR-code quota check. Returns the limit message (or null when allowed).
 * When the count cannot be read it sends 503 itself and returns
 * QUOTA_REPLIED, so issuance never proceeds on an unknown count.
 */
async function checkQrQuota(
  usageService: UsageService,
  orgId: string,
  plan: string,
  reply: FastifyReply,
): Promise<string | null | typeof QUOTA_REPLIED> {
  try {
    return await usageService.checkQuota(orgId, plan, 'qrcodes');
  } catch (err) {
    if (!(err instanceof QuotaUnavailableError)) throw err;
    reply
      .status(503)
      .header('Retry-After', QUOTA_UNAVAILABLE_RETRY_AFTER_SECONDS)
      .send({ statusCode: 503, error: 'Service Unavailable', message: err.message });
    return QUOTA_REPLIED;
  }
}

/**
 * Compares a destination with the domains of verified organizations and, when
 * it is suspiciously similar, records a HIGH fraud incident on the QR code.
 * Non-blocking: the caller keeps going whatever the result. Runs on create and
 * whenever an update changes the destination.
 */
async function checkDestinationSimilarity(
  fastify: FastifyInstance,
  domainService: DomainService,
  qrCodeId: string,
  destinationUrl: string,
  organizationId: string,
): ReturnType<DomainService['checkUrlAgainstVerifiedDomains']> {
  const domainCheck = await domainService.checkUrlAgainstVerifiedDomains(
    destinationUrl,
    organizationId,
  );

  if (domainCheck.isSuspicious) {
    try {
      await fastify.prisma.fraudIncident.create({
        data: {
          qrCodeId,
          type: 'MANUAL_REPORT',
          severity: 'HIGH',
          details: {
            reason: 'suspicious_domain',
            destinationDomain: domainService.extractDomain(destinationUrl),
            similarTo: domainCheck.warnings[0]?.domain,
            verifiedOrg: domainCheck.warnings[0]?.verifiedOrgName,
            similarity: domainCheck.warnings[0]?.similarity,
          } as any,
        },
      });
    } catch (err) {
      fastify.log.warn({ err, qrCodeId }, 'Failed to create suspicious domain fraud incident');
    }
  }

  return domainCheck;
}

/**
 * Core QR code generation logic extracted so it can be reused by both the
 * single-create and bulk-create endpoints without duplication.
 */
async function generateQRCode(
  fastify: FastifyInstance,
  signingService: SigningService,
  hybridSigningService: HybridSigningService,
  macService: MacService,
  geoService: GeoService,
  transparencyService: TransparencyLogService,
  domainService: DomainService,
  organizationId: string,
  input: {
    destinationUrl: string;
    label?: string;
    location?: { lat: number; lng: number; radiusM: number; requireProximity?: boolean };
    expiresAt?: string;
    contentType?: string;
    content?: unknown;
    maxScans?: number;
    maxScansPerDevice?: number;
    scanMode?: ScanMode;
    qrStyle?: QrStyle;
    /** The customer logo's bytes when qrStyle draws one (loaded and scoped by the route). */
    assetLogo?: Uint8Array | null;
    /** The organization is a verified issuer: the badge mark's wording in qr_image_url (D9). */
    issuerVerified: boolean;
  },
) {
  // 1. Resolve and validate content type.
  const resolvedContentType = input.contentType || 'url';
  const typeRegistry = getContentType(resolvedContentType);
  if (!typeRegistry) {
    throw new Error(`Unknown content type: ${resolvedContentType}`);
  }

  let contentHashHex = '';
  if (input.content && resolvedContentType !== 'url') {
    const parseResult = typeRegistry.schema.safeParse(input.content);
    if (!parseResult.success) {
      throw new Error(`Invalid content for type ${resolvedContentType}: ${parseResult.error.message}`);
    }
    // Deterministic JSON for hashing (PostgreSQL JSONB reorders keys alphabetically).
    // SHA-256 here matches the verify-side hashString(stableStringify(...)) call
    // so the destHash computation agrees across sign and verify.
    contentHashHex = createHash('sha256').update(stableStringify(input.content)).digest('hex');
  }

  // Derive destinationUrl for non-URL types (the verify page is the destination).
  const baseUrl = config.server.isDev
    ? `http://localhost:${config.server.port}`
    : config.webauthn.origin;

  // 2. Get active signing key.
  const signingKey = await signingService.getActiveKey(organizationId);

  // 3. Generate a short, unbiased token.
  const token = generateToken();

  // 3a. A customer logo must read back at the checked export sizes before the
  // style is stored (ADR-0005 PR 4); a failure (LogoUnreadableError) stores
  // nothing.
  const assetLogo = input.qrStyle?.logo?.kind === 'asset' ? (input.assetLogo ?? null) : null;
  if (input.qrStyle && assetLogo) await checkLogoScans(token, input.qrStyle, assetLogo);

  // 3b. Render qr_image_url now, before anything is signed or stored: if
  // rendering fails (RenderUnavailableError) nothing is persisted and no
  // quota is used. The image depends only on the token and the style.
  const qrImageUrl = await qrImageDataUrl({ token, issuerVerified: input.issuerVerified }, input.qrStyle ?? null, assetLogo);

  // 4. For non-URL types, the QR code points to the QRAuth verify page itself.
  const destinationUrl = resolvedContentType === 'url'
    ? input.destinationUrl
    : `${baseUrl}/v/${token}`;

  // 5. Encode geohash when location is provided.
  const geoHash = input.location
    ? geoService.encodeGeoHash(input.location.lat, input.location.lng)
    : '';

  const expiresAtStr = input.expiresAt ?? '';
  const expiresAtDate = input.expiresAt ? new Date(input.expiresAt) : null;

  // 6. Sign the canonical payload through the hybrid (ECDSA + SLH-DSA/Merkle)
  //    pipeline and await both legs before persisting. Latency is dominated
  //    by the SLH-DSA batch-root sign, amortized across concurrent enqueues.
  //    Every row is written with all Merkle fields set; there is no
  //    intermediate state (ALGORITHM.md §6.3).
  const hybrid = await hybridSigningService.signSingleQR({
    organizationId,
    signingKeyDbId: signingKey.id,
    signingKeyId: signingKey.keyId,
    token,
    contentType: resolvedContentType,
    destinationUrl,
    contentHashHex,
    expiresAt: expiresAtStr,
    lat: input.location?.lat ?? null,
    lng: input.location?.lng ?? null,
    radiusM: input.location?.radiusM ?? null,
  });
  const signature = hybrid.ecdsaSignature;
  const pqcFields = {
    algVersion: hybrid.algVersion,
    merkleBatchId: hybrid.batchId,
    merkleLeafIndex: hybrid.leafIndex,
    merkleLeafHash: hybrid.leafHash,
    merkleLeafNonce: hybrid.leafNonce,
    merklePath: hybrid.merklePath as unknown as object,
    merkleRoot: hybrid.merkleRoot,
  };

  // 6b. Compute the symmetric MAC fast path (ALGORITHM.md §7,
  //     AUDIT-FINDING-011). The MAC binds the SAME canonical core string
  //     the ECDSA leg signs, so the verifier recomputes it deterministically
  //     from any QR row. Stored server-side only — never embedded in the QR.
  const { mac: macTokenMac, keyVersion: macKeyVersion } = await recomputeAndSignMac(
    macService,
    fastify.log,
    {
      algVersion: pqcFields.algVersion,
      token,
      organizationId,
      contentType: resolvedContentType,
      destinationUrl,
      contentHashHex,
      lat: input.location?.lat ?? null,
      lng: input.location?.lng ?? null,
      radiusM: input.location?.radiusM ?? null,
      expiresAt: expiresAtStr,
    },
  );

  // 7. Persist to database. A style that draws a customer logo is written
  //    under the logo row's lock, after re-checking that the logo still
  //    exists, so a parallel delete cannot leave the code without it
  //    (LogoNotFoundError when it lost the race; nothing is stored).
  const persist = (db: Pick<LogoTx, 'qRCode'>) => db.qRCode.create({
    data: {
      token,
      organizationId,
      signingKeyId: signingKey.id,
      keyId: signingKey.keyId,
      destinationUrl,
      label: input.label,
      contentType: resolvedContentType,
      content: input.content ? (input.content as object) : undefined,
      // Dashboard style preferences. Undefined when omitted → stored NULL;
      // callers fall back to DEFAULT_STYLE on read. Already validated by
      // qrStyleSchema at the route boundary.
      style: input.qrStyle ?? undefined,
      signature,
      geoHash: geoHash || null,
      latitude: input.location?.lat ?? null,
      longitude: input.location?.lng ?? null,
      radiusM: input.location?.radiusM ?? 50,
      // Default true — geo-bound rows fail closed at verify unless explicitly
      // toggled off. Ignored at verify time when lat/lng are null.
      requireProximity: input.location?.requireProximity ?? true,
      status: 'ACTIVE',
      expiresAt: expiresAtDate,
      maxScans: input.maxScans ?? null,
      maxScansPerDevice: input.maxScansPerDevice ?? null,
      // Browser scan behaviour; display only, not part of the signed payload.
      scanMode: input.scanMode ?? 'FLASH',
      algVersion: pqcFields.algVersion,
      merkleBatchId: pqcFields.merkleBatchId,
      merkleLeafIndex: pqcFields.merkleLeafIndex,
      merkleLeafHash: pqcFields.merkleLeafHash,
      merkleLeafNonce: pqcFields.merkleLeafNonce,
      merklePath: pqcFields.merklePath as never,
      macTokenMac,
      macKeyVersion,
    },
  });
  const logoAssetId = input.qrStyle?.logo?.kind === 'asset' ? input.qrStyle.logo.assetId : null;
  const qrCode = logoAssetId
    ? await new LogoLibrary(fastify.prisma).writeWithLogo(organizationId, logoAssetId, persist)
    : await persist(fastify.prisma);

  // 6. Append to transparency log. For hybrid-signed QRs we attach the
  //    commitment-only fields (leaf hash, batch root ref, inclusion proof)
  //    so the public log carries opaque commitments instead of plaintext
  //    hashes — see ALGORITHM.md §8.
  let transparencyLogIndex: number | null = null;
  try {
    const pqcBlock =
      pqcFields.algVersion === 'hybrid-ecdsa-slhdsa-v1' &&
      pqcFields.merkleLeafHash &&
      pqcFields.merkleBatchId &&
      pqcFields.merkleRoot
        ? {
            algVersion: pqcFields.algVersion,
            leafHash: pqcFields.merkleLeafHash,
            batchRootRef: TransparencyLogService.computeBatchRootRef(pqcFields.merkleRoot),
            merkleInclusionProof: pqcFields.merklePath as unknown as MerkleNode[],
          }
        : null;

    const logEntry = await transparencyService.appendEntry({
      id: qrCode.id,
      token: qrCode.token,
      organizationId: qrCode.organizationId,
      destinationUrl: qrCode.destinationUrl,
      geoHash: qrCode.geoHash,
      pqc: pqcBlock,
    });
    transparencyLogIndex = logEntry.logIndex;
  } catch (err) {
    fastify.log.warn({ err, qrCodeId: qrCode.id }, 'Failed to append transparency log entry');
  }

  // 7. Check destination domain against verified org domains (non-blocking).
  const domainCheck = await checkDestinationSimilarity(
    fastify,
    domainService,
    qrCode.id,
    destinationUrl,
    organizationId,
  );

  const verificationUrl = buildVerificationUrl(qrCode.token);

  return {
    token: qrCode.token,
    verification_url: verificationUrl,
    qr_image_url: qrImageUrl,
    signature: qrCode.signature,
    organization_id: qrCode.organizationId,
    label: qrCode.label,
    created_at: qrCode.createdAt,
    expires_at: qrCode.expiresAt,
    transparency_log_index: transparencyLogIndex,
    // PQC fields — present on every new token since the hybrid
    // cutover. `alg_version` is authoritative; `merkle_batch_id` is
    // null for legacy or async-pending rows.
    alg_version: qrCode.algVersion,
    merkle_batch_id: qrCode.merkleBatchId,
    scan_mode: qrCode.scanMode,
    ...(domainCheck.warnings.length > 0 ? {
      domain_warnings: domainCheck.warnings.map((w) => ({
        similar_to: w.domain,
        verified_org: w.verifiedOrgName,
        similarity: w.similarity,
        reason: w.reason,
      })),
    } : {}),
  };
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

export default async function qrCodeRoutes(fastify: FastifyInstance): Promise<void> {
  const signingService = fastify.signingService;
  const hybridSigningService = new HybridSigningService(
    fastify.prisma,
    signingService,
    fastify.batchSigner,
  );
  const macService = new MacService(fastify.prisma);
  const geoService = new GeoService(fastify.prisma);
  const transparencyService = new TransparencyLogService(fastify.prisma);
  const domainService = new DomainService(fastify.prisma);
  const logos = new LogoLibrary(fastify.prisma);
  const { authenticate } = fastify;
  // Creating codes needs a verified email behind the request (lib/verified-actor.ts).
  const requireVerifiedEmail = verifiedEmailGuard(fastify.prisma);

  // -------------------------------------------------------------------------
  // POST / — Generate a signed QR code
  // -------------------------------------------------------------------------

  fastify.post('/', {
    config: { rateLimit: rateLimitGenerate },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER', 'MEMBER'), requireVerifiedEmail],
    preValidation: zodValidator({ body: extendedCreateSchema }),
  }, async (request, reply) => {
    const body = request.body as {
      destinationUrl: string;
      label?: string;
      location?: { lat: number; lng: number; radiusM: number; requireProximity?: boolean };
      expiresAt?: string;
      contentType?: string;
      content?: unknown;
      maxScans?: number;
      maxScansPerDevice?: number;
      scanMode?: ScanMode;
      qrStyle?: QrStyle;
    };

    // Check QR code quota
    const usageService = new UsageService(fastify.prisma, fastify.log);
    const org = await fastify.prisma.organization.findUnique({
      where: { id: request.user!.orgId },
      select: CUSTOMER_LOGO_ORG_SELECT,
    });
    // Plan gate on the style's shapes and customer logo, and the
    // verified-issuer gate on a customer logo (ADR-0005 D9), before any
    // quota is checked.
    const styleRefusal = body.qrStyle ? qrStyleGate(logoEligibility(org), body.qrStyle) : null;
    if (styleRefusal) return reply.status(403).send(gateRefusalBody(styleRefusal));
    // A customer logo must be one of the organization's own (another
    // organization's id answers like a missing one).
    let assetLogo: Uint8Array | null = null;
    if (body.qrStyle?.logo?.kind === 'asset') {
      assetLogo = await logos.bytes(request.user!.orgId, body.qrStyle.logo.assetId);
      if (!assetLogo) return sendStyleLogoRejected(reply, 'logo-not-found', LOGO_NOT_FOUND_MESSAGE);
    }
    const quotaError = await checkQrQuota(usageService, request.user!.orgId, org?.plan || 'FREE', reply);
    if (quotaError === QUOTA_REPLIED) return reply;
    if (quotaError) {
      return reply.status(429).send({ statusCode: 429, error: 'Quota Exceeded', message: quotaError });
    }
    const contentTypeError = contentTypeGateMessage(org?.plan || 'FREE', body.contentType);
    if (contentTypeError) {
      return reply.status(403).send({ statusCode: 403, error: 'Forbidden', message: contentTypeError });
    }

    // Destination screening (URL codes): a listed destination is refused;
    // if Web Risk cannot answer, issue the code and re-check it right away.
    const isUrlCode = (body.contentType ?? 'url') === 'url';
    const screening = isUrlCode ? await screenDestination(body.destinationUrl) : null;
    if (screening?.verdict === 'flagged') {
      return reply.status(422).send(destinationFlaggedBody(screening.threatTypes));
    }

    // Issuance awaits the merkle batch flush, so the response carries a
    // populated `transparency_log_index` and a final `alg_version`.
    let result: Awaited<ReturnType<typeof generateQRCode>>;
    try {
      result = await generateQRCode(
        fastify,
        signingService,
        hybridSigningService,
        macService,
        geoService,
        transparencyService,
        domainService,
        request.user!.orgId,
        { ...body, assetLogo, issuerVerified: isIssuerVerified(logoEligibility(org)) },
      );
    } catch (err) {
      if (err instanceof LogoNotFoundError) {
        request.log.info({ assetId: err.assetId }, 'QR create: the logo was deleted before the code was stored; nothing stored');
        return sendStyleLogoRejected(reply, 'logo-not-found', LOGO_NOT_FOUND_MESSAGE);
      }
      if (err instanceof LogoUnreadableError) {
        request.log.info({ raster: err.raster }, 'QR create: customer logo did not read back; nothing stored');
        return sendStyleLogoRejected(reply, 'logo-unreadable', logoUnreadableMessage(err.raster));
      }
      if (!(err instanceof RenderUnavailableError)) throw err;
      // Rendering runs before anything is stored, so nothing was created.
      request.log.error({ err: err.cause ?? err }, 'QR create: image rendering failed; nothing stored');
      return sendRenderUnavailable(reply);
    }
    if (screening?.verdict === 'unavailable') {
      await enqueueDestinationRecheck(result.token, request.log);
    }

    // Emit webhook (fire-and-forget). Includes the same securityContext
    // block that qr.scanned carries so consumers can correlate token
    // issuance with the signing algorithm from the moment the token
    // is minted. `merkleBatchId` may be null on async-pending rows
    // where the merkle leg is still flushing in the BatchSigner.
    const webhookService = new WebhookService(fastify.prisma);
    const createdAlgVersion = result.alg_version ?? ALG_VERSION_POLICY.hybrid;
    webhookService.emit(request.user!.orgId, {
      event: 'qr.created',
      data: {
        token: result.token,
        verification_url: result.verification_url,
        label: result.label,
        securityContext: {
          algVersion: createdAlgVersion,
          algVersionStatus: checkAlgVersion(createdAlgVersion),
          // Issuance always writes a hybrid row with complete Merkle data.
          pqcProtected: createdAlgVersion === ALG_VERSION_POLICY.hybrid,
          merkleBatchId: result.merkle_batch_id ?? null,
        },
        payloadVersion: 'v2',
      },
    }).catch(() => {});

    return reply.status(201).send(result);
  });

  // -------------------------------------------------------------------------
  // GET / — List QR codes for authenticated issuer
  // -------------------------------------------------------------------------

  fastify.get('/', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER', 'MEMBER', 'VIEWER')],
    preValidation: zodValidator({ querystring: listQRCodesQuerySchema }),
  }, async (request, reply) => {
    const query = request.query as {
      page: number;
      pageSize: number;
      status?: 'ACTIVE' | 'EXPIRED' | 'REVOKED';
    };

    const { page, pageSize, status } = query;
    const skip = paginationSkip(page, pageSize);

    const where = {
      organizationId: request.user!.orgId,
      ...(status ? { status } : {}),
    };

    const [data, total] = await Promise.all([
      fastify.prisma.qRCode.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip,
        take: pageSize,
        include: {
          _count: { select: { scans: true } },
        },
      }),
      fastify.prisma.qRCode.count({ where }),
    ]);

    return reply.send({
      data,
      total,
      page,
      pageSize,
      totalPages: Math.ceil(total / pageSize),
    });
  });

  // -------------------------------------------------------------------------
  // GET /:token — Get a single QR code
  // -------------------------------------------------------------------------

  fastify.get('/:token', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER', 'MEMBER', 'VIEWER')],
    preValidation: zodValidator({ params: tokenParamsSchema }),
  }, async (request, reply) => {
    const { token } = request.params as { token: string };

    const qrCode = await fastify.prisma.qRCode.findUnique({
      where: { token },
      include: {
        _count: { select: { scans: true } },
        scans: {
          orderBy: { createdAt: 'desc' },
          take: 5,
          select: {
            id: true,
            clientIpHash: true,
            clientLat: true,
            clientLng: true,
            trustScore: true,
            proxyDetected: true,
            createdAt: true,
          },
        },
      },
    });

    if (!qrCode) {
      return reply.status(404).send(notFoundError('QR code', token));
    }

    // Ownership check — the QR code must belong to the authenticated organization.
    if (!assertOwnership(qrCode, request, reply)) return;

    // The URL the code encodes, as in create responses; the dashboard
    // preview renders it so it matches the image endpoint byte for byte.
    return reply.send({ ...qrCode, verification_url: buildVerificationUrl(qrCode.token) });
  });

  // -------------------------------------------------------------------------
  // PATCH /:token — Update destination URL (re-signs the payload)
  // -------------------------------------------------------------------------

  fastify.patch('/:token', {
    config: { rateLimit: rateLimitGenerate },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER', 'MEMBER')],
    preValidation: zodValidator({
      params: tokenParamsSchema,
      body: extendedUpdateSchema,
    }),
  }, async (request, reply) => {
    const { token } = request.params as { token: string };
    const body = request.body as {
      destinationUrl?: string;
      label?: string;
      content?: unknown;
      expiresAt?: string;
      maxScans?: number;
      maxScansPerDevice?: number;
      requireProximity?: boolean;
      scanMode?: ScanMode;
      qrStyle?: QrStyle;
    };

    const existing = await fastify.prisma.qRCode.findUnique({ where: { token } });

    if (!existing) {
      return reply.status(404).send(notFoundError('QR code', token));
    }

    if (!assertOwnership(existing, request, reply)) return;

    // A style identical to the stored one changes nothing, so it is neither
    // gated, decode-checked nor written: an API client that resends the
    // unchanged style after a downgrade or a loss of verification succeeds
    // (ADR-0005 D9: only a changed style must comply).
    const newStyle = body.qrStyle && !isSameAsStoredStyle(existing.style, body.qrStyle) ? body.qrStyle : undefined;

    // A saved style must use only the shapes and frames the plan includes,
    // and a customer logo needs a paid plan and a verified issuer (ADR-0005
    // D9). A stored style keeps rendering after a downgrade or a loss of
    // verification; only a request that sends a changed style is checked,
    // and the dashboard sends one only when it changed. A stored caption is
    // grandfathered on FREE: its text may change, or the frame be removed,
    // but not its template or colours (D9 amendment of 2026-10-30).
    if (newStyle) {
      const org = await fastify.prisma.organization.findUnique({
        where: { id: existing.organizationId },
        select: CUSTOMER_LOGO_ORG_SELECT,
      });
      const styleRefusal = qrStyleGate(logoEligibility(org), newStyle, storedFrameOf(existing.style));
      if (styleRefusal) return reply.status(403).send(gateRefusalBody(styleRefusal));
      // A new style with a customer logo: the logo is the organization's
      // own, and the code reads back with it at the checked export sizes.
      if (newStyle.logo?.kind === 'asset') {
        const assetLogo = await logos.bytes(existing.organizationId, newStyle.logo.assetId);
        if (!assetLogo) return sendStyleLogoRejected(reply, 'logo-not-found', LOGO_NOT_FOUND_MESSAGE);
        try {
          await checkLogoScans(token, newStyle, assetLogo);
        } catch (err) {
          if (err instanceof LogoUnreadableError) {
            request.log.info({ token, raster: err.raster }, 'QR update: customer logo did not read back; style not saved');
            return sendStyleLogoRejected(reply, 'logo-unreadable', logoUnreadableMessage(err.raster));
          }
          if (err instanceof RenderUnavailableError) {
            request.log.error({ err: err.cause ?? err }, 'QR update: logo check could not render');
            return reply
              .status(503)
              .header('Retry-After', String(RENDER_RETRY_AFTER_SECONDS))
              .send({ statusCode: 503, error: 'Service Unavailable', message: 'QR image rendering is unavailable; retry shortly. Nothing was changed.' });
          }
          throw err;
        }
      }
    }

    // Changing where the code points (the URL, or the hosted content of
    // other types) needs a verified email, as creating does. Label, style,
    // expiry and limits stay editable.
    const changesDestination = body.destinationUrl !== undefined || body.content !== undefined;
    if (changesDestination && !(await isActorEmailVerified(fastify.prisma, request.user!))) {
      return sendEmailNotVerified(reply, request.user!);
    }

    // Reject requireProximity toggles on QRs that are not geo-bound — the flag
    // is meaningless without coordinates and accepting it would mislead the
    // caller into thinking enforcement is active.
    if (
      body.requireProximity !== undefined &&
      (existing.latitude === null || existing.longitude === null)
    ) {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: 'requireProximity can only be toggled on QR codes with a registered location.',
      });
    }

    // Validate content against content type schema if provided.
    const contentType = existing.contentType || 'url';
    let newContent = existing.content;
    if (body.content !== undefined && contentType !== 'url') {
      const typeRegistry = getContentType(contentType);
      if (typeRegistry) {
        const parseResult = typeRegistry.schema.safeParse(body.content);
        if (!parseResult.success) {
          return reply.status(400).send({
            statusCode: 400,
            error: 'Bad Request',
            message: `Invalid content for type ${contentType}: ${parseResult.error.message}`,
          });
        }
      }
      newContent = body.content as object;
    }

    const newDestinationUrl = body.destinationUrl ?? existing.destinationUrl;
    const newExpiresAt = body.expiresAt !== undefined ? new Date(body.expiresAt) : existing.expiresAt;

    // Compute content hash for signing (non-URL types include content in the
    // destHash via computeDestHash).
    let newContentHashHex = '';
    if (newContent && contentType !== 'url') {
      newContentHashHex = createHash('sha256').update(stableStringify(newContent)).digest('hex');
    }

    // Re-sign when the URL, content, or expiresAt changes (all are part of the signature).
    let signature = existing.signature;
    let signingKeyId = existing.signingKeyId;
    let updatedKeyId = existing.keyId;
    let updatedAlgVersion = existing.algVersion;
    let updatedMerkleBatchId = existing.merkleBatchId;
    let updatedMerkleLeafIndex = existing.merkleLeafIndex;
    let updatedMerkleLeafHash = existing.merkleLeafHash;
    let updatedMerkleLeafNonce = existing.merkleLeafNonce;
    let updatedMerklePath: object | null = existing.merklePath as object | null;
    let updatedMacTokenMac = existing.macTokenMac;
    let updatedMacKeyVersion = existing.macKeyVersion;

    const urlChanged = body.destinationUrl && body.destinationUrl !== existing.destinationUrl;
    const contentChanged = body.content !== undefined;
    const expiresAtChanged = body.expiresAt !== undefined;

    // Destination screening for a new URL. A flagged code is cleared only by
    // repointing it to a URL Web Risk reports clean (or by a superadmin).
    let clearDestinationFlag = false;
    let recheckAfterUpdate = false;
    if (urlChanged && contentType === 'url') {
      const screening = await screenDestination(newDestinationUrl);
      if (screening.verdict === 'flagged') {
        return reply.status(422).send(destinationFlaggedBody(screening.threatTypes));
      }
      if (existing.destinationFlaggedAt) {
        if (screening.verdict !== 'clean') {
          const unavailable = screening.verdict === 'unavailable';
          return reply.status(unavailable ? 503 : 409).send({
            statusCode: unavailable ? 503 : 409,
            error: unavailable ? 'Service Unavailable' : DESTINATION_FLAGGED_ERROR,
            message: unavailable
              ? 'This code is flagged and the new destination cannot be screened right now. Try again shortly.'
              : 'This code is flagged; its destination can only be changed to a URL that passes screening. Contact QRAuth support.',
          });
        }
        clearDestinationFlag = true;
      }
      recheckAfterUpdate = screening.verdict === 'unavailable';
    }

    if (urlChanged || contentChanged || expiresAtChanged) {
      const activeKey = await signingService.getActiveKey(existing.organizationId);
      const newExpiresAtStr = newExpiresAt?.toISOString() ?? '';

      const hybrid = await hybridSigningService.signSingleQR({
        organizationId: existing.organizationId,
        signingKeyDbId: activeKey.id,
        signingKeyId: activeKey.keyId,
        token: existing.token,
        contentType,
        destinationUrl: newDestinationUrl,
        contentHashHex: newContentHashHex,
        expiresAt: newExpiresAtStr,
        lat: existing.latitude,
        lng: existing.longitude,
        radiusM: existing.radiusM,
      });
      signature = hybrid.ecdsaSignature;
      signingKeyId = activeKey.id;
      updatedKeyId = activeKey.keyId;
      updatedAlgVersion = hybrid.algVersion;
      updatedMerkleBatchId = hybrid.batchId;
      updatedMerkleLeafIndex = hybrid.leafIndex;
      updatedMerkleLeafHash = hybrid.leafHash;
      updatedMerkleLeafNonce = hybrid.leafNonce;
      updatedMerklePath = hybrid.merklePath as unknown as object;

      // Recompute the MAC over the same canonical core the hybrid leg
      // signed. Unified form — MAC, ECDSA, Merkle all agree byte-for-byte.
      const macResult = await recomputeAndSignMac(macService, fastify.log, {
        algVersion: updatedAlgVersion,
        token: existing.token,
        organizationId: existing.organizationId,
        contentType,
        destinationUrl: newDestinationUrl,
        contentHashHex: newContentHashHex,
        lat: existing.latitude,
        lng: existing.longitude,
        radiusM: existing.radiusM,
        expiresAt: newExpiresAtStr,
      });
      updatedMacTokenMac = macResult.mac;
      updatedMacKeyVersion = macResult.keyVersion;
    }

    const persistUpdate = (db: Pick<LogoTx, 'qRCode'>) => db.qRCode.update({
      where: { token },
      data: {
        destinationUrl: newDestinationUrl,
        label: body.label !== undefined ? body.label : existing.label,
        content: newContent as object | undefined,
        expiresAt: newExpiresAt,
        signature,
        signingKeyId,
        keyId: updatedKeyId,
        algVersion: updatedAlgVersion,
        merkleBatchId: updatedMerkleBatchId,
        merkleLeafIndex: updatedMerkleLeafIndex,
        merkleLeafHash: updatedMerkleLeafHash,
        merkleLeafNonce: updatedMerkleLeafNonce,
        merklePath: updatedMerklePath as never,
        macTokenMac: updatedMacTokenMac,
        macKeyVersion: updatedMacKeyVersion,
        ...(body.maxScans !== undefined ? { maxScans: body.maxScans } : {}),
        ...(body.maxScansPerDevice !== undefined ? { maxScansPerDevice: body.maxScansPerDevice } : {}),
        ...(body.requireProximity !== undefined ? { requireProximity: body.requireProximity } : {}),
        ...(body.scanMode !== undefined ? { scanMode: body.scanMode } : {}),
        // Style is presentational (not signed). Only write when provided, so an
        // unrelated save never clobbers a stored style with null.
        ...(newStyle !== undefined ? { style: newStyle } : {}),
        ...(clearDestinationFlag ? { destinationFlaggedAt: null, destinationFlagReason: null } : {}),
      },
    });
    // A new style with a customer logo is written under the logo row's lock,
    // after re-checking that the logo still exists (as on create).
    const logoAssetId = newStyle?.logo?.kind === 'asset' ? newStyle.logo.assetId : null;
    let updated: Awaited<ReturnType<typeof persistUpdate>>;
    try {
      updated = logoAssetId
        ? await logos.writeWithLogo(existing.organizationId, logoAssetId, persistUpdate)
        : await persistUpdate(fastify.prisma);
    } catch (err) {
      if (!(err instanceof LogoNotFoundError)) throw err;
      request.log.info({ token, assetId: err.assetId }, 'QR update: the logo was deleted before the style was saved; nothing changed');
      return sendStyleLogoRejected(reply, 'logo-not-found', LOGO_NOT_FOUND_MESSAGE);
    }
    if (recheckAfterUpdate) {
      await enqueueDestinationRecheck(token, request.log);
    }

    // Bust the verify cache for this token so the updated URL is reflected
    // immediately on the next verification request.
    await cacheDel(`verify:${token}`);

    // Same destination-similarity check as create (non-blocking). The verify
    // page runs the check again on every scan against the current destination.
    if (urlChanged) {
      const domainCheck = await checkDestinationSimilarity(
        fastify,
        domainService,
        existing.id,
        newDestinationUrl,
        existing.organizationId,
      );
      if (domainCheck.warnings.length > 0) {
        return reply.send({
          ...updated,
          domain_warnings: domainCheck.warnings.map((w) => ({
            similar_to: w.domain,
            verified_org: w.verifiedOrgName,
            similarity: w.similarity,
            reason: w.reason,
          })),
        });
      }
    }

    return reply.send(updated);
  });

  // -------------------------------------------------------------------------
  // DELETE /:token — Revoke a QR code
  // -------------------------------------------------------------------------

  fastify.delete('/:token', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER', 'MEMBER')],
    preValidation: zodValidator({ params: tokenParamsSchema }),
  }, async (request, reply) => {
    const { token } = request.params as { token: string };

    const existing = await fastify.prisma.qRCode.findUnique({ where: { token } });

    if (!existing) {
      return reply.status(404).send(notFoundError('QR code', token));
    }

    if (!assertOwnership(existing, request, reply)) return;

    if (existing.status === 'REVOKED') {
      return reply.status(409).send({
        statusCode: 409,
        error: 'Conflict',
        message: 'QR code is already revoked.',
      });
    }

    await fastify.prisma.qRCode.update({
      where: { token },
      data: { status: 'REVOKED', revokedAt: new Date() },
    });

    // Invalidate cache so revocation is visible immediately.
    await cacheDel(`verify:${token}`);

    return reply.status(204).send();
  });

  // -------------------------------------------------------------------------
  // POST /bulk-revoke — Revoke up to 100 codes of the caller's organization.
  //
  // 207 with one result per token (revoked | already_revoked | not_found).
  // Tokens of other organizations are reported as not_found. On the `auth`
  // rate-limit tier (fails open), so revoking still works during a Redis
  // outage.
  // -------------------------------------------------------------------------

  fastify.post('/bulk-revoke', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
    preValidation: zodValidator({ body: bulkRevokeSchema }),
  }, async (request, reply) => {
    const { tokens } = request.body as z.infer<typeof bulkRevokeSchema>;

    const results = await revokeTokensForOrg(fastify.prisma, request.log, request.user!.orgId, tokens);

    return reply.status(207).send({
      results,
      summary: {
        revoked: results.filter((r) => r.status === 'revoked').length,
        already_revoked: results.filter((r) => r.status === 'already_revoked').length,
        not_found: results.filter((r) => r.status === 'not_found').length,
      },
    });
  });

  // -------------------------------------------------------------------------
  // POST /bulk — Bulk generate QR codes
  // -------------------------------------------------------------------------

  fastify.post('/bulk', {
    config: { rateLimit: rateLimitBulk },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER'), requireVerifiedEmail],
    preValidation: zodValidator({ body: bulkCreateQRCodeSchema }),
  }, async (request, reply) => {
    const { items } = request.body as {
      items: Array<{
        destinationUrl: string;
        label?: string;
        location?: { lat: number; lng: number; radiusM: number; requireProximity?: boolean };
        expiresAt?: string;
        scanMode?: ScanMode;
      }>;
    };

    const organizationId = request.user!.orgId;

    // Check QR code quota before processing bulk items
    const usageService = new UsageService(fastify.prisma, fastify.log);
    const org = await fastify.prisma.organization.findUnique({
      where: { id: organizationId },
      select: CUSTOMER_LOGO_ORG_SELECT,
    });
    const plan = org?.plan || 'FREE';
    const issuerVerified = isIssuerVerified(logoEligibility(org));

    // For plans with limits, check if we have enough remaining quota
    const quotaError = await checkQrQuota(usageService, organizationId, plan, reply);
    if (quotaError === QUOTA_REPLIED) return reply;
    if (quotaError) {
      return reply.status(429).send({ statusCode: 429, error: 'Quota Exceeded', message: quotaError });
    }

    // Also check if the batch would exceed the remaining quota
    const currentQrcodes = await usageService.current(organizationId, 'qrcodes');
    const limits = usageService.getLimits(plan);
    if (limits.qrcodes !== 'unlimited' && currentQrcodes + items.length > limits.qrcodes) {
      return reply.status(429).send({
        statusCode: 429,
        error: 'Quota Exceeded',
        message: `Bulk request would exceed QR code limit. Current: ${currentQrcodes}, requested: ${items.length}, limit: ${limits.qrcodes}. Upgrade your plan at https://qrauth.io/dashboard/settings.`,
      });
    }

    // Process sequentially to keep signing key lookups consistent and avoid
    // hammering the database with concurrent inserts under the bulk limit.
    const results: Array<
      | { index: number; success: true; data: object; label?: string }
      | { index: number; success: false; error: string; errorCode: string; threatTypes?: string[]; label?: string }
    > = [];

    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      const screening = await screenDestination(item.destinationUrl);
      if (screening.verdict === 'flagged') {
        results.push({
          index: i,
          success: false,
          error: destinationFlaggedBody(screening.threatTypes).message,
          errorCode: 'DESTINATION_FLAGGED',
          threatTypes: screening.threatTypes,
          label: item.label,
        });
        continue;
      }
      try {
        const data = await generateQRCode(
          fastify,
          signingService,
          hybridSigningService,
          macService,
          geoService,
          transparencyService,
          domainService,
          organizationId,
          { ...item, issuerVerified },
        );
        if (screening.verdict === 'unavailable') {
          await enqueueDestinationRecheck(data.token, request.log);
        }
        results.push({ index: i, success: true, data, label: item.label });
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Unknown error';
        fastify.log.warn({ err, item }, 'Bulk QR code generation failed for item');

        // Derive a machine-readable error code from the error message so
        // integrators (e.g. comtel-sirens) can handle failures programmatically.
        let errorCode = 'INTERNAL_ERROR';
        if (err instanceof RenderUnavailableError) {
          // Rendering runs before anything is stored: this item was not created.
          errorCode = 'RENDER_UNAVAILABLE';
          fastify.log.error({ err: err.cause ?? err }, 'Bulk QR create: image rendering failed; item not stored');
        } else if (message.toLowerCase().includes('quota') || message.toLowerCase().includes('limit')) {
          errorCode = 'QUOTA_EXCEEDED';
        } else if (message.toLowerCase().includes('rate')) {
          errorCode = 'RATE_LIMIT';
        } else if (message.toLowerCase().includes('valid') || message.toLowerCase().includes('schema')) {
          errorCode = 'VALIDATION_ERROR';
        }

        results.push({ index: i, success: false, error: message, errorCode, label: item.label });
      }
    }

    const successCount = results.filter((r) => r.success).length;
    const failureCount = results.length - successCount;

    return reply.status(207).send({
      results,
      summary: {
        total: results.length,
        succeeded: successCount,
        failed: failureCount,
      },
    });
  });
}
