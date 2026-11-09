import type { QRCode } from '@prisma/client';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import {
  createQRCodeSchema,
  updateQRCodeSchema,
  bulkCreateQRCodeSchema,
  paginationSchema,
  getContentType,
  destinationHttpUrl,
  destinationHostRefusal,
  normalizeUrl,
  isIssuerVerified,
  contentLinkUrls,
  isLinkedContentType,
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
  computeDestHash,
  checkAlgVersion,
  ALG_VERSION_POLICY,
} from '@qrauth/shared';
import { GeoService } from '../services/geo.js';
import { TransparencyLogService } from '../services/transparency.js';
import { DomainService } from '../services/domain.js';
import { checkContent, pruneLinkFlags, SCREENING_RETRY_AFTER_SECONDS, type ContentCheck, type LinkScreening } from '../services/link-screening.js';
import { cacheDel } from '../lib/cache.js';
import { config } from '../lib/config.js';
import { assertOwnership, buildVerificationUrl } from '../lib/qrcode-access.js';
import { RENDER_RETRY_AFTER_SECONDS, RenderUnavailableError } from '../services/qr-render.js';
import { LogoUnreadableError } from '../services/logo-decode.js';
import { LogoLibrary, LogoNotFoundError, type LogoTx } from '../services/logo-library.js';
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
import {
  bulkMoveSchema,
  bulkTagSchema,
  qrListFilterSchema,
  type BulkMoveInput,
  type BulkTagInput,
} from '@qrauth/shared';
import { bulkMove, bulkTag, organizeAudit } from '../services/qr-organize.js';
import { auditContext, recordAudit, type AuditContext, type AuditDb } from '../services/audit.js';
import { listQRCodes, type QrListQuery } from '../services/qr-search.js';
import {
  allowlistRefusal,
  destinationRoleRefusal,
  enforcePolicyInTransaction,
  isOutsidePolicy,
  PolicyRefusalError,
  readPolicy,
  type PolicyRefusal,
} from '../services/org-policy.js';
import { policyDestinations } from '../lib/allowlist-domains.js';
import {
  checkCodeSimilarity,
  checkLogoScans,
  domainWarningsBody,
  generateQRCode,
  recomputeAndSignMac,
} from '../services/qr-create.js';
import { sendOrganizeError } from '../lib/organize-errors.js';
import {
  listRevisions,
  revisionContext,
  RestoreConflictError,
  RevisionNotFoundError,
  RevisionValueUnavailableError,
  snapshot,
  updateWithRevision,
  valueAtRevision,
} from '../services/qr-revisions.js';

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

type UpdateBody = {
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

/** An organization policy refused the write (ADR-0008 D8): 422 allowlist, 403 role. */
function sendPolicyRefusal(reply: FastifyReply, refusal: PolicyRefusal): FastifyReply {
  return reply.status(refusal.status).send(refusal.body);
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


const listQRCodesQuerySchema = paginationSchema
  .extend({ status: z.enum(['ACTIVE', 'EXPIRED', 'REVOKED']).optional() })
  .extend(qrListFilterSchema.shape);

// Extends the shared createQRCodeSchema with optional content-type fields.
// `destinationUrl` is made optional so non-URL content types (vCard, event,
// …) can omit it — their destination is the verify page. The superRefine
// then re-requires it for URL-type QRs; without that guard an empty URL
// reaches prisma.qRCode.create() as undefined and 500s on the required column.
export const extendedCreateSchema = createQRCodeSchema
  .extend({
    destinationUrl: destinationHttpUrl().optional(), // Override: optional for content types; http(s) with a public host
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

/** Code settings a PATCH can change that the QR edit history does not track. */
const UNTRACKED_SETTINGS = ['label', 'maxScans', 'maxScansPerDevice', 'requireProximity'] as const;
type UntrackedSettings = Record<(typeof UNTRACKED_SETTINGS)[number], string | number | boolean | null>;

/**
 * qr.organize when a PATCH changed a setting outside the QR edit history
 * (services/qr-revisions.ts records the tracked fields): label and scan
 * limits, as { field: { from, to } }. Run in the update's transaction.
 */
export async function auditSettingsChange(
  tx: AuditDb,
  ctx: AuditContext,
  code: { id: string; organizationId: string; token: string } & UntrackedSettings,
  after: UntrackedSettings,
): Promise<void> {
  const changed = UNTRACKED_SETTINGS.filter((f) => code[f] !== after[f]);
  if (changed.length === 0) return;
  const changes = Object.fromEntries(changed.map((f) => [f, { from: code[f], to: after[f] }]));
  await recordAudit(tx, ctx, {
    organizationId: code.organizationId,
    action: 'qr.organize',
    resource: 'QRCode',
    resourceId: code.id,
    metadata: { token: code.token, ...changes },
  });
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


/** Refusal from checkContent: 400 schema, 422 listed link, 503 links not screenable (Retry-After when temporary). */
function sendContentRefusal(reply: FastifyReply, check: Extract<ContentCheck, { ok: false }>) {
  if (check.retryable) reply.header('Retry-After', String(SCREENING_RETRY_AFTER_SECONDS));
  return reply.status(check.status).send(check.body);
}

/** normalizeUrl, or the value itself when a stored legacy value does not parse. */
function normalizedOrSelf(url: string): string {
  try {
    return normalizeUrl(url);
  } catch {
    return url;
  }
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
  const domainService = new DomainService(fastify.prisma, fastify.log);
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

    // The organization's destination allowlist (ADR-0008 D8), before Web
    // Risk: an allowed host is still screened and checked for lookalikes.
    const policyRefused = allowlistRefusal(
      await readPolicy(fastify.prisma, request.user!.orgId),
      policyDestinations({ contentType: body.contentType ?? 'url', destinationUrl: body.destinationUrl, content: body.content }),
    );
    if (policyRefused) return sendPolicyRefusal(reply, policyRefused);

    // Content of other types must match its schema (400), and the links of
    // smart link and link list codes are screened like a destination.
    const contentCheck = await checkContent(body.contentType ?? 'url', body.content);
    if (!contentCheck.ok) return sendContentRefusal(reply, contentCheck);

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
        { ...body, content: contentCheck.content, assetLogo, issuerVerified: isIssuerVerified(logoEligibility(org)), revision: revisionContext(request) },
      );
    } catch (err) {
      if (err instanceof PolicyRefusalError) return sendPolicyRefusal(reply, err.refusal);
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
    const query = request.query as QrListQuery;
    try {
      return reply.send(await listQRCodes(fastify.prisma, request.user!.orgId, query));
    } catch (err) {
      if (sendOrganizeError(err, reply)) return;
      throw err;
    }
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
        folder: { select: { id: true, name: true } },
        tags: {
          select: { tag: { select: { id: true, name: true, color: true } } },
          orderBy: { tag: { name: 'asc' } },
        },
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
    // Tags flattened to {id, name, color}, the same shape as list items.
    const { tags, ...rest } = qrCode;
    return reply.send({
      ...rest,
      tags: tags.map((t) => t.tag),
      verification_url: buildVerificationUrl(qrCode.token),
    });
  });

  // -------------------------------------------------------------------------
  // GET /:token/history — Edit history, newest first (every role).
  // POST /:token/history/:revision/restore — "Restore this destination"
  //   (MANAGER+): the destination (URL codes) or content (other types) as
  //   it was right after that revision, applied through the PATCH logic, so
  //   it meets today's rules and is re-signed. Records a RESTORED revision.
  // Another organization's code is 404 on both, not 403.
  // -------------------------------------------------------------------------

  const historyQuerySchema = paginationSchema;
  const revisionParamsSchema = tokenParamsSchema.extend({ revision: z.coerce.number().int().min(1) });

  const ownCode = async (request: FastifyRequest, token: string) => {
    const code = await fastify.prisma.qRCode.findUnique({ where: { token } });
    return code && code.organizationId === request.user!.orgId ? code : null;
  };

  fastify.get('/:token/history', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER', 'MEMBER', 'VIEWER')],
    preValidation: zodValidator({ params: tokenParamsSchema, querystring: historyQuerySchema }),
  }, async (request, reply) => {
    const { token } = request.params as { token: string };
    const { page, pageSize } = request.query as { page: number; pageSize: number };
    const code = await ownCode(request, token);
    if (!code) return reply.status(404).send(notFoundError('QR code', token));
    const { data, total } = await listRevisions(fastify.prisma, code, page, pageSize);
    return reply.send({ data, total, page, pageSize, totalPages: Math.ceil(total / pageSize) });
  });

  fastify.post('/:token/history/:revision/restore', {
    config: { rateLimit: rateLimitGenerate },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER')],
    preValidation: zodValidator({ params: revisionParamsSchema }),
  }, async (request, reply) => {
    const { token, revision } = request.params as { token: string; revision: number };
    const code = await ownCode(request, token);
    if (!code) return reply.status(404).send(notFoundError('QR code', token));
    if (code.status === 'REVOKED') {
      return reply.status(409).send({ statusCode: 409, error: 'Conflict', code: 'revoked', message: 'A revoked QR code cannot be changed.' });
    }

    const field = (code.contentType || 'url') === 'url' ? 'destinationUrl' : 'content';
    let value: unknown;
    try {
      value = await valueAtRevision(fastify.prisma, code.id, revision, field);
    } catch (err) {
      if (err instanceof RevisionNotFoundError) return reply.status(404).send(notFoundError('Revision', revision));
      if (err instanceof RevisionValueUnavailableError) {
        return reply.status(409).send({ statusCode: 409, error: 'Conflict', code: 'history-incomplete', message: err.message });
      }
      throw err;
    }
    const current = snapshot(code)[field];
    if (stableStringify(value) === stableStringify(current)) {
      return reply.status(409).send({ statusCode: 409, error: 'Conflict', code: 'already-current', message: 'That is already the current destination.' });
    }

    // The same validation as a new destination (http(s), a public host, no
    // spaces) or, for other types, today's content schema: refused as 422.
    const destinationCheck = field === 'destinationUrl' ? destinationHttpUrl().safeParse(value) : undefined;
    if (destinationCheck && !destinationCheck.success) {
      return reply.status(422).send({
        statusCode: 422,
        error: 'Unprocessable Entity',
        code: 'restore-not-allowed',
        message: `That destination does not meet the current rules: ${destinationCheck.error.issues.map((i) => i.message).join('; ')}`,
      });
    }
    const parsed = extendedUpdateSchema.safeParse(field === 'destinationUrl' ? { destinationUrl: value } : { content: value });
    const contentCheck = field === 'content' ? getContentType(code.contentType)?.schema.safeParse(value) : undefined;
    if (contentCheck && !contentCheck.success) {
      return reply.status(422).send({
        statusCode: 422,
        error: 'Unprocessable Entity',
        code: 'restore-not-allowed',
        message: `That content does not meet the current rules for ${code.contentType}: ${contentCheck.error.issues.map((i) => i.message).join('; ')}`,
      });
    }
    if (!parsed.success) {
      return reply.status(422).send({
        statusCode: 422,
        error: 'Unprocessable Entity',
        code: 'restore-not-allowed',
        message: `That destination does not meet the current rules: ${parsed.error.issues.map((i) => i.message).join('; ')}`,
      });
    }
    return applyUpdate(request, reply, token, parsed.data as UpdateBody, { kind: 'RESTORED', restoredFrom: revision });
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
    return applyUpdate(request, reply, token, request.body as UpdateBody, { kind: 'UPDATED' });
  });

  /**
   * The PATCH logic: every rule a change must pass (ownership, style gates
   * and logo checks, verified email for a new destination, content schema,
   * Web Risk screening, re-signing) and the write with its edit-history
   * revision. "Restore this destination" runs through here too, so a
   * restored destination meets the rules in force today.
   */
  async function applyUpdate(
    request: FastifyRequest,
    reply: FastifyReply,
    token: string,
    body: UpdateBody,
    revision: { kind: 'UPDATED' | 'RESTORED'; restoredFrom?: number },
  ) {

    const existing = await fastify.prisma.qRCode.findUnique({ where: { token } });

    if (!existing) {
      return reply.status(404).send(notFoundError('QR code', token));
    }

    if (!assertOwnership(existing, request, reply)) return;

    const contentType = existing.contentType || 'url';
    // Smart link and link list codes point to their verify page; their
    // links live in the content.
    if (body.destinationUrl !== undefined && isLinkedContentType(contentType)) {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: `destinationUrl cannot be set on ${contentType} codes; change the links in content.`,
      });
    }
    // A destination is compared and stored in its normalized form; resending
    // the current one (in any spelling) is not a change. The dashboard
    // resends the stored content with every save; only a different content
    // (compared canonically) is a change.
    const requestedUrl = body.destinationUrl !== undefined ? normalizeUrl(body.destinationUrl) : undefined;
    const urlChanged = requestedUrl !== undefined && requestedUrl !== normalizedOrSelf(existing.destinationUrl);
    // URL codes keep their destination in destinationUrl: content sent with
    // one (the dashboard may send {}) is not a change of where it points.
    const contentEdited =
      contentType !== 'url' &&
      body.content !== undefined &&
      stableStringify(body.content) !== stableStringify(existing.content);
    // Organization policies (ADR-0008 D8) apply to a change of where the code
    // points: the minimum role (restore keeps its own MANAGER floor) and the
    // allowlist. Label, tags, style, expiry and limits are never blocked.
    const changesWhereItPoints = urlChanged || contentEdited;
    const destinationFloor = revision.kind === 'RESTORED' ? ('MANAGER' as const) : ('MEMBER' as const);
    const policyUrls = (content: unknown): string[] =>
      urlChanged ? [requestedUrl] : isLinkedContentType(contentType) ? contentLinkUrls(contentType, content) : [];
    if (changesWhereItPoints) {
      const policy = await readPolicy(fastify.prisma, existing.organizationId);
      const refused =
        (await destinationRoleRefusal(fastify.prisma, request.user!, policy, destinationFloor)) ??
        allowlistRefusal(policy, policyUrls(body.content));
      if (refused) return sendPolicyRefusal(reply, refused);
    }

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

    // Validate content against content type schema if provided. Only a
    // different content is gated, screened and re-checked for lookalikes.
    let newContent = existing.content;
    let contentLinks: string[] = [];
    let contentScreening: LinkScreening | null = null;
    if (contentEdited && contentType !== 'url') {
      // Changing the content of a type the plan does not include is refused,
      // as creating one is.
      const org = await fastify.prisma.organization.findUnique({
        where: { id: existing.organizationId },
        select: { plan: true },
      });
      const gateMessage = contentTypeGateMessage(org?.plan || 'FREE', contentType);
      if (gateMessage) {
        return reply.status(403).send({ statusCode: 403, error: 'Forbidden', message: gateMessage });
      }
      // Schema (400) and, for smart link and link list, Web Risk on every link (422, or 503).
      const contentCheck = await checkContent(contentType, body.content);
      if (!contentCheck.ok) return sendContentRefusal(reply, contentCheck);
      contentLinks = contentCheck.urls;
      contentScreening = contentCheck.screening;
      newContent = contentCheck.content as object;
    }

    const newDestinationUrl = urlChanged ? requestedUrl : existing.destinationUrl;
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

    const contentChanged = body.content !== undefined;
    const expiresAtChanged = body.expiresAt !== undefined;

    // A new destination needs a public host (no IP address, localhost or
    // private network name). An unchanged destination is not re-checked, so
    // an existing code can still be edited.
    if (urlChanged) {
      const hostRefusal = destinationHostRefusal(new URL(newDestinationUrl).hostname);
      if (hostRefusal) {
        return reply.status(400).send({
          statusCode: 400,
          error: 'Bad Request',
          message: `destinationUrl: ${hostRefusal}`,
        });
      }
    }

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

    // A restore was decided on `existing`: under the row lock, refuse if the
    // code was revoked or changed in the meantime.
    const assertRestorable = revision.kind === 'RESTORED'
      ? (locked: { status: string; updatedAt: Date }) => {
          if (locked.status === 'REVOKED') throw new RestoreConflictError('revoked', 'A revoked QR code cannot be changed.');
          if (locked.updatedAt.getTime() !== existing.updatedAt.getTime()) {
            throw new RestoreConflictError('concurrent-change', 'The code changed while restoring. Reload its history and try again.');
          }
        }
      : undefined;
    const auditCtx = auditContext(request);
    // The row as read under updateWithRevision's lock: the audit entry's
    // "before", so a concurrent change is never reported as ours.
    let lockedBefore: QRCode | null = null;
    const onLocked = (locked: QRCode) => {
      lockedBefore = locked;
      assertRestorable?.(locked);
    };
    let outsidePolicyAfter: boolean | undefined;
    const writeUpdate = (db: LogoTx) => updateWithRevision(db, existing.id, revisionContext(request), revision.kind, (tx) => tx.qRCode.update({
      where: { token },
      data: {
        destinationUrl: newDestinationUrl,
        ...(body.label !== undefined ? { label: body.label } : {}),
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
        // The mark for the code's destinations after this write, against the
        // policy locked in persistUpdate (set only when that policy was read).
        ...(outsidePolicyAfter !== undefined ? { outsidePolicy: outsidePolicyAfter } : {}),
      },
    }), revision.restoredFrom, onLocked);
    // Label and scan limits are not in the edit history: an audit entry, same transaction.
    const persistUpdate = async (db: LogoTx) => {
      // The policy checks again under the organization lock, before the
      // code's row lock (services/org-policy.ts explains the order).
      if (changesWhereItPoints) {
        const lockedPolicy = await enforcePolicyInTransaction(db, existing.organizationId, {
          urls: policyUrls(newContent),
          change: { user: request.user!, floor: destinationFloor },
        });
        outsidePolicyAfter = isOutsidePolicy(
          lockedPolicy,
          policyDestinations({ contentType, destinationUrl: newDestinationUrl, content: newContent }),
        );
      }
      const after = await writeUpdate(db);
      await auditSettingsChange(db, auditCtx, lockedBefore ?? existing, after);
      return after;
    };
    // A new style with a customer logo is written under the logo row's lock,
    // after re-checking that the logo still exists (as on create).
    const logoAssetId = newStyle?.logo?.kind === 'asset' ? newStyle.logo.assetId : null;
    let updated: Awaited<ReturnType<typeof persistUpdate>>;
    try {
      updated = logoAssetId
        ? await logos.writeWithLogo(existing.organizationId, logoAssetId, persistUpdate)
        : await fastify.prisma.$transaction((tx) => persistUpdate(tx));
    } catch (err) {
      if (err instanceof PolicyRefusalError) return sendPolicyRefusal(reply, err.refusal);
      if (err instanceof RestoreConflictError) {
        return reply.status(409).send({ statusCode: 409, error: 'Conflict', code: err.code, message: err.message });
      }
      if (!(err instanceof LogoNotFoundError)) throw err;
      request.log.info({ token, assetId: err.assetId }, 'QR update: the logo was deleted before the style was saved; nothing changed');
      return sendStyleLogoRejected(reply, 'logo-not-found', LOGO_NOT_FOUND_MESSAGE);
    }
    if (contentEdited && isLinkedContentType(contentType)) {
      await pruneLinkFlags(fastify.prisma, existing.id, contentLinks, contentScreening);
    }
    if (recheckAfterUpdate) {
      await enqueueDestinationRecheck(token, request.log);
    }

    // Bust the verify cache for this token so the updated URL is reflected
    // immediately on the next verification request.
    await cacheDel(`verify:${token}`);

    // Same destination-similarity check as create (non-blocking). The verify
    // page runs the check again on every scan against the current destination.
    if (urlChanged || (contentEdited && isLinkedContentType(contentType))) {
      const domainCheck = await checkCodeSimilarity(fastify, domainService, {
        id: existing.id,
        organizationId: existing.organizationId,
        contentType,
        destinationUrl: newDestinationUrl,
        content: newContent,
      }, 'update');
      if (domainCheck.warnings.length > 0) {
        return reply.send({ ...updated, domain_warnings: domainWarningsBody(domainCheck.warnings) });
      }
    }

    return reply.send(updated);
  }

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

    await fastify.prisma.$transaction((tx) =>
      updateWithRevision(tx, existing.id, revisionContext(request), 'REVOKED', (t) =>
        t.qRCode.update({ where: { token }, data: { status: 'REVOKED', revokedAt: new Date() } })));

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

    const results = await revokeTokensForOrg(fastify.prisma, request.log, request.user!.orgId, tokens, revisionContext(request));

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
  // POST /bulk-tag, /bulk-move — Organise up to 100 codes (Milestone 1).
  //
  // MEMBER+ (VIEWER is read-only). Tag and folder ids must belong to the
  // caller's organization (404 otherwise, before anything changes); tokens of
  // other organizations are reported in `notFound`, as in bulk revoke.
  // Neither touches the signed payload, so nothing is re-signed.
  // -------------------------------------------------------------------------

  fastify.post('/bulk-tag', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER', 'MEMBER')],
    preValidation: zodValidator({ body: bulkTagSchema }),
  }, async (request, reply) => {
    try {
      const audit = organizeAudit(auditContext(request), request.user!.orgId, 'qr.bulkTag', 'QRCode');
      return reply.send(await bulkTag(fastify.prisma, request.user!.orgId, request.body as BulkTagInput, audit));
    } catch (err) {
      if (sendOrganizeError(err, reply)) return;
      throw err;
    }
  });

  fastify.post('/bulk-move', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER', 'MEMBER')],
    preValidation: zodValidator({ body: bulkMoveSchema }),
  }, async (request, reply) => {
    try {
      const audit = organizeAudit(auditContext(request), request.user!.orgId, 'qr.bulkMove', 'QRCode');
      return reply.send(await bulkMove(fastify.prisma, request.user!.orgId, request.body as BulkMoveInput, audit));
    } catch (err) {
      if (sendOrganizeError(err, reply)) return;
      throw err;
    }
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

    // The destination allowlist (ADR-0008 D8), per item like Web Risk.
    const policy = await readPolicy(fastify.prisma, organizationId);

    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      const policyRefused = allowlistRefusal(policy, [item.destinationUrl]);
      if (policyRefused) {
        results.push({ index: i, success: false, error: policyRefused.body.message, errorCode: 'DESTINATION_NOT_ALLOWED', label: item.label });
        continue;
      }
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
          { ...item, issuerVerified, revision: revisionContext(request) },
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
        if (err instanceof PolicyRefusalError) {
          errorCode = 'DESTINATION_NOT_ALLOWED';
        } else if (err instanceof RenderUnavailableError) {
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
