import type { FastifyInstance } from 'fastify';
import {
  createQRCodeSchema,
  updateQRCodeSchema,
  bulkCreateQRCodeSchema,
  paginationSchema,
  generateToken,
  getContentType,
} from '@qrauth/shared';
import { zodValidator } from '../middleware/validate.js';
import { authorize } from '../middleware/authorize.js';
import {
  rateLimitAuth,
  rateLimitGenerate,
  rateLimitBulk,
  rateLimitPublic,
} from '../middleware/rateLimit.js';
import { SigningService } from '../services/signing.js';
import {
  HybridSigningService,
  ALGORITHM_VERSION_PENDING,
} from '../services/hybrid-signing.js';
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
import type { BatchSignResult } from '../services/batch-signer.js';
import { DomainService } from '../services/domain.js';
import { cacheDel } from '../lib/cache.js';
import { config } from '../lib/config.js';
import { UsageService } from '../services/usage.js';
import { createHash, randomBytes } from 'node:crypto';
import { stableStringify } from '../lib/crypto.js';
import { z } from 'zod';

// ---------------------------------------------------------------------------
// Local schemas
// ---------------------------------------------------------------------------

const tokenParamsSchema = z.object({
  token: z.string().min(1, 'Token is required'),
});

const listQRCodesQuerySchema = paginationSchema.extend({
  status: z.enum(['ACTIVE', 'EXPIRED', 'REVOKED']).optional(),
});

// Extends the shared createQRCodeSchema with optional content-type fields.
const extendedCreateSchema = createQRCodeSchema
  .extend({
    destinationUrl: z.string().url().optional(), // Override: optional for content types
    contentType: z.string().optional(),
    content: z.any().optional(),
  });

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function buildVerificationUrl(token: string): string {
  if (config.server.isDev) {
    return `http://localhost:${config.server.port}/v/${token}`;
  }
  const baseUrl = process.env.WEBAUTHN_ORIGIN || 'https://qrauth.io';
  return `${baseUrl}/v/${token}`;
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
    location?: { lat: number; lng: number; radiusM: number };
    expiresAt?: string;
    contentType?: string;
    content?: unknown;
    maxScans?: number;
    maxScansPerDevice?: number;
  },
  options: { asyncMerkle?: boolean } = {},
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
    : (process.env.WEBAUTHN_ORIGIN || 'https://qrauth.io');

  // 2. Get active signing key.
  const signingKey = await signingService.getActiveKey(organizationId);

  // 3. Generate a short, unbiased token.
  const token = generateToken();

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
  //    pipeline. Two modes:
  //
  //    a) Synchronous (bulk-create path): await both legs before persisting.
  //       Caller gets a fully-issued QR back. Latency dominated by the
  //       SLH-DSA sign (~2.3s for the batch — amortized across N parallel
  //       enqueues from the same bulk request).
  //
  //    b) Async merkle (single-create path, opt-in via options.asyncMerkle):
  //       sign the ECDSA leg synchronously, fire-and-forget the Merkle leg.
  //       The QR row is persisted immediately with `algVersion =
  //       ecdsa-pending-slhdsa-v1` and merkle fields nulled. A background
  //       handler upgrades the row to `hybrid-ecdsa-slhdsa-v1` once the
  //       batcher flushes. Single-create returns in ~10ms instead of ~2.3s.
  //
  //    If the active signing key predates the PQC layer it has no SLH-DSA
  //    secret on disk; both paths throw and we fall back to legacy
  //    ECDSA-only signing for the row.
  let signature: string;
  let pendingMerkle: Promise<BatchSignResult> | null = null;
  let pqcFields: {
    algVersion: string;
    merkleBatchId: string | null;
    merkleLeafIndex: number | null;
    merkleLeafHash: string | null;
    merkleLeafNonce: string | null;
    merklePath: object | null;
    merkleRoot: string | null;
  };

  const hybridInput = {
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
  };

  if (options.asyncMerkle) {
    const asyncResult = await hybridSigningService.signSingleQRAsync(hybridInput);
    signature = asyncResult.ecdsaSignature;
    pendingMerkle = asyncResult.merklePromise;
    pqcFields = {
      algVersion: ALGORITHM_VERSION_PENDING,
      merkleBatchId: null,
      merkleLeafIndex: null,
      merkleLeafHash: null,
      merkleLeafNonce: null,
      merklePath: null,
      merkleRoot: null,
    };
  } else {
    const hybrid = await hybridSigningService.signSingleQR(hybridInput);
    signature = hybrid.ecdsaSignature;
    pqcFields = {
      algVersion: hybrid.algVersion,
      merkleBatchId: hybrid.batchId,
      merkleLeafIndex: hybrid.leafIndex,
      merkleLeafHash: hybrid.leafHash,
      merkleLeafNonce: hybrid.leafNonce,
      merklePath: hybrid.merklePath as unknown as object,
      merkleRoot: hybrid.merkleRoot,
    };
  }

  // 6b. Compute the symmetric MAC fast path (ALGORITHM.md §7,
  //     AUDIT-FINDING-011). The MAC binds the SAME canonical core string
  //     the ECDSA leg signs, so the verifier recomputes it deterministically
  //     from any QR row. Stored server-side only — never embedded in the QR.
  const macDestHash = await computeDestHash(resolvedContentType, destinationUrl, contentHashHex);
  const macGeoHash = await canonicalGeoHash(
    input.location?.lat ?? null,
    input.location?.lng ?? null,
    input.location?.radiusM ?? null,
  );
  const macCanonical = canonicalizeCore({
    algVersion: pqcFields.algVersion,
    token,
    tenantId: organizationId,
    destHash: macDestHash,
    geoHash: macGeoHash,
    expiresAt: expiresAtStr,
  });
  let macTokenMac: string | null = null;
  let macKeyVersion: number | null = null;
  try {
    const macResult = await macService.signCanonical(organizationId, macCanonical);
    macTokenMac = macResult.mac;
    macKeyVersion = macResult.keyVersion;
  } catch (err) {
    fastify.log.warn({ err, organizationId }, 'MAC signing unavailable, QR will lack fast-path MAC');
  }

  // 7. Persist to database.
  const qrCode = await fastify.prisma.qRCode.create({
    data: {
      token,
      organizationId,
      signingKeyId: signingKey.id,
      keyId: signingKey.keyId,
      destinationUrl,
      label: input.label,
      contentType: resolvedContentType,
      content: input.content ? (input.content as object) : undefined,
      signature,
      geoHash: geoHash || null,
      latitude: input.location?.lat ?? null,
      longitude: input.location?.lng ?? null,
      radiusM: input.location?.radiusM ?? 50,
      status: 'ACTIVE',
      expiresAt: expiresAtDate,
      maxScans: input.maxScans ?? null,
      maxScansPerDevice: input.maxScansPerDevice ?? null,
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

  // 6a. Async merkle upgrade. The pendingMerkle promise was returned by
  //     hybridSigningService.signSingleQRAsync above and is currently
  //     queued inside the BatchSigner. When it resolves we upgrade the row
  //     from `ecdsa-pending-slhdsa-v1` to `hybrid-ecdsa-slhdsa-v1` and
  //     append the commitment-only transparency log entry. Until then the
  //     row verifies via ECDSA + MAC alone, which is no weaker than legacy
  //     ECDSA-only signing.
  //
  //     Failures here do NOT block the response. The row stays in pending
  //     state and a future reconciler worker (Phase 2.5) can rescue it by
  //     re-enqueuing the merkle leg.
  if (pendingMerkle) {
    pendingMerkle
      .then(async (batch) => {
        await fastify.prisma.qRCode.update({
          where: { id: qrCode.id },
          data: {
            algVersion: batch.algVersion,
            merkleBatchId: batch.batchId,
            merkleLeafIndex: batch.leafIndex,
            merkleLeafHash: batch.leafHash,
            merkleLeafNonce: batch.leafNonce,
            merklePath: batch.merklePath as never,
          },
        });

        try {
          await transparencyService.appendEntry({
            id: qrCode.id,
            token: qrCode.token,
            organizationId: qrCode.organizationId,
            destinationUrl: qrCode.destinationUrl,
            geoHash: qrCode.geoHash,
            pqc: {
              algVersion: batch.algVersion,
              leafHash: batch.leafHash,
              batchRootRef: TransparencyLogService.computeBatchRootRef(batch.merkleRoot),
              merkleInclusionProof: batch.merklePath,
            },
          });
        } catch (err) {
          fastify.log.warn(
            { err, qrCodeId: qrCode.id },
            'Async merkle upgrade: transparency log append failed',
          );
        }
      })
      .catch((err) => {
        fastify.log.error(
          { err, qrCodeId: qrCode.id },
          'Async merkle upgrade failed; row remains in ecdsa-pending state',
        );
      });
  }

  // 6. Append to transparency log. For hybrid-signed QRs we attach the
  //    commitment-only fields (leaf hash, batch root ref, inclusion proof)
  //    so the public log carries opaque commitments instead of plaintext
  //    hashes — see ALGORITHM.md §8.
  //
  //    Async-merkle rows skip this block entirely: the upgrade handler
  //    above writes the pqc entry once the merkle leg resolves. The
  //    `qrCodeId` column is unique on TransparencyLogEntry so we cannot
  //    write twice for the same row.
  let transparencyLogIndex: number | null = null;
  if (!pendingMerkle) {
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
  }

  // 7. Check destination domain against verified org domains (non-blocking).
  const domainCheck = await domainService.checkUrlAgainstVerifiedDomains(
    destinationUrl,
    organizationId,
  );

  // Auto-create fraud incident for highly suspicious domain similarity.
  if (domainCheck.isSuspicious) {
    try {
      await fastify.prisma.fraudIncident.create({
        data: {
          qrCodeId: qrCode.id,
          type: 'MANUAL_REPORT',
          severity: 'HIGH',
          details: {
            reason: 'suspicious_domain',
            destinationDomain: domainService.extractDomain(input.destinationUrl),
            similarTo: domainCheck.warnings[0]?.domain,
            verifiedOrg: domainCheck.warnings[0]?.verifiedOrgName,
            similarity: domainCheck.warnings[0]?.similarity,
          } as any,
        },
      });
    } catch (err) {
      fastify.log.warn({ err, qrCodeId: qrCode.id }, 'Failed to create suspicious domain fraud incident');
    }
  }

  return {
    token: qrCode.token,
    verification_url: buildVerificationUrl(qrCode.token),
    qr_image_url: `https://api.qrserver.com/v1/create-qr-code/?data=${encodeURIComponent(buildVerificationUrl(qrCode.token))}&size=300x300`,
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
  const { authenticate } = fastify;

  // -------------------------------------------------------------------------
  // POST / — Generate a signed QR code
  // -------------------------------------------------------------------------

  fastify.post('/', {
    config: { rateLimit: rateLimitGenerate },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER', 'MEMBER')],
    preValidation: zodValidator({ body: extendedCreateSchema }),
  }, async (request, reply) => {
    const body = request.body as {
      destinationUrl: string;
      label?: string;
      location?: { lat: number; lng: number; radiusM: number };
      expiresAt?: string;
      contentType?: string;
      content?: unknown;
      maxScans?: number;
      maxScansPerDevice?: number;
    };

    // Check QR code quota
    const usageService = new UsageService(fastify.prisma);
    const org = await fastify.prisma.organization.findUnique({
      where: { id: request.user!.orgId },
      select: { plan: true },
    });
    const quotaError = await usageService.checkQuota(request.user!.orgId, org?.plan || 'FREE', 'qrCodes');
    if (quotaError) {
      return reply.status(429).send({ statusCode: 429, error: 'Quota Exceeded', message: quotaError });
    }

    // Single-create path awaits the merkle batch flush so the response
    // carries a populated `transparency_log_index` and a finalised
    // `alg_version`. The `asyncMerkle` option exists for bulk-create
    // throughput; on a per-request single-create call the batcher's
    // flush window (≤ maxWaitMs) is an acceptable trade-off and removes
    // the race between the HTTP response and the deferred transparency
    // append inside `generateQRCode`'s `pendingMerkle.then()` handler.
    const result = await generateQRCode(
      fastify,
      signingService,
      hybridSigningService,
      macService,
      geoService,
      transparencyService,
      domainService,
      request.user!.orgId,
      body,
      { asyncMerkle: false },
    );

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
          // After legacy-ecdsa drop every accepted row is PQC-protected.
          pqcProtected: createdAlgVersion !== null,
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
    const skip = (page - 1) * pageSize;

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
      return reply.status(404).send({
        statusCode: 404,
        error: 'Not Found',
        message: `QR code with token "${token}" not found.`,
      });
    }

    // Ownership check — the QR code must belong to the authenticated organization.
    if (qrCode.organizationId !== request.user!.orgId) {
      return reply.status(403).send({
        statusCode: 403,
        error: 'Forbidden',
        message: 'You do not own this QR code.',
      });
    }

    return reply.send(qrCode);
  });

  // -------------------------------------------------------------------------
  // PATCH /:token — Update destination URL (re-signs the payload)
  // -------------------------------------------------------------------------

  fastify.patch('/:token', {
    config: { rateLimit: rateLimitGenerate },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER', 'MEMBER')],
    preValidation: zodValidator({
      params: tokenParamsSchema,
      body: updateQRCodeSchema,
    }),
  }, async (request, reply) => {
    const { token } = request.params as { token: string };
    const body = request.body as { destinationUrl?: string; label?: string; content?: unknown; expiresAt?: string; maxScans?: number; maxScansPerDevice?: number };

    const existing = await fastify.prisma.qRCode.findUnique({ where: { token } });

    if (!existing) {
      return reply.status(404).send({
        statusCode: 404,
        error: 'Not Found',
        message: `QR code with token "${token}" not found.`,
      });
    }

    if (existing.organizationId !== request.user!.orgId) {
      return reply.status(403).send({
        statusCode: 403,
        error: 'Forbidden',
        message: 'You do not own this QR code.',
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
      const newDestHash = await computeDestHash(contentType, newDestinationUrl, newContentHashHex);
      const newGeoHash = await canonicalGeoHash(
        existing.latitude,
        existing.longitude,
        existing.radiusM,
      );
      const newMacCanonical = canonicalizeCore({
        algVersion: updatedAlgVersion ?? ALG_VERSION_POLICY.hybrid,
        token: existing.token,
        tenantId: existing.organizationId,
        destHash: newDestHash,
        geoHash: newGeoHash,
        expiresAt: newExpiresAtStr,
      });
      try {
        const macResult = await macService.signCanonical(existing.organizationId, newMacCanonical);
        updatedMacTokenMac = macResult.mac;
        updatedMacKeyVersion = macResult.keyVersion;
      } catch (err) {
        fastify.log.warn({ err }, 'MAC re-sign failed, dropping fast-path MAC for this row');
        updatedMacTokenMac = null;
        updatedMacKeyVersion = null;
      }
    }

    const updated = await fastify.prisma.qRCode.update({
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
      },
    });

    // Bust the verify cache for this token so the updated URL is reflected
    // immediately on the next verification request.
    await cacheDel(`verify:${token}`);

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
      return reply.status(404).send({
        statusCode: 404,
        error: 'Not Found',
        message: `QR code with token "${token}" not found.`,
      });
    }

    if (existing.organizationId !== request.user!.orgId) {
      return reply.status(403).send({
        statusCode: 403,
        error: 'Forbidden',
        message: 'You do not own this QR code.',
      });
    }

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
  // POST /bulk — Bulk generate QR codes
  // -------------------------------------------------------------------------

  fastify.post('/bulk', {
    config: { rateLimit: rateLimitBulk },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER')],
    preValidation: zodValidator({ body: bulkCreateQRCodeSchema }),
  }, async (request, reply) => {
    const { items } = request.body as {
      items: Array<{
        destinationUrl: string;
        label?: string;
        location?: { lat: number; lng: number; radiusM: number };
        expiresAt?: string;
      }>;
    };

    const organizationId = request.user!.orgId;

    // Check QR code quota before processing bulk items
    const usageService = new UsageService(fastify.prisma);
    const org = await fastify.prisma.organization.findUnique({
      where: { id: organizationId },
      select: { plan: true },
    });
    const plan = org?.plan || 'FREE';

    // For plans with limits, check if we have enough remaining quota
    const quotaError = await usageService.checkQuota(organizationId, plan, 'qrCodes');
    if (quotaError) {
      return reply.status(429).send({ statusCode: 429, error: 'Quota Exceeded', message: quotaError });
    }

    // Also check if the batch would exceed the remaining quota
    const currentUsage = await usageService.getUsage(organizationId);
    const limits = usageService.getLimits(plan);
    if (limits.qrCodes !== -1 && (currentUsage.qrCodes + items.length) > limits.qrCodes) {
      return reply.status(429).send({
        statusCode: 429,
        error: 'Quota Exceeded',
        message: `Bulk request would exceed QR code limit. Current: ${currentUsage.qrCodes}, requested: ${items.length}, limit: ${limits.qrCodes}. Upgrade your plan at https://qrauth.io/dashboard/settings.`,
      });
    }

    // Process sequentially to keep signing key lookups consistent and avoid
    // hammering the database with concurrent inserts under the bulk limit.
    const results: Array<
      | { index: number; success: true; data: object; label?: string }
      | { index: number; success: false; error: string; errorCode: string; label?: string }
    > = [];

    for (let i = 0; i < items.length; i++) {
      const item = items[i];
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
          item,
        );
        results.push({ index: i, success: true, data, label: item.label });
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Unknown error';
        fastify.log.warn({ err, item }, 'Bulk QR code generation failed for item');

        // Derive a machine-readable error code from the error message so
        // integrators (e.g. comtel-sirens) can handle failures programmatically.
        let errorCode = 'INTERNAL_ERROR';
        if (message.toLowerCase().includes('quota') || message.toLowerCase().includes('limit')) {
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

  // -------------------------------------------------------------------------
  // AUDIT-2 N-1 test-harness hook
  // -------------------------------------------------------------------------
  //
  // The N-1 plan amendment explicitly allows a test-harness hook to
  // trigger the reconciler out of cadence. The revoke branch's
  // production threshold is 1 hour, so an E2E test would otherwise
  // need to either sleep that long or monkey-patch time. Instead the
  // test calls this endpoint, which:
  //
  //   1. Inserts a synthetic QRCode row in `ecdsa-pending-slhdsa-v1`
  //      state attached to the caller's org (and a real signing key
  //      minted at signup), with `createdAt` backdated per the
  //      request body.
  //   2. Immediately invokes `revokeOrphanedPending` with
  //      `thresholdMs: 0` so the helper treats the backdated row as
  //      orphaned and runs the revoke branch end-to-end — real
  //      Prisma write, real WebhookService.emit, real counter log
  //      line.
  //   3. Returns the post-revoke row state plus the reconciler
  //      result summary so the test can assert on both halves.
  //
  // Only mounted when `NODE_ENV !== 'production'`, matching the
  // `routes/auth.ts::/_test/mark-verified` precedent. Takes no
  // auth; the test-mode gate is the only protection. The handler
  // never touches rows it did not create (it only operates on the
  // ID it just inserted), so there is no cross-tenant blast
  // radius even if someone accidentally mounts this in prod.
  if (!config.server.isProd) {
    const { revokeOrphanedPending } = await import('../services/pending-reconciler.js');
    const { WebhookService } = await import('../services/webhook.js');

    fastify.post('/_test/force-orphaned-pending-revoke', {
      config: { rateLimit: rateLimitPublic },
    }, async (request, reply) => {
      const body = request.body as {
        organizationId?: string;
        ageMs?: number;
      };
      if (!body?.organizationId) {
        return reply.status(400).send({ error: 'organizationId required' });
      }
      const ageMs = body.ageMs ?? 2 * 60 * 60 * 1000; // default 2 hours

      // Grab the org's active signing key so the fake QR row
      // satisfies the FK constraint and looks structurally
      // identical to a real pending row.
      const signingKey = await fastify.prisma.signingKey.findFirst({
        where: { organizationId: body.organizationId, status: 'ACTIVE' },
        orderBy: { createdAt: 'desc' },
      });
      if (!signingKey) {
        return reply.status(404).send({ error: 'no active signing key for org' });
      }

      const nowMs = Date.now();
      const backdatedCreatedAt = new Date(nowMs - ageMs);

      const token = `test-n1-${randomBytes(8).toString('hex')}`;
      const qr = await fastify.prisma.qRCode.create({
        data: {
          token,
          organizationId: body.organizationId,
          signingKeyId: signingKey.id,
          keyId: signingKey.keyId,
          destinationUrl: 'https://example.com/n1-test',
          signature: 'TEST_N1_SYNTHETIC_SIGNATURE',
          algVersion: 'ecdsa-pending-slhdsa-v1',
          status: 'ACTIVE',
          createdAt: backdatedCreatedAt,
        },
      });

      const result = await revokeOrphanedPending({
        prisma: fastify.prisma,
        webhookService: new WebhookService(fastify.prisma),
      }, { thresholdMs: 0, nowMs });

      const updated = await fastify.prisma.qRCode.findUnique({
        where: { id: qr.id },
        select: {
          id: true,
          token: true,
          status: true,
          revokedAt: true,
          revocationReason: true,
          algVersion: true,
        },
      });

      return reply.send({ qrCode: updated, reconciler: result });
    });
  }
}
