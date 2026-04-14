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
} from '../middleware/rateLimit.js';
import { SigningService } from '../services/signing.js';
import {
  HybridSigningService,
  ALGORITHM_VERSION_PENDING,
} from '../services/hybrid-signing.js';
import { MacService } from '../services/mac.js';
import { WebhookService } from '../services/webhook.js';
import { hashPayload, checkAlgVersion, ALG_VERSION_POLICY } from '@qrauth/shared';
import { GeoService } from '../services/geo.js';
import { TransparencyLogService } from '../services/transparency.js';
import type { MerkleNode } from '../services/merkle-signing.js';
import type { BatchSignResult } from '../services/batch-signer.js';
import { DomainService } from '../services/domain.js';
import { cacheDel } from '../lib/cache.js';
import { config } from '../lib/config.js';
import { UsageService } from '../services/usage.js';
import { createHash } from 'node:crypto';
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

  let contentHash = '';
  if (input.content && resolvedContentType !== 'url') {
    const parseResult = typeRegistry.schema.safeParse(input.content);
    if (!parseResult.success) {
      throw new Error(`Invalid content for type ${resolvedContentType}: ${parseResult.error.message}`);
    }
    // Deterministic JSON for hashing (PostgreSQL JSONB reorders keys alphabetically)
    contentHash = createHash('sha256').update(stableStringify(input.content)).digest('hex');
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

  try {
    if (options.asyncMerkle) {
      const asyncResult = await hybridSigningService.signSingleQRAsync({
        organizationId,
        signingKeyDbId: signingKey.id,
        signingKeyId: signingKey.keyId,
        token,
        destinationUrl,
        geoHash,
        expiresAt: expiresAtStr,
        contentHash,
        lat: input.location?.lat ?? null,
        lng: input.location?.lng ?? null,
        radiusM: input.location?.radiusM ?? null,
        expiresAtDate,
      });
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
      const hybrid = await hybridSigningService.signSingleQR({
        organizationId,
        signingKeyDbId: signingKey.id,
        signingKeyId: signingKey.keyId,
        token,
        destinationUrl,
        geoHash,
        expiresAt: expiresAtStr,
        contentHash,
        lat: input.location?.lat ?? null,
        lng: input.location?.lng ?? null,
        radiusM: input.location?.radiusM ?? null,
        expiresAtDate,
      });
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
  } catch (err) {
    fastify.log.warn(
      { err, signingKeyId: signingKey.keyId },
      'Hybrid signing unavailable, falling back to ECDSA-only',
    );
    signature = await signingService.signQRCode(
      signingKey.keyId,
      token,
      destinationUrl,
      geoHash,
      expiresAtStr,
      contentHash,
    );
    pqcFields = {
      algVersion: 'ecdsa-p256-sha256-v1',
      merkleBatchId: null,
      merkleLeafIndex: null,
      merkleLeafHash: null,
      merkleLeafNonce: null,
      merklePath: null,
      merkleRoot: null,
    };
  }

  // 6b. Compute the symmetric MAC fast path (ALGORITHM.md §7). The MAC
  //     covers the same canonical payload as the legacy ECDSA leg so the
  //     verifier can recompute it from any QR row without needing the
  //     merkle nonce. Stored server-side only — never embedded in the QR.
  const macCanonical = hashPayload(token, destinationUrl, geoHash, expiresAtStr, contentHash);
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
  const signingService = new SigningService(fastify.prisma);
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
      { asyncMerkle: true },
    );

    // Emit webhook (fire-and-forget). Includes the same securityContext
    // block that qr.scanned carries so consumers can correlate token
    // issuance with the signing algorithm from the moment the token
    // is minted. `merkleBatchId` may be null on async-pending rows
    // where the merkle leg is still flushing in the BatchSigner.
    const webhookService = new WebhookService(fastify.prisma);
    const createdAlgVersion = result.alg_version ?? ALG_VERSION_POLICY.legacyEcdsa;
    webhookService.emit(request.user!.orgId, {
      event: 'qr.created',
      data: {
        token: result.token,
        verification_url: result.verification_url,
        label: result.label,
        securityContext: {
          algVersion: createdAlgVersion,
          algVersionStatus: checkAlgVersion(createdAlgVersion),
          pqcProtected: createdAlgVersion !== ALG_VERSION_POLICY.legacyEcdsa,
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

    // Compute content hash for signing (non-URL types include content in the signature).
    let contentHash = '';
    if (newContent && contentType !== 'url') {
      contentHash = createHash('sha256').update(stableStringify(newContent)).digest('hex');
    }

    // Re-sign when the URL, content, or expiresAt changes (all are part of the signature).
    let signature = existing.signature;
    let signingKeyId = existing.signingKeyId;
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

      // Recompute the MAC over the new canonical payload. Even on the
      // ECDSA-only fallback path the MAC must be refreshed — otherwise the
      // verifier's MAC check would still validate the old destination URL.
      const newMacCanonical = hashPayload(
        existing.token,
        newDestinationUrl,
        existing.geoHash ?? '',
        newExpiresAt?.toISOString() ?? '',
        contentHash,
      );
      try {
        const macResult = await macService.signCanonical(existing.organizationId, newMacCanonical);
        updatedMacTokenMac = macResult.mac;
        updatedMacKeyVersion = macResult.keyVersion;
      } catch (err) {
        fastify.log.warn({ err }, 'MAC re-sign failed, dropping fast-path MAC for this row');
        updatedMacTokenMac = null;
        updatedMacKeyVersion = null;
      }

      try {
        const hybrid = await hybridSigningService.signSingleQR({
          organizationId: existing.organizationId,
          signingKeyDbId: activeKey.id,
          signingKeyId: activeKey.keyId,
          token: existing.token,
          destinationUrl: newDestinationUrl,
          geoHash: existing.geoHash ?? '',
          expiresAt: newExpiresAt?.toISOString() ?? '',
          contentHash,
          lat: existing.latitude,
          lng: existing.longitude,
          radiusM: existing.radiusM,
          expiresAtDate: newExpiresAt ?? null,
        });
        signature = hybrid.ecdsaSignature;
        signingKeyId = activeKey.id;
        updatedAlgVersion = hybrid.algVersion;
        updatedMerkleBatchId = hybrid.batchId;
        updatedMerkleLeafIndex = hybrid.leafIndex;
        updatedMerkleLeafHash = hybrid.leafHash;
        updatedMerkleLeafNonce = hybrid.leafNonce;
        updatedMerklePath = hybrid.merklePath as unknown as object;
      } catch (err) {
        fastify.log.warn({ err, signingKeyId: activeKey.keyId }, 'Hybrid re-signing unavailable, falling back to ECDSA-only');
        signature = await signingService.signQRCode(
          activeKey.keyId,
          existing.token,
          newDestinationUrl,
          existing.geoHash ?? '',
          newExpiresAt?.toISOString() ?? '',
          contentHash,
        );
        signingKeyId = activeKey.id;
        updatedAlgVersion = 'ecdsa-p256-sha256-v1';
        updatedMerkleBatchId = null;
        updatedMerkleLeafIndex = null;
        updatedMerkleLeafHash = null;
        updatedMerkleLeafNonce = null;
        updatedMerklePath = null;
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
}
