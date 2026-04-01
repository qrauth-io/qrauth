import type { FastifyInstance } from 'fastify';
import {
  createQRCodeSchema,
  updateQRCodeSchema,
  bulkCreateQRCodeSchema,
  paginationSchema,
  generateToken,
} from '@vqr/shared';
import { zodValidator } from '../middleware/validate.js';
import { authorize } from '../middleware/authorize.js';
import {
  rateLimitAuth,
  rateLimitGenerate,
  rateLimitBulk,
} from '../middleware/rateLimit.js';
import { SigningService } from '../services/signing.js';
import { GeoService } from '../services/geo.js';
import { TransparencyLogService } from '../services/transparency.js';
import { cacheDel } from '../lib/cache.js';
import { config } from '../lib/config.js';
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

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function buildVerificationUrl(token: string): string {
  if (config.server.isDev) {
    return `http://localhost:${config.server.port}/v/${token}`;
  }
  return `https://vqr.io/v/${token}`;
}

/**
 * Core QR code generation logic extracted so it can be reused by both the
 * single-create and bulk-create endpoints without duplication.
 */
async function generateQRCode(
  fastify: FastifyInstance,
  signingService: SigningService,
  geoService: GeoService,
  transparencyService: TransparencyLogService,
  organizationId: string,
  input: {
    destinationUrl: string;
    label?: string;
    location?: { lat: number; lng: number; radiusM: number };
    expiresAt?: string;
  },
) {
  // 1. Get active signing key.
  const signingKey = await signingService.getActiveKey(organizationId);

  // 2. Generate a short, unbiased token.
  const token = generateToken();

  // 3. Encode geohash when location is provided.
  const geoHash = input.location
    ? geoService.encodeGeoHash(input.location.lat, input.location.lng)
    : '';

  const expiresAtStr = input.expiresAt ?? '';

  // 4. Sign the canonical payload.
  const signature = await signingService.signQRCode(
    signingKey.keyId,
    token,
    input.destinationUrl,
    geoHash,
    expiresAtStr,
  );

  // 5. Persist to database.
  const qrCode = await fastify.prisma.qRCode.create({
    data: {
      token,
      organizationId,
      signingKeyId: signingKey.id,
      destinationUrl: input.destinationUrl,
      label: input.label,
      signature,
      geoHash: geoHash || null,
      latitude: input.location?.lat ?? null,
      longitude: input.location?.lng ?? null,
      radiusM: input.location?.radiusM ?? 50,
      status: 'ACTIVE',
      expiresAt: input.expiresAt ? new Date(input.expiresAt) : null,
    },
  });

  // 6. Append to transparency log (non-blocking best-effort — log failure
  //    should not abort the QR code creation response).
  let transparencyLogIndex: number | null = null;
  try {
    const logEntry = await transparencyService.appendEntry({
      id: qrCode.id,
      token: qrCode.token,
      organizationId: qrCode.organizationId,
      destinationUrl: qrCode.destinationUrl,
      geoHash: qrCode.geoHash,
    });
    transparencyLogIndex = logEntry.logIndex;
  } catch (err) {
    fastify.log.warn({ err, qrCodeId: qrCode.id }, 'Failed to append transparency log entry');
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
  };
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

export default async function qrCodeRoutes(fastify: FastifyInstance): Promise<void> {
  const signingService = new SigningService(fastify.prisma);
  const geoService = new GeoService(fastify.prisma);
  const transparencyService = new TransparencyLogService(fastify.prisma);
  const { authenticate } = fastify;

  // -------------------------------------------------------------------------
  // POST / — Generate a signed QR code
  // -------------------------------------------------------------------------

  fastify.post('/', {
    config: { rateLimit: rateLimitGenerate },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER', 'MEMBER')],
    preValidation: zodValidator({ body: createQRCodeSchema }),
  }, async (request, reply) => {
    const body = request.body as {
      destinationUrl: string;
      label?: string;
      location?: { lat: number; lng: number; radiusM: number };
      expiresAt?: string;
    };

    const result = await generateQRCode(
      fastify,
      signingService,
      geoService,
      transparencyService,
      request.user!.orgId,
      body,
    );

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
    const body = request.body as { destinationUrl?: string; label?: string };

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

    const newDestinationUrl = body.destinationUrl ?? existing.destinationUrl;

    // Re-sign with the organization's current active key when the URL changes.
    let signature = existing.signature;
    let signingKeyId = existing.signingKeyId;

    if (body.destinationUrl && body.destinationUrl !== existing.destinationUrl) {
      const activeKey = await signingService.getActiveKey(existing.organizationId);
      signature = await signingService.signQRCode(
        activeKey.keyId,
        existing.token,
        newDestinationUrl,
        existing.geoHash ?? '',
        existing.expiresAt?.toISOString() ?? '',
      );
      signingKeyId = activeKey.id;
    }

    const updated = await fastify.prisma.qRCode.update({
      where: { token },
      data: {
        destinationUrl: newDestinationUrl,
        label: body.label !== undefined ? body.label : existing.label,
        signature,
        signingKeyId,
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

    // Process sequentially to keep signing key lookups consistent and avoid
    // hammering the database with concurrent inserts under the bulk limit.
    const results: Array<{ success: true; data: object } | { success: false; error: string }> = [];

    for (const item of items) {
      try {
        const data = await generateQRCode(
          fastify,
          signingService,
          geoService,
          transparencyService,
          organizationId,
          item,
        );
        results.push({ success: true, data });
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Unknown error';
        fastify.log.warn({ err, item }, 'Bulk QR code generation failed for item');
        results.push({ success: false, error: message });
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
