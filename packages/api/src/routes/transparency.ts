import type { FastifyInstance } from 'fastify';
import { createHash } from 'node:crypto';
import { transparencyLogQuerySchema } from '@qrauth/shared';
import { zodValidator } from '../middleware/validate.js';
import { rateLimitPublic } from '../middleware/rateLimit.js';
import { TransparencyLogService } from '../services/transparency.js';
import { z } from 'zod';

// Local schema for the batch lookup endpoint. batchId is a hex string
// generated via generateSecureEntropy(16) — 32 lowercase hex chars. A
// strict validator here rejects path-traversal attempts before the
// query even hits Postgres.
const batchParamsSchema = z.object({
  batchId: z
    .string()
    .regex(/^[a-z0-9]{32}$/, 'batchId must be 32 lowercase hex chars'),
});

// ---------------------------------------------------------------------------
// Local parameter schema
// ---------------------------------------------------------------------------

const tokenParamsSchema = z.object({
  token: z.string().min(1, 'Token is required'),
});

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

export default async function transparencyRoutes(fastify: FastifyInstance): Promise<void> {
  const transparencyService = new TransparencyLogService(fastify.prisma);

  // -------------------------------------------------------------------------
  // GET /log — Paginated transparency log entries (public)
  // -------------------------------------------------------------------------

  fastify.get('/log', {
    config: { rateLimit: rateLimitPublic },
    preValidation: zodValidator({ querystring: transparencyLogQuerySchema }),
  }, async (request, reply) => {
    const query = request.query as {
      page: number;
      pageSize: number;
      startIndex?: number;
      endIndex?: number;
      organizationId?: string;
    };

    const { page, pageSize, startIndex, endIndex, organizationId } = query;
    const skip = (page - 1) * pageSize;

    const where = {
      ...(organizationId ? { organizationId } : {}),
      ...(startIndex !== undefined || endIndex !== undefined
        ? {
            logIndex: {
              ...(startIndex !== undefined ? { gte: startIndex } : {}),
              ...(endIndex !== undefined ? { lte: endIndex } : {}),
            },
          }
        : {}),
    };

    const [data, total] = await Promise.all([
      fastify.prisma.transparencyLogEntry.findMany({
        where,
        orderBy: { logIndex: 'asc' },
        skip,
        take: pageSize,
        select: {
          id: true,
          logIndex: true,
          qrCodeId: true,
          organizationId: true,
          tokenHash: true,
          destinationHash: true,
          geoHash: true,
          previousHash: true,
          entryHash: true,
          createdAt: true,
        },
      }),
      fastify.prisma.transparencyLogEntry.count({ where }),
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
  // GET /proof/:token — Inclusion proof for a specific QR code (public)
  // -------------------------------------------------------------------------

  fastify.get('/proof/:token', {
    config: { rateLimit: rateLimitPublic },
    preValidation: zodValidator({ params: tokenParamsSchema }),
  }, async (request, reply) => {
    const { token } = request.params as { token: string };

    // Resolve token → QR code record.
    const qrCode = await fastify.prisma.qRCode.findUnique({
      where: { token },
      select: { id: true, token: true, organizationId: true },
    });

    if (!qrCode) {
      return reply.status(404).send({
        statusCode: 404,
        error: 'Not Found',
        message: `No QR code found for token "${token}".`,
      });
    }

    // Retrieve the inclusion proof.
    let proof: Awaited<ReturnType<typeof transparencyService.getInclusionProof>>;
    try {
      proof = await transparencyService.getInclusionProof(qrCode.id);
    } catch {
      return reply.status(404).send({
        statusCode: 404,
        error: 'Not Found',
        message: `No transparency log entry found for token "${token}".`,
      });
    }

    // Verify chain linkage for this entry.
    const chainVerification = await transparencyService.verifyChain(
      proof.previous ? proof.previous.logIndex : proof.entry.logIndex,
      proof.next ? proof.next.logIndex : proof.entry.logIndex,
    );

    return reply.send({
      token: qrCode.token,
      entry: proof.entry,
      neighbours: {
        previous: proof.previous,
        next: proof.next,
      },
      chainVerification: {
        valid: chainVerification.valid,
        brokenAt: chainVerification.brokenAt ?? null,
      },
    });
  });

  // -------------------------------------------------------------------------
  // GET /batch/:batchId — Batch root entry for auditors (public)
  //
  // Returns the signed Merkle batch metadata for a given batchId. Public
  // because auditors must be able to verify any batch without credentials.
  // Response carries the SLH-DSA signature over the batch root plus a
  // SHA3-256 hash of the tenant's SLH-DSA public key — the public key
  // itself is NEVER returned from this endpoint. Auditors fetch the real
  // public key from an authenticated endpoint and compare its hash
  // against what we return here. This eliminates the public log as a
  // quantum-harvest surface (ALGORITHM.md §8).
  // -------------------------------------------------------------------------

  fastify.get('/batch/:batchId', {
    config: { rateLimit: rateLimitPublic },
    preValidation: zodValidator({ params: batchParamsSchema }),
  }, async (request, reply) => {
    const { batchId } = request.params as { batchId: string };

    const batch = await fastify.prisma.signedBatch.findUnique({
      where: { batchId },
      include: {
        signingKey: {
          select: { slhdsaPublicKey: true },
        },
      },
    });

    if (!batch) {
      return reply.status(404).send({
        statusCode: 404,
        error: 'Not Found',
        message: `No signed batch found for batchId "${batchId}".`,
      });
    }

    // Hash the SLH-DSA public key — never return the key itself. The
    // key lives on the same signingKey row as the ECDSA public key and
    // can be fetched via the authenticated tenant signing-key endpoint.
    // Auditors verify by comparing hashes.
    let tenantPublicKeyHash: string | null = null;
    if (batch.signingKey.slhdsaPublicKey) {
      tenantPublicKeyHash = createHash('sha3-256')
        .update(Buffer.from(batch.signingKey.slhdsaPublicKey, 'base64'))
        .digest('hex');
    }

    return reply.send({
      batchId: batch.batchId,
      merkleRoot: batch.merkleRoot,
      rootSignature: batch.rootSignature,
      tenantPublicKeyHash,
      algVersion: batch.algVersion,
      issuedAt: batch.issuedAt.toISOString(),
      tokenCount: batch.tokenCount,
    });
  });
}
