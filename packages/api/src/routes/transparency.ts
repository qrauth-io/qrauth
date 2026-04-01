import type { FastifyInstance } from 'fastify';
import { transparencyLogQuerySchema } from '@vqr/shared';
import { zodValidator } from '../middleware/validate.js';
import { rateLimitPublic } from '../middleware/rateLimit.js';
import { TransparencyLogService } from '../services/transparency.js';
import { z } from 'zod';

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
}
