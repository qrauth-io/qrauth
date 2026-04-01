import type { FastifyInstance } from 'fastify';
import { verifyQuerySchema } from '@vqr/shared';
import { zodValidator } from '../middleware/validate.js';
import { rateLimitPublic } from '../middleware/rateLimit.js';
import { SigningService } from '../services/signing.js';
import { GeoService } from '../services/geo.js';
import { TransparencyLogService } from '../services/transparency.js';
import { cacheGet, cacheSet } from '../lib/cache.js';
import { hashString } from '../lib/crypto.js';
import { scanQueue } from '../lib/queue.js';
import { CACHE_TTL } from '@vqr/shared';
import { z } from 'zod';

// ---------------------------------------------------------------------------
// Local parameter schema
// ---------------------------------------------------------------------------

const tokenParamsSchema = z.object({
  token: z.string().min(1, 'Token is required'),
});

// ---------------------------------------------------------------------------
// Response type (mirrors VerificationResult from shared types)
// ---------------------------------------------------------------------------

interface VerificationResponse {
  verified: boolean;
  reason?: string;
  organization: {
    id: string;
    name: string;
    slug: string;
    trustLevel: string;
    kycStatus: string;
  };
  destination_url: string;
  location_match: {
    matched: boolean;
    distanceM: number | null;
    registeredAddress: string | null;
  };
  security: {
    signatureValid: boolean;
    proxyDetected: boolean;
    trustScore: number;
    transparencyLogVerified: boolean;
  };
  scannedAt: string;
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

export default async function verifyRoutes(fastify: FastifyInstance): Promise<void> {
  const signingService = new SigningService(fastify.prisma);
  const geoService = new GeoService(fastify.prisma);
  const transparencyService = new TransparencyLogService(fastify.prisma);

  // -------------------------------------------------------------------------
  // GET /:token — Core verification (public, no auth)
  // -------------------------------------------------------------------------

  fastify.get('/:token', {
    config: { rateLimit: rateLimitPublic },
    preValidation: zodValidator({
      params: tokenParamsSchema,
      querystring: verifyQuerySchema,
    }),
  }, async (request, reply) => {
    const { token } = request.params as { token: string };
    const query = request.query as { clientLat?: number; clientLng?: number };

    const scannedAt = new Date().toISOString();
    const cacheKey = `verify:${token}`;

    // ------------------------------------------------------------------
    // 1. Try cache first (only for the static parts — geo is per-request)
    // ------------------------------------------------------------------
    const cached = await cacheGet<Omit<VerificationResponse, 'location_match' | 'scannedAt'>>(cacheKey);

    // ------------------------------------------------------------------
    // 2. Fetch QR code from database
    // ------------------------------------------------------------------
    const qrCode = await fastify.prisma.qRCode.findUnique({
      where: { token },
      include: {
        organization: {
          select: {
            id: true,
            name: true,
            slug: true,
            trustLevel: true,
            kycStatus: true,
          },
        },
        signingKey: {
          select: {
            publicKey: true,
            keyId: true,
            status: true,
          },
        },
        transparencyLogEntry: {
          select: { logIndex: true, entryHash: true, previousHash: true },
        },
      },
    });

    if (!qrCode) {
      return reply.status(404).send({
        statusCode: 404,
        error: 'Not Found',
        message: `No QR code found for token "${token}".`,
      });
    }

    // ------------------------------------------------------------------
    // 3. Status checks
    // ------------------------------------------------------------------
    if (qrCode.status === 'REVOKED') {
      return reply.send({
        verified: false,
        reason: 'This QR code has been revoked by its issuer.',
        organization: qrCode.organization,
        destination_url: qrCode.destinationUrl,
        location_match: { matched: false, distanceM: null, registeredAddress: null },
        security: {
          signatureValid: false,
          proxyDetected: false,
          trustScore: 0,
          transparencyLogVerified: false,
        },
        scannedAt,
      } satisfies VerificationResponse);
    }

    if (qrCode.status === 'EXPIRED' || (qrCode.expiresAt && qrCode.expiresAt < new Date())) {
      return reply.send({
        verified: false,
        reason: 'This QR code has expired.',
        organization: qrCode.organization,
        destination_url: qrCode.destinationUrl,
        location_match: { matched: false, distanceM: null, registeredAddress: null },
        security: {
          signatureValid: false,
          proxyDetected: false,
          trustScore: 0,
          transparencyLogVerified: false,
        },
        scannedAt,
      } satisfies VerificationResponse);
    }

    // ------------------------------------------------------------------
    // 4. Cryptographic signature verification
    // ------------------------------------------------------------------
    const signatureValid = signingService.verifyQRCode(
      qrCode.signingKey.publicKey,
      qrCode.signature,
      qrCode.token,
      qrCode.destinationUrl,
      qrCode.geoHash ?? '',
      qrCode.expiresAt?.toISOString() ?? '',
    );

    // ------------------------------------------------------------------
    // 5. Transparency log chain check
    // ------------------------------------------------------------------
    let transparencyLogVerified = false;
    if (qrCode.transparencyLogEntry) {
      try {
        const proof = await transparencyService.getInclusionProof(qrCode.id);
        // A simple chain check: if this is not the genesis entry, the
        // previousHash stored on this entry must match the prior entry's hash.
        if (proof.previous) {
          transparencyLogVerified =
            proof.entry.previousHash === proof.previous.entryHash;
        } else {
          // Genesis entry — no previous hash to validate against.
          transparencyLogVerified = true;
        }
      } catch {
        transparencyLogVerified = false;
      }
    }

    // ------------------------------------------------------------------
    // 6. Geo-proximity check (per-request, not cached)
    // ------------------------------------------------------------------
    let locationMatch: VerificationResponse['location_match'] = {
      matched: false,
      distanceM: null,
      registeredAddress: null,
    };

    if (
      query.clientLat !== undefined &&
      query.clientLng !== undefined &&
      qrCode.latitude !== null &&
      qrCode.longitude !== null
    ) {
      const proximity = geoService.checkProximity(
        qrCode.latitude,
        qrCode.longitude,
        qrCode.radiusM,
        query.clientLat,
        query.clientLng,
      );

      locationMatch = {
        matched: proximity.matched,
        distanceM: Math.round(proximity.distanceM),
        // Use the stored geohash as a proxy for the registered address.
        // A real implementation would reverse-geocode the coordinates.
        registeredAddress: qrCode.geoHash ?? null,
      };
    } else if (qrCode.latitude !== null && qrCode.longitude !== null) {
      // Location is registered on the QR code but client did not supply coords.
      locationMatch = {
        matched: false,
        distanceM: null,
        registeredAddress: qrCode.geoHash ?? null,
      };
    }

    // ------------------------------------------------------------------
    // 7. Build response and populate cache (static parts only)
    // ------------------------------------------------------------------
    const staticParts = {
      verified: signatureValid,
      organization: qrCode.organization,
      destination_url: qrCode.destinationUrl,
      security: {
        signatureValid,
        proxyDetected: false, // populated by scan worker post-response
        trustScore: 100,      // populated by scan worker post-response
        transparencyLogVerified,
      },
    };

    // Cache the static verification result for VERIFY_RESULT TTL seconds.
    // We deliberately exclude location_match and scannedAt as they are
    // per-request values that must never be served stale.
    cacheSet(cacheKey, staticParts, CACHE_TTL.VERIFY_RESULT).catch((err) => {
      fastify.log.warn({ err, token }, 'Failed to cache verification result');
    });

    const response: VerificationResponse = {
      ...staticParts,
      location_match: locationMatch,
      scannedAt,
    };

    // ------------------------------------------------------------------
    // 8. Enqueue scan recording asynchronously (fire-and-forget)
    // ------------------------------------------------------------------
    const clientIpHash = hashString(request.ip);

    scanQueue
      .add('record-scan', {
        qrCodeId: qrCode.id,
        clientIpHash,
        clientLat: query.clientLat ?? null,
        clientLng: query.clientLng ?? null,
        userAgent: request.headers['user-agent'] ?? null,
        metadata: {
          signatureValid,
          token,
        },
      })
      .catch((err) => {
        fastify.log.warn({ err, token }, 'Failed to enqueue scan recording');
      });

    return reply.send(response);
  });

  // -------------------------------------------------------------------------
  // POST /:token/webauthn — Stub (Phase 2)
  // -------------------------------------------------------------------------

  fastify.post('/:token/webauthn', {
    config: { rateLimit: rateLimitPublic },
  }, async (_request, reply) => {
    return reply.status(501).send({
      statusCode: 501,
      error: 'Not Implemented',
      message: 'WebAuthn verification coming in Phase 2.',
    });
  });
}
