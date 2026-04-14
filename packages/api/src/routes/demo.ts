import type { FastifyInstance } from 'fastify';
import { createHash } from 'node:crypto';
import { z } from 'zod';
import { generateToken, getContentType } from '@qrauth/shared';
import { zodValidator } from '../middleware/validate.js';
import { rateLimitConfig } from '../middleware/rateLimit.js';
import { SigningService } from '../services/signing.js';
import { TransparencyLogService } from '../services/transparency.js';
import { DomainService } from '../services/domain.js';
import { config } from '../lib/config.js';

// ---------------------------------------------------------------------------
// Rate limit: 5 req/min per IP — aggressive because this is an unauthed, public
// endpoint backed by a single shared demo org.
// ---------------------------------------------------------------------------

const rateLimitDemo = rateLimitConfig('public', { max: 5, timeWindow: '1 minute' });

// ---------------------------------------------------------------------------
// Request body schema
// ---------------------------------------------------------------------------

const createDemoQRSchema = z.object({
  url: z.string().url('url must be a valid URL'),
  label: z.string().max(255).optional(),
});

// ---------------------------------------------------------------------------
// Module-level cache: org ID is resolved from the demo API key once and then
// reused for all subsequent requests to avoid a DB round-trip on every call.
// ---------------------------------------------------------------------------

let cachedOrgId: string | null = null;

// ---------------------------------------------------------------------------
// Helpers (mirrors qrcodes.ts internals)
// ---------------------------------------------------------------------------

function buildVerificationUrl(token: string): string {
  if (config.server.isDev) {
    return `http://localhost:${config.server.port}/v/${token}`;
  }
  const baseUrl = process.env.WEBAUTHN_ORIGIN || 'https://qrauth.io';
  return `${baseUrl}/v/${token}`;
}

function sha256hex(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

export default async function demoRoutes(fastify: FastifyInstance): Promise<void> {
  const signingService = new SigningService(fastify.prisma);
  const transparencyService = new TransparencyLogService(fastify.prisma);
  const domainService = new DomainService(fastify.prisma);

  // -------------------------------------------------------------------------
  // POST /qrcodes — Generate a signed QR code without authentication
  //
  // This endpoint simulates a "customer backend" calling the QRAuth API via
  // an API key.  The key is stored in env (DEMO_API_KEY) so the demo works
  // without exposing credentials in client-side code.
  //
  // Rate limited to 5 req/min per IP to prevent abuse of the shared demo org.
  // -------------------------------------------------------------------------

  fastify.post('/qrcodes', {
    config: { rateLimit: rateLimitDemo },
    preValidation: zodValidator({ body: createDemoQRSchema }),
  }, async (request, reply) => {
    // 1. Verify the demo API key is configured in this environment.
    if (!config.demo.apiKey) {
      return reply.status(503).send({
        statusCode: 503,
        error: 'Service Unavailable',
        message: 'Demo endpoint is not configured on this server.',
      });
    }

    // 2. Resolve the organization from the demo API key.  The result is cached
    //    at module scope so we only hit the database on the first request (or
    //    after a server restart).
    if (!cachedOrgId) {
      const keyHash = sha256hex(config.demo.apiKey);

      const apiKey = await fastify.prisma.apiKey.findFirst({
        where: {
          keyHash,
          revokedAt: null,
        },
        select: { organizationId: true },
      });

      if (!apiKey) {
        fastify.log.error('Demo API key not found or revoked — check DEMO_API_KEY env var');
        return reply.status(503).send({
          statusCode: 503,
          error: 'Service Unavailable',
          message: 'Demo endpoint is misconfigured.',
        });
      }

      cachedOrgId = apiKey.organizationId;
      fastify.log.info({ orgId: cachedOrgId }, 'Demo org ID resolved and cached');
    }

    const organizationId = cachedOrgId;
    const body = request.body as { url: string; label?: string };

    // 3. Resolve content type (always 'url' for the demo).
    const resolvedContentType = 'url';
    const typeRegistry = getContentType(resolvedContentType);
    if (!typeRegistry) {
      // Should never happen, but guard defensively.
      return reply.status(500).send({
        statusCode: 500,
        error: 'Internal Server Error',
        message: 'Unknown content type.',
      });
    }

    // 4. Get active signing key for the demo org.
    const signingKey = await signingService.getActiveKey(organizationId);

    // 5. Generate a short, unbiased token.
    const token = generateToken();

    // 6. For URL-type codes, the destination is the provided URL directly.
    const destinationUrl = body.url;

    // 7. No geo-location for the demo.
    const geoHash = '';
    const expiresAtStr = '';
    const contentHash = '';

    // 8. Sign the canonical payload.
    const signature = await signingService.signQRCode(
      signingKey.keyId,
      token,
      destinationUrl,
      geoHash,
      expiresAtStr,
      contentHash,
    );

    // 9. Persist to database.
    const qrCode = await fastify.prisma.qRCode.create({
      data: {
        token,
        organizationId,
        signingKeyId: signingKey.id,
        destinationUrl,
        label: body.label ?? 'Demo QR',
        contentType: resolvedContentType,
        signature,
        geoHash: null,
        latitude: null,
        longitude: null,
        radiusM: 50,
        status: 'ACTIVE',
        expiresAt: null,
      },
    });

    // 10. Append to transparency log (best-effort, non-blocking).
    try {
      await transparencyService.appendEntry({
        id: qrCode.id,
        token: qrCode.token,
        organizationId: qrCode.organizationId,
        destinationUrl: qrCode.destinationUrl,
        geoHash: qrCode.geoHash,
      });
    } catch (err) {
      fastify.log.warn({ err, qrCodeId: qrCode.id }, 'Demo: failed to append transparency log entry');
    }

    // 11. Domain similarity check (non-blocking, informational only for demo).
    try {
      await domainService.checkUrlAgainstVerifiedDomains(destinationUrl, organizationId);
    } catch (err) {
      fastify.log.warn({ err }, 'Demo: domain check failed');
    }

    // 12. Build and return the response.
    const verificationUrl = buildVerificationUrl(qrCode.token);

    return reply.status(201).send({
      token: qrCode.token,
      verification_url: verificationUrl,
      qr_image_url: `https://api.qrserver.com/v1/create-qr-code/?data=${encodeURIComponent(verificationUrl)}&size=300x300`,
      expires_at: qrCode.expiresAt,
    });
  });
}
