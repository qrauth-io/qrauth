import type { FastifyInstance } from 'fastify';
import { verifyQuerySchema } from '@qrauth/shared';
import { zodValidator } from '../middleware/validate.js';
import { rateLimitPublic } from '../middleware/rateLimit.js';
import { HybridSigningService } from '../services/hybrid-signing.js';
import { MacService } from '../services/mac.js';
import { verifyRowSignatures } from './verify-signatures.js';
import { GeoService } from '../services/geo.js';
import {
  canonicalizeCore,
  canonicalGeoHash,
  computeDestHash,
  checkAlgVersion,
  ALG_VERSION_POLICY,
  type AlgVersionStatus,
} from '@qrauth/shared';
import { TransparencyLogService } from '../services/transparency.js';
import { FraudDetectionService } from '../services/fraud.js';
import { DomainService } from '../services/domain.js';
import { cacheGet, cacheSet } from '../lib/cache.js';
import { hashString, stableStringify } from '../lib/crypto.js';
import { constantTimeEqualString } from '../lib/constant-time.js';
import { scanQueue } from '../lib/queue.js';
import { collectRequestMetadata } from '../lib/metadata.js';
import { config } from '../lib/config.js';
import { CACHE_TTL } from '@qrauth/shared';
import { z } from 'zod';
import { getRenderer } from '../renderers/index.js';
import { renderShell } from '../renderers/shell.js';
import type { RenderContext } from '../renderers/index.js';
import { UsageService } from '../services/usage.js';

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
    domainVerified: boolean;
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
    algVersion?: string | null;
    algVersionStatus?: AlgVersionStatus;
    pqcProtected?: boolean;
    merkleProofValid?: boolean;
    merkleBatchId?: string | null;
  };
  warnings?: Array<{
    code: 'ALG_DEPRECATED' | 'TOKEN_EXPIRING_SOON' | 'GEO_MISMATCH_SOFT';
    message: string;
    sunsetDate?: string;
  }>;
  scannedAt: string;
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

export default async function verifyRoutes(fastify: FastifyInstance): Promise<void> {
  const signingService = fastify.signingService;
  const hybridSigningService = new HybridSigningService(
    fastify.prisma,
    signingService,
    fastify.batchSigner,
  );
  const macService = new MacService(fastify.prisma);
  const geoService = new GeoService(fastify.prisma);
  const transparencyService = new TransparencyLogService(fastify.prisma);
  const fraudService = new FraudDetectionService(fastify.prisma, geoService, null as any);
  const domainService = new DomainService(fastify.prisma);

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
    // Clamp geo values to valid ranges
    if (query.clientLat !== undefined) {
      query.clientLat = Math.max(-90, Math.min(90, Number(query.clientLat) || 0));
    }
    if (query.clientLng !== undefined) {
      query.clientLng = Math.max(-180, Math.min(180, Number(query.clientLng) || 0));
    }

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
            domainVerified: true,
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
    // 3. Status & limit checks
    // ------------------------------------------------------------------
    // Helper: send a failure response as HTML (browser) or JSON (API).
    const acceptsJsonEarly =
      request.headers['x-client-id'] ||
      request.headers.accept?.includes('application/json');

    const sendFailure = (reason: string) => {
      const failResponse: VerificationResponse = {
        verified: false,
        reason,
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
      };
      if (acceptsJsonEarly) {
        return reply.send(failResponse);
      }
      return reply.type('text/html').send(
        renderSimpleFailurePage(reason, qrCode.organization.name, token, scannedAt),
      );
    };

    if (qrCode.status === 'REVOKED') {
      return sendFailure('This QR code has been revoked by its issuer.');
    }

    if (qrCode.status === 'EXPIRED' || (qrCode.expiresAt && qrCode.expiresAt < new Date())) {
      return sendFailure('This QR code has expired.');
    }

    // Scan limit checks
    const clientIpHashForLimits = hashString(request.ip);

    if (qrCode.maxScans !== null) {
      const totalScans = await fastify.prisma.scan.count({
        where: { qrCodeId: qrCode.id },
      });
      if (totalScans >= qrCode.maxScans) {
        return sendFailure('This QR code has reached its maximum number of scans.');
      }
    }

    if (qrCode.maxScansPerDevice !== null) {
      const deviceScans = await fastify.prisma.scan.count({
        where: { qrCodeId: qrCode.id, clientIpHash: clientIpHashForLimits },
      });
      if (deviceScans >= qrCode.maxScansPerDevice) {
        return sendFailure('This QR code has reached its scan limit for this device.');
      }
    }

    // ------------------------------------------------------------------
    // 4. Algorithm-version policy gate (ALGORITHM.md §11)
    // ------------------------------------------------------------------
    // Classify the row's algVersion against the policy in
    // packages/shared/src/alg-versions.ts. Three outcomes:
    //   - accepted   → silent, normal verification proceeds
    //   - deprecated → verification proceeds but a warn log fires so
    //                  operators can surface "tokens using deprecated
    //                  cryptography" as a compliance metric
    //   - rejected   → fail closed, the verifier refuses the row even if
    //                  the underlying signature is mathematically valid
    //   - unknown    → fail closed, schema violation
    const algVersionStatus = checkAlgVersion(qrCode.algVersion);
    if (algVersionStatus === 'rejected' || algVersionStatus === 'unknown') {
      fastify.log.warn(
        { token: qrCode.token, algVersion: qrCode.algVersion, algVersionStatus },
        'Verification refused: algVersion is rejected or unknown',
      );
      return sendFailure(
        algVersionStatus === 'rejected'
          ? 'This QR code uses a cryptographic algorithm that is no longer supported.'
          : 'This QR code uses an unrecognized cryptographic algorithm.',
      );
    }
    if (algVersionStatus === 'deprecated') {
      fastify.log.warn(
        { token: qrCode.token, algVersion: qrCode.algVersion },
        'Verification with deprecated algVersion — schedule re-issuance',
      );
    }

    // ------------------------------------------------------------------
    // 5. Cryptographic signature verification
    // ------------------------------------------------------------------
    //
    // Build the unified canonical core string once (AUDIT-FINDING-011/...)
    // and pass it through the three-leg decision tree. MAC and ECDSA verify
    // against the same bytes; the Merkle leg verifies its per-leaf hash
    // plus the batch root.
    //
    // Content-type-aware destHash: URL QRs commit to the URL; content QRs
    // (vCard, coupon, event, pdf, feedback) commit to the SHA3 of the
    // stable-stringified content body. Domain-separated via `computeDestHash`.
    let contentHashHex = '';
    if (qrCode.content && qrCode.contentType !== 'url') {
      contentHashHex = hashString(stableStringify(qrCode.content));
    }
    const destHash = await computeDestHash(
      qrCode.contentType ?? 'url',
      qrCode.destinationUrl,
      contentHashHex,
    );
    const geoHashVerify = await canonicalGeoHash(
      qrCode.latitude,
      qrCode.longitude,
      qrCode.radiusM,
    );
    const coreCanonical = canonicalizeCore({
      algVersion: qrCode.algVersion ?? ALG_VERSION_POLICY.hybrid,
      token: qrCode.token,
      tenantId: qrCode.organizationId,
      destHash,
      geoHash: geoHashVerify,
      expiresAt: qrCode.expiresAt?.toISOString() ?? '',
    });

    // Signature verification decision tree (AUDIT-FINDING-001).
    //
    // MAC is now a fast-reject pre-filter only. For hybrid rows the ECDSA
    // and Merkle/SLH-DSA legs both run on every request. The logic lives in
    // verify-signatures.ts so it can be unit-tested with spies on each dep.
    const outcome = await verifyRowSignatures(qrCode, coreCanonical, {
      verifyMac: (input) => macService.verifyCanonical(input),
      verifyEcdsa: (publicKey, sig, canonical) =>
        signingService.verifyCanonical(publicKey, sig, canonical),
      verifyHybridLeg: (input) => hybridSigningService.verifyHybridLeg(input),
    });

    if (outcome.macRejected) {
      fastify.log.warn(
        { token: qrCode.token },
        'verify: MAC pre-filter rejected — possible forgery',
      );
      return sendFailure('This QR code failed signature verification.');
    }

    const signatureValid = outcome.signatureValid;
    const merkleProofValid = outcome.merkleProofValid;
    const merkleBatchId = outcome.merkleBatchId;
    if (!signatureValid && outcome.pqcReason) {
      fastify.log.warn(
        { token: qrCode.token, pqcReason: outcome.pqcReason },
        'Signature verification failed',
      );
    }

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
          // AUDIT-FINDING-012: constant-time compare on hash-chain link.
          transparencyLogVerified =
            !!proof.entry.previousHash &&
            !!proof.previous.entryHash &&
            constantTimeEqualString(proof.entry.previousHash, proof.previous.entryHash);
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

    // Compute real-time trust score based on fraud history
    const trustScore = await fraudService.getQuickTrustScore(qrCode.id);

    // Check if destination domain looks like a known verified domain (phishing defense)
    const domainWarnings = await domainService.checkUrlAgainstVerifiedDomains(
      qrCode.destinationUrl,
      qrCode.organizationId,
    );

    // Lower trust score if domain is suspiciously similar to a verified one
    const domainPenalty = domainWarnings.isSuspicious ? 30 : 0;
    const finalTrustScore = Math.max(0, trustScore - domainPenalty);

    const staticParts = {
      verified: signatureValid && finalTrustScore > 20,
      ...(signatureValid && finalTrustScore <= 20 ? { reason: 'QR code has a critically low trust score due to detected fraud.' } : {}),
      ...(domainWarnings.isSuspicious ? {
        domain_warning: {
          message: `This URL looks similar to "${domainWarnings.warnings[0]?.domain}" which belongs to verified organization "${domainWarnings.warnings[0]?.verifiedOrgName}". Proceed with caution.`,
          similar_to: domainWarnings.warnings[0]?.domain,
          verified_org: domainWarnings.warnings[0]?.verifiedOrgName,
          similarity: domainWarnings.warnings[0]?.similarity,
        },
      } : {}),
      organization: {
        ...qrCode.organization,
        domainVerified: qrCode.organization.domainVerified,
      },
      destination_url: qrCode.destinationUrl,
      security: {
        signatureValid,
        proxyDetected: false,
        trustScore: finalTrustScore,
        transparencyLogVerified,
        algVersion: qrCode.algVersion,
        algVersionStatus,
        // True when the token is protected by any post-quantum signing
        // leg. After the canonical-form unification dropped the legacy
        // ECDSA-only alg version, every accepted alg version carries a
        // PQC leg — this flag is effectively always true for valid rows
        // and stays in the response shape for SDK compatibility.
        pqcProtected: qrCode.algVersion !== null,
        merkleProofValid,
        merkleBatchId,
      },
      // Non-fatal advisories. Populated when the verifier detects a
      // condition operators should plan a response to. Currently fires
      // only on deprecated alg versions; future: geo-soft-mismatch,
      // token-expiring-soon, etc.
      warnings:
        algVersionStatus === 'deprecated'
          ? [
              {
                code: 'ALG_DEPRECATED' as const,
                message:
                  `Token signed with ${qrCode.algVersion}, scheduled for removal. ` +
                  'Re-issue to upgrade to the current signing algorithm.',
                sunsetDate: process.env.ECDSA_SUNSET_DATE ?? 'TBD',
              },
            ]
          : [],
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
    const clientIpHash = clientIpHashForLimits;

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

    // Track verification usage
    const usageService = new UsageService(fastify.prisma);
    usageService.increment(qrCode.organizationId, 'verifications').catch(() => {});

    // ------------------------------------------------------------------
    // 9. Content negotiation: HTML for browsers, JSON for API clients
    // ------------------------------------------------------------------
    const acceptsJson =
      request.headers['x-client-id'] ||
      request.headers.accept?.includes('application/json');

    if (!acceptsJson) {
      // Collect ephemeral proof data — personalized, impossible for a clone to reproduce
      const meta = await collectRequestMetadata(request);
      const proofTimestamp = new Date().toISOString();
      // Audit-3 C-2: no hardcoded fallback. Dev/test shows a placeholder.
      const proofSecret = config.visualProof.secret;
      const proofHmac = proofSecret
        ? hashString(`${proofSecret}:${token}:${proofTimestamp}:${request.ip}`)
        : null;
      const ephemeralProof = {
        city: meta.ipCity || meta.ipCountry || 'Unknown location',
        device: `${meta.browser || 'Unknown browser'} on ${meta.os || 'Unknown OS'}`,
        timestamp: proofTimestamp,
        fingerprint: proofHmac ? proofHmac.slice(0, 12) : 'dev-mode',
      };
      const contentType = (qrCode.contentType as string) || 'url';
      const renderer = await getRenderer(contentType);

      if (renderer) {
        const renderCtx: RenderContext = {
          qrCode: {
            token,
            contentType,
            content: qrCode.content,
            label: qrCode.label,
            destinationUrl: qrCode.destinationUrl,
            latitude: qrCode.latitude,
            longitude: qrCode.longitude,
            createdAt: qrCode.createdAt,
          },
          organization: qrCode.organization as RenderContext['organization'],
          verified: response.verified,
          reason: (response as any).reason,
          security: response.security,
          locationMatch: response.location_match,
          ephemeralProof,
          domainWarning: (response as any).domain_warning,
          scannedAt: response.scannedAt,
          assetBaseUrl: `${process.env.WEBAUTHN_ORIGIN || 'http://localhost:3000'}/assets`,
        };
        const contentBody = renderer(renderCtx);
        return reply.type('text/html').send(renderShell(renderCtx, contentBody, proofHmac ?? undefined));
      }

      // Fallback to legacy renderer for unknown types
      return reply.type('text/html').send(renderVerificationPage(response, token, qrCode, ephemeralProof));
    }

    return reply.send(response);
  });

  // -------------------------------------------------------------------------
  // POST /:token/webauthn/options — Generate authentication options for scan
  // -------------------------------------------------------------------------

  fastify.post('/:token/webauthn/options', {
    config: { rateLimit: rateLimitPublic },
  }, async (request, reply) => {
    const { token } = request.params as { token: string };

    const qrCode = await fastify.prisma.qRCode.findUnique({
      where: { token },
      select: { id: true, status: true },
    });

    if (!qrCode || qrCode.status !== 'ACTIVE') {
      return reply.status(404).send({
        statusCode: 404,
        error: 'Not Found',
        message: 'QR code not found.',
      });
    }

    // Generate discoverable credential options (no specific user)
    const { WebAuthnService } = await import('../services/webauthn.js');
    const webauthnService = new WebAuthnService(fastify.prisma);

    try {
      const { options, challengeKey } = await webauthnService.generateAuthenticationOpts();
      return reply.send({ options, challengeKey });
    } catch (err: any) {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: err.message,
      });
    }
  });

  // -------------------------------------------------------------------------
  // POST /:token/webauthn/verify — Verify passkey on scan for trust boost
  // -------------------------------------------------------------------------

  fastify.post('/:token/webauthn/verify', {
    config: { rateLimit: rateLimitPublic },
  }, async (request, reply) => {
    const { token } = request.params as { token: string };
    const body = request.body as { credential: any; challengeKey: string; scanId?: string };

    const qrCode = await fastify.prisma.qRCode.findUnique({
      where: { token },
      select: { id: true, status: true },
    });

    if (!qrCode || qrCode.status !== 'ACTIVE') {
      return reply.status(404).send({
        statusCode: 404,
        error: 'Not Found',
        message: 'QR code not found.',
      });
    }

    const { WebAuthnService } = await import('../services/webauthn.js');
    const webauthnService = new WebAuthnService(fastify.prisma);

    try {
      const { user, passkeyId } = await webauthnService.verifyAuthentication(
        body.credential,
        body.challengeKey,
      );

      // Update the scan record if provided
      if (body.scanId) {
        await fastify.prisma.scan.updateMany({
          where: { id: body.scanId, qrCodeId: qrCode.id },
          data: { passkeyVerified: true },
        });
      }

      return reply.send({
        verified: true,
        passkeyVerified: true,
        user: { id: user.id, name: user.name },
      });
    } catch (err: any) {
      return reply.status(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        message: err.message,
      });
    }
  });

  // -------------------------------------------------------------------------
  // POST /v/:token/feedback — Submit feedback rating (public, rate-limited)
  // -------------------------------------------------------------------------

  fastify.post('/:token/feedback', {
    config: { rateLimit: rateLimitPublic },
  }, async (request, reply) => {
    const { token } = request.params as { token: string };
    const body = request.body as { rating?: number; comment?: string; name?: string; email?: string; phone?: string };

    if (!body.rating || body.rating < 1 || body.rating > 5) {
      return reply.status(400).send({ statusCode: 400, error: 'Bad Request', message: 'Rating must be 1-5' });
    }

    const qrCode = await fastify.prisma.qRCode.findUnique({
      where: { token },
      select: { id: true, contentType: true },
    });

    if (!qrCode || qrCode.contentType !== 'feedback') {
      return reply.status(404).send({ statusCode: 404, error: 'Not Found', message: 'Feedback QR code not found' });
    }

    const ipHash = hashString(request.ip || 'unknown');

    await fastify.prisma.feedbackSubmission.create({
      data: {
        qrCodeId: qrCode.id,
        rating: body.rating,
        comment: body.comment?.slice(0, 1000) || null,
        name: body.name?.slice(0, 200) || null,
        email: body.email?.slice(0, 200) || null,
        phone: body.phone?.slice(0, 50) || null,
        ipHash,
        userAgent: request.headers['user-agent'] || null,
      },
    });

    return reply.send({ success: true });
  });
}

// ---------------------------------------------------------------------------
// HTML renderer for browser-based QR scans
// ---------------------------------------------------------------------------

function renderVerificationPage(
  result: VerificationResponse & { domain_warning?: { message: string; similar_to: string; verified_org: string } },
  token: string,
  qrCode: { label?: string | null; destinationUrl: string; createdAt: Date },
  ephemeralProof?: { city: string; device: string; timestamp: string; fingerprint: string },
): string {
  const verified = result.verified;
  const org = result.organization;
  const sec = result.security;
  const loc = result.location_match;
  const domainWarn = result.domain_warning;

  const trustColor = sec.trustScore >= 80 ? '#00A76F' : sec.trustScore >= 50 ? '#FFAB00' : '#FF5630';
  const trustLabel = sec.trustScore >= 80 ? 'High Trust' : sec.trustScore >= 50 ? 'Medium Trust' : 'Low Trust';

  const kycBadge = org.kycStatus === 'VERIFIED'
    ? '<span class="badge badge-green">KYC Verified</span>'
    : org.kycStatus === 'UNDER_REVIEW'
      ? '<span class="badge badge-yellow">KYC Pending</span>'
      : '<span class="badge badge-gray">Unverified</span>';

  const domainBadge = org.domainVerified
    ? '<span class="badge badge-green">Domain Verified</span>'
    : '<span class="badge badge-gray">Domain Unverified</span>';

  const trustLevelBadge = org.trustLevel === 'GOVERNMENT'
    ? '<span class="badge badge-blue">Government</span>'
    : org.trustLevel === 'BUSINESS'
      ? '<span class="badge badge-blue">Business</span>'
      : '<span class="badge badge-gray">Individual</span>';

  let destinationHostname: string;
  try {
    destinationHostname = new URL(qrCode.destinationUrl).hostname;
  } catch {
    destinationHostname = qrCode.destinationUrl;
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>QRAuth Verification — ${esc(token)}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: ${verified ? '#f0fdf4' : '#fef2f2'};
      min-height: 100vh;
      padding: 20px;
    }
    .container { max-width: 480px; margin: 0 auto; }
    .card {
      background: white;
      border-radius: 16px;
      box-shadow: 0 4px 24px rgba(0,0,0,0.06);
      overflow: hidden;
    }
    .header {
      padding: 32px 24px 24px;
      text-align: center;
      background: ${verified ? '#00A76F' : '#FF5630'};
      color: white;
    }
    .header svg { width: 64px; height: 64px; margin-bottom: 16px; }
    .header h1 { font-size: 22px; font-weight: 700; margin-bottom: 4px; }
    .header p { font-size: 14px; opacity: 0.9; }
    .body { padding: 24px; }
    .section { margin-bottom: 20px; }
    .section-title {
      font-size: 11px; font-weight: 700; text-transform: uppercase;
      letter-spacing: 0.5px; color: #919eab; margin-bottom: 8px;
    }
    .org-name { font-size: 18px; font-weight: 700; color: #212b36; }
    .badges { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 8px; }
    .badge {
      display: inline-block; padding: 3px 10px; border-radius: 12px;
      font-size: 11px; font-weight: 600;
    }
    .badge-green { background: #E8F5E9; color: #1B5E20; }
    .badge-yellow { background: #FFF8E1; color: #F57F17; }
    .badge-blue { background: #E3F2FD; color: #0D47A1; }
    .badge-gray { background: #F5F5F5; color: #616161; }
    .badge-red { background: #FFEBEE; color: #C62828; }
    .dest-url {
      display: block; padding: 12px 16px; background: #f8f9fa;
      border-radius: 8px; color: #0D47A1; text-decoration: none;
      font-size: 14px; word-break: break-all; transition: background 0.2s;
    }
    .dest-url:hover { background: #e3f2fd; }
    .trust-meter { margin-top: 12px; }
    .trust-bar {
      height: 8px; border-radius: 4px; background: #f0f0f0;
      overflow: hidden; margin-bottom: 6px;
    }
    .trust-fill {
      height: 100%; border-radius: 4px; transition: width 0.5s ease;
      background: ${trustColor};
    }
    .trust-label { display: flex; justify-content: space-between; font-size: 13px; }
    .trust-score { font-weight: 700; color: ${trustColor}; }
    .check-row {
      display: flex; align-items: center; gap: 10px;
      padding: 8px 0; font-size: 14px; color: #212b36;
    }
    .check-icon { font-size: 18px; }
    .check-pass { color: #00A76F; }
    .check-fail { color: #FF5630; }
    .check-warn { color: #FFAB00; }
    .location-info {
      padding: 12px 16px; background: ${loc.matched ? '#E8F5E9' : '#FFF8E1'};
      border-radius: 8px; font-size: 13px; margin-top: 8px;
    }
    .divider { height: 1px; background: #f0f0f0; margin: 16px 0; }
    .footer {
      text-align: center; padding: 16px 24px 24px;
      font-size: 11px; color: #919eab;
    }
    .footer a { color: #637381; text-decoration: none; }
    .cta-btn {
      display: block; width: 100%; padding: 14px; margin-top: 16px;
      background: ${verified ? '#00A76F' : '#637381'}; color: white;
      border: none; border-radius: 10px; font-size: 16px; font-weight: 600;
      cursor: pointer; text-align: center; text-decoration: none;
      transition: opacity 0.2s;
    }
    .cta-btn:hover { opacity: 0.9; }
    .warn-banner {
      padding: 12px 16px; background: #FFF3E0; border-radius: 8px;
      font-size: 13px; color: #E65100; margin-bottom: 16px;
      display: flex; align-items: center; gap: 8px;
    }
    .time { font-family: monospace; font-size: 12px; color: #919eab; text-align: center; margin-top: 12px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <div class="header">
        <svg viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg">
          <path d="M48 24 H152 Q166 24 166 38 V108 Q166 156 100 182 Q34 156 34 108 V38 Q34 24 48 24 Z" fill="none" stroke="rgba(255,255,255,0.3)" stroke-width="5"/>
          <g fill="rgba(255,255,255,0.1)">
            <rect x="52" y="40" width="18" height="18" rx="3"/><rect x="78" y="40" width="18" height="18" rx="3"/>
            <rect x="130" y="40" width="18" height="18" rx="3"/><rect x="52" y="66" width="18" height="18" rx="3"/>
            <rect x="104" y="66" width="18" height="18" rx="3"/><rect x="78" y="92" width="18" height="18" rx="3"/>
            <rect x="130" y="92" width="18" height="18" rx="3"/><rect x="52" y="118" width="18" height="18" rx="3"/>
            <rect x="104" y="118" width="18" height="18" rx="3"/>
          </g>
          ${verified
            ? '<path d="M62 104 L88 134 L144 64" fill="none" stroke="#fff" stroke-width="15" stroke-linecap="round" stroke-linejoin="round"/>'
            : '<path d="M70 80 L130 140 M130 80 L70 140" fill="none" stroke="#fff" stroke-width="15" stroke-linecap="round" stroke-linejoin="round"/>'
          }
        </svg>
        <h1>${verified ? 'Verified QR Code' : 'Verification Failed'}</h1>
        <p>${verified
          ? 'This QR code is authentic and registered on the QRAuth platform.'
          : (result.reason || 'This QR code could not be verified.')
        }</p>
      </div>

      <div class="body">
        ${!verified && result.reason ? `<div class="warn-banner">&#9888; ${esc(result.reason)}</div>` : ''}
        ${domainWarn ? `
        <div class="warn-banner" style="background:#FFEBEE;color:#C62828;border-left:4px solid #C62828;">
          <strong>&#9888; Phishing Warning:</strong> This URL looks similar to <strong>${esc(domainWarn.similar_to)}</strong> which belongs to the verified organization <strong>${esc(domainWarn.verified_org)}</strong>. Double-check the URL before proceeding.
        </div>
        ` : ''}

        <div class="section">
          <div class="section-title">Registered By</div>
          <div class="org-name">${esc(org.name)}</div>
          <div class="badges">
            ${trustLevelBadge}
            ${kycBadge}
            ${domainBadge}
          </div>
        </div>

        ${qrCode.label ? `
        <div class="section">
          <div class="section-title">Label</div>
          <div style="font-size:14px;color:#212b36;">${esc(qrCode.label)}</div>
        </div>
        ` : ''}

        <div class="section">
          <div class="section-title">Destination</div>
          <a class="dest-url" href="${esc(qrCode.destinationUrl)}" rel="noopener">${esc(qrCode.destinationUrl)}</a>
        </div>

        <div class="divider"></div>

        <div class="section">
          <div class="section-title">Security Checks</div>
          <div class="check-row">
            <span class="check-icon ${sec.signatureValid ? 'check-pass' : 'check-fail'}">
              ${sec.signatureValid ? '&#10003;' : '&#10007;'}
            </span>
            Digital Signature (ECDSA-P256)
          </div>
          <div class="check-row">
            <span class="check-icon ${sec.transparencyLogVerified ? 'check-pass' : 'check-fail'}">
              ${sec.transparencyLogVerified ? '&#10003;' : '&#10007;'}
            </span>
            Transparency Log
          </div>
          <div class="check-row">
            <span class="check-icon ${sec.proxyDetected ? 'check-fail' : 'check-pass'}">
              ${sec.proxyDetected ? '&#10007;' : '&#10003;'}
            </span>
            Proxy Detection ${sec.proxyDetected ? '— <strong style="color:#FF5630">PROXY DETECTED</strong>' : '— Clean'}
          </div>

          <div class="trust-meter">
            <div class="trust-bar">
              <div class="trust-fill" style="width:${sec.trustScore}%"></div>
            </div>
            <div class="trust-label">
              <span>${trustLabel}</span>
              <span class="trust-score">${sec.trustScore}/100</span>
            </div>
          </div>
        </div>

        ${loc.distanceM !== null ? `
        <div class="section">
          <div class="section-title">Location</div>
          <div class="location-info">
            ${loc.matched
              ? `&#128205; You are within the registered area (${loc.distanceM}m away)`
              : `&#128205; You are ${loc.distanceM}m from the registered location`
            }
          </div>
        </div>
        ` : ''}

        ${ephemeralProof ? `
        <div class="section">
          <div class="section-title">Ephemeral Proof — personalized to you right now</div>
          <div style="background:#f8f9fa;border-radius:8px;padding:12px 16px;font-size:13px;">
            <div style="display:flex;justify-content:space-between;margin-bottom:6px;">
              <span style="color:#919eab;">Your location</span>
              <strong>${esc(ephemeralProof.city)}</strong>
            </div>
            <div style="display:flex;justify-content:space-between;margin-bottom:6px;">
              <span style="color:#919eab;">Your device</span>
              <strong>${esc(ephemeralProof.device)}</strong>
            </div>
            <div style="display:flex;justify-content:space-between;margin-bottom:6px;">
              <span style="color:#919eab;">Timestamp</span>
              <strong>${esc(new Date(ephemeralProof.timestamp).toLocaleTimeString('en-US', { hour12: false }))}</strong>
            </div>
            <div style="display:flex;justify-content:space-between;">
              <span style="color:#919eab;">Proof ID</span>
              <span style="font-family:monospace;font-weight:700;color:#00A76F;">${esc(ephemeralProof.fingerprint)}</span>
            </div>
          </div>
          <div style="font-size:11px;color:#919eab;margin-top:6px;">
            If this info doesn't match your device and location, this page may be cloned.
          </div>
        </div>
        ` : ''}

        ${verified ? `
        <a class="cta-btn" href="${esc(qrCode.destinationUrl)}" rel="noopener">
          Continue to ${esc(destinationHostname)}
        </a>
        ` : `
        <div class="cta-btn" style="background:#637381;cursor:default;">
          Do not proceed — this QR code is not verified
        </div>
        `}

        <div class="time">Scanned at ${result.scannedAt}</div>

        <div id="origin-warning" style="display:none;margin-top:12px;padding:12px 16px;background:#FFEBEE;border-radius:8px;border-left:4px solid #C62828;color:#C62828;font-size:13px;">
          <strong>&#9888; WARNING:</strong> This verification page is not being served from the official QRAuth domain. This may be a cloned phishing page. Do NOT enter any information.
        </div>
      </div>

      <div class="footer">
        Secured by <a href="https://qrauth.io"><strong>QRAuth</strong></a> — Identity Verification Platform<br>
        <span style="font-size:10px;margin-top:4px;display:inline-block;">Token: ${esc(token)}</span>
      </div>
    </div>

    <script>
      // Origin integrity check — detect if this page is being served from a clone
      (function() {
        var allowedHosts = ['qrauth.io', 'localhost'];
        var currentHost = window.location.hostname;
        var isLegit = allowedHosts.some(function(h) { return currentHost === h || currentHost.endsWith('.' + h); });
        if (!isLegit) {
          document.getElementById('origin-warning').style.display = 'block';
          // Also try to disable the CTA button
          var cta = document.querySelector('.cta-btn');
          if (cta) { cta.style.pointerEvents = 'none'; cta.style.opacity = '0.3'; }
        }
      })();
    </script>
  </div>
</body>
</html>`;
}

function esc(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ---------------------------------------------------------------------------
// Simple failure page for status/limit failures (revoked, expired, scan limit)
// ---------------------------------------------------------------------------

function renderSimpleFailurePage(
  reason: string,
  orgName: string,
  token: string,
  scannedAt: string,
): string {
  // Pick icon and color based on the failure type
  const isExpired = reason.toLowerCase().includes('expired');
  const isRevoked = reason.toLowerCase().includes('revoked');
  const isScanLimit = reason.toLowerCase().includes('scan limit') || reason.toLowerCase().includes('maximum number');

  let icon: string;
  let accentColor: string;
  let title: string;

  if (isExpired) {
    icon = '<svg viewBox="0 0 24 24" width="64" height="64" fill="none" stroke="#fff" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>';
    accentColor = '#FF8C00';
    title = 'QR Code Expired';
  } else if (isRevoked) {
    icon = '<svg viewBox="0 0 24 24" width="64" height="64" fill="none" stroke="#fff" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>';
    accentColor = '#DC2626';
    title = 'QR Code Revoked';
  } else if (isScanLimit) {
    icon = '<svg viewBox="0 0 24 24" width="64" height="64" fill="none" stroke="#fff" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>';
    accentColor = '#7C3AED';
    title = 'Scan Limit Reached';
  } else {
    icon = '<svg viewBox="0 0 24 24" width="64" height="64" fill="none" stroke="#fff" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><circle cx="12" cy="16" r="0.5" fill="#fff"/></svg>';
    accentColor = '#637381';
    title = 'Verification Failed';
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>QRAuth — ${esc(title)}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #f8f9fa;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .card {
      max-width: 420px;
      width: 100%;
      background: white;
      border-radius: 20px;
      box-shadow: 0 8px 32px rgba(0,0,0,0.08);
      overflow: hidden;
      text-align: center;
    }
    .header {
      padding: 40px 24px 32px;
      background: ${accentColor};
      color: white;
    }
    .header svg { margin-bottom: 20px; opacity: 0.95; }
    .header h1 { font-size: 24px; font-weight: 700; margin-bottom: 8px; }
    .header p { font-size: 15px; opacity: 0.9; line-height: 1.5; max-width: 320px; margin: 0 auto; }
    .body { padding: 32px 24px; }
    .org {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 10px 20px;
      background: #f0f0f0;
      border-radius: 24px;
      font-size: 14px;
      font-weight: 600;
      color: #333;
      margin-bottom: 20px;
    }
    .org svg { flex-shrink: 0; }
    .help {
      font-size: 13px;
      color: #919eab;
      line-height: 1.6;
      margin-bottom: 24px;
    }
    .help strong { color: #637381; }
    .footer {
      padding: 16px 24px 24px;
      font-size: 11px;
      color: #c4cdd5;
      border-top: 1px solid #f0f0f0;
    }
    .footer a { color: #919eab; text-decoration: none; font-weight: 600; }
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      ${icon}
      <h1>${esc(title)}</h1>
      <p>${esc(reason)}</p>
    </div>
    <div class="body">
      <div class="org">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#637381" stroke-width="2"><path d="M12 2L3 7v6c0 5.5 3.8 10.7 9 12 5.2-1.3 9-6.5 9-12V7l-9-5z"/></svg>
        Issued by ${esc(orgName)}
      </div>
      <div class="help">
        ${isExpired ? 'This QR code has passed its expiration date and is no longer active. Please contact <strong>the issuer</strong> if you believe this is an error.' : ''}
        ${isRevoked ? 'This QR code has been revoked by its issuer and is no longer valid.' : ''}
        ${isScanLimit ? 'This QR code has been scanned the maximum number of times allowed and is no longer accepting new scans.' : ''}
      </div>
    </div>
    <div class="footer">
      Secured by <a href="https://qrauth.io">QRAuth</a> &mdash; Token: ${esc(token)}<br>
      ${esc(scannedAt)}
    </div>
  </div>
</body>
</html>`;
}
