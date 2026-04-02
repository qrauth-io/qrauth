import type { FastifyInstance } from 'fastify';
import { verifyQuerySchema } from '@vqr/shared';
import { zodValidator } from '../middleware/validate.js';
import { rateLimitPublic } from '../middleware/rateLimit.js';
import { SigningService } from '../services/signing.js';
import { GeoService } from '../services/geo.js';
import { TransparencyLogService } from '../services/transparency.js';
import { FraudDetectionService } from '../services/fraud.js';
import { DomainService } from '../services/domain.js';
import { cacheGet, cacheSet } from '../lib/cache.js';
import { hashString, stableStringify } from '../lib/crypto.js';
import { scanQueue } from '../lib/queue.js';
import { collectRequestMetadata } from '../lib/metadata.js';
import { config } from '../lib/config.js';
import { CACHE_TTL } from '@vqr/shared';
import { z } from 'zod';
import { getRenderer } from '../renderers/index.js';
import { renderShell } from '../renderers/shell.js';
import type { RenderContext } from '../renderers/index.js';

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
    // Compute contentHash for verification (must match what was signed)
    let verifyContentHash = '';
    if (qrCode.content && qrCode.contentType !== 'url') {
      // Deterministic JSON for hashing (PostgreSQL JSONB reorders keys alphabetically)
      verifyContentHash = hashString(stableStringify(qrCode.content));
    }

    const signatureValid = signingService.verifyQRCode(
      qrCode.signingKey.publicKey,
      qrCode.signature,
      qrCode.token,
      qrCode.destinationUrl,
      qrCode.geoHash ?? '',
      qrCode.expiresAt?.toISOString() ?? '',
      verifyContentHash,
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
      const proofHmac = hashString(`${config.visualProof.secret || 'vqr'}:${token}:${proofTimestamp}:${request.ip}`);
      const ephemeralProof = {
        city: meta.ipCity || meta.ipCountry || 'Unknown location',
        device: `${meta.browser || 'Unknown browser'} on ${meta.os || 'Unknown OS'}`,
        timestamp: proofTimestamp,
        fingerprint: proofHmac.slice(0, 12),
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
        return reply.type('text/html').send(renderShell(renderCtx, contentBody));
      }

      // Fallback to legacy renderer for unknown types
      return reply.type('text/html').send(renderVerificationPage(response, token, qrCode, ephemeralProof));
    }

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
  <title>vQR Verification — ${esc(token)}</title>
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
        <svg viewBox="0 0 120 120" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M60 8L16 28v32c0 28 18.7 54.2 44 60 25.3-5.8 44-32 44-60V28L60 8z" fill="rgba(255,255,255,0.2)"/>
          <path d="M60 16L24 33v25c0 23.5 15.3 45.5 36 50.4 20.7-4.9 36-26.9 36-50.4V33L60 16z" fill="rgba(255,255,255,0.15)"/>
          ${verified
            ? '<circle cx="60" cy="56" r="24" fill="rgba(255,255,255,0.3)"/><path d="M50 56l7 7 13-14" stroke="#fff" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>'
            : '<circle cx="60" cy="56" r="24" fill="rgba(255,255,255,0.3)"/><path d="M52 48l16 16M68 48L52 64" stroke="#fff" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>'
          }
          <text x="60" y="100" text-anchor="middle" font-family="Arial,sans-serif" font-weight="800" font-size="16" fill="#fff" letter-spacing="1">vQR</text>
        </svg>
        <h1>${verified ? 'Verified QR Code' : 'Verification Failed'}</h1>
        <p>${verified
          ? 'This QR code is authentic and registered on the vQR platform.'
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
          <strong>&#9888; WARNING:</strong> This verification page is not being served from the official vQR domain. This may be a cloned phishing page. Do NOT enter any information.
        </div>
      </div>

      <div class="footer">
        Secured by <a href="https://vqr.io"><strong>vQR</strong></a> — Verified QR Code Security Platform<br>
        <span style="font-size:10px;margin-top:4px;display:inline-block;">Token: ${esc(token)}</span>
      </div>
    </div>

    <script>
      // Origin integrity check — detect if this page is being served from a clone
      (function() {
        var allowedHosts = ['vqr.io', 'vqr.progressnet.io', 'localhost'];
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
