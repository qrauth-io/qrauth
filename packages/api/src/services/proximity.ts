import { createVerify, createHash } from 'node:crypto';
import type { PrismaClient } from '@prisma/client';
import { GeoService } from './geo.js';
import type { SigningService } from './signing.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Default attestation TTL: 5 minutes. */
const ATTESTATION_TTL_SECONDS = 300;

/** Maximum allowed clock skew for iat validation (seconds). */
const MAX_CLOCK_SKEW_SECONDS = 30;

/**
 * `alg_version` embedded in the attestation payload (AUDIT-FINDING-025).
 * The JWT header also carries `alg: 'ES256'` — the claim-level version is
 * a secondary lock so a future migration to ML-DSA-based attestations can
 * be signalled without re-using the `alg` header slot.
 */
export const PROXIMITY_ATTESTATION_ALG_VERSION = 'proximity-es256-v1' as const;

/**
 * AUDIT-2 N-2: domain-separation prefix on the ECDSA signing path.
 * The signer prepends this constant to every message before feeding it
 * to SHA-256 + ECDSA, so the verify path on this side has to reconstruct
 * it to get the same signed bytes. Byte-identical to the constants in
 * `services/signing.ts`, `services/ecdsa-signer/local.ts`, and
 * `packages/signer-service/src/server.ts`. Pinned in `ALGORITHM.md §12`.
 *
 * Note: proximity JWTs used to be standards-compliant ES256 JWTs over
 * `header.payload`. After N-2 the signed bytes are
 * `qrauth:ecdsa-canonical:v1:header.payload`, so third-party verifiers
 * need the QRAuth SDK (or the same-shaped reconstruction) to validate.
 */
const ECDSA_CANONICAL_DOMAIN_PREFIX = 'qrauth:ecdsa-canonical:v1:';

/**
 * Opaque error string returned to external verifiers (AUDIT-FINDING-026).
 * Internal callers still get detail via server-side logs; the HTTP
 * response collapses every post-structural-parse failure to a single
 * string so fuzzers cannot distinguish between "wrong key", "expired",
 * "forged signature", etc.
 */
export const OPAQUE_INVALID_ATTESTATION = 'INVALID_ATTESTATION' as const;

// ---------------------------------------------------------------------------
// Helpers — compact ES256 JWT
// ---------------------------------------------------------------------------

function base64url(data: string | Buffer): string {
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
  return buf.toString('base64url');
}

function base64urlDecode(str: string): string {
  return Buffer.from(str, 'base64url').toString('utf8');
}

function sha3_256hex(input: string): string {
  return createHash('sha3-256').update(input, 'utf8').digest('hex');
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export interface CreateAttestationInput {
  token: string;
  clientLat: number;
  clientLng: number;
  /** Relying-party identifier — lands in the `aud` claim. */
  rpId: string;
  /** Client-reported device identity — hashed into the `device` claim. */
  deviceFingerprint: string;
}

export class ProximityService {
  private geoService: GeoService;

  constructor(
    private prisma: PrismaClient,
    /**
     * AUDIT-FINDING-016: all ECDSA signing now routes through the
     * `SigningService.signCanonical` path, which delegates to the
     * `EcdsaSigner` backend. The API server no longer reads PEM files
     * for proximity attestation signing.
     */
    private signingService: SigningService,
  ) {
    this.geoService = new GeoService(prisma);
  }

  /**
   * Generate a signed ProximityAttestation JWT (AUDIT-FINDING-005/006/025).
   *
   * The JWT header carries `kid` so third-party verifiers can look up the
   * correct public key during signing-key rotation without needing to
   * guess which key was active at issuance. Claims include `aud` (bound
   * relying-party), `device` (SHA3-256 of the caller-supplied fingerprint),
   * and `alg_version` (claim-level algorithm tag for agility).
   */
  async createAttestation(input: CreateAttestationInput) {
    // 1. Look up the QR code
    const qrCode = await this.prisma.qRCode.findUnique({
      where: { token: input.token },
      select: {
        id: true,
        token: true,
        latitude: true,
        longitude: true,
        radiusM: true,
        geoHash: true,
        status: true,
        organizationId: true,
      },
    });

    if (!qrCode) {
      throw Object.assign(new Error('QR code not found'), { statusCode: 404 });
    }

    if (qrCode.status !== 'ACTIVE') {
      throw Object.assign(new Error('QR code is not active'), { statusCode: 410 });
    }

    if (qrCode.latitude == null || qrCode.longitude == null) {
      throw Object.assign(
        new Error('QR code has no registered location — proximity attestation requires a geo-enabled QR code'),
        { statusCode: 400 },
      );
    }

    // 2. Get the org's active signing key
    const signingKey = await this.prisma.signingKey.findFirst({
      where: { organizationId: qrCode.organizationId, status: 'ACTIVE' },
      orderBy: { createdAt: 'desc' },
      select: { id: true, keyId: true, publicKey: true },
    });

    if (!signingKey) {
      throw Object.assign(new Error('No active signing key for this organization'), { statusCode: 500 });
    }

    // 3. Compute proximity
    const proximity = this.geoService.checkProximity(
      qrCode.latitude,
      qrCode.longitude,
      qrCode.radiusM,
      input.clientLat,
      input.clientLng,
    );

    // 4. Build header (per-signing) and claims
    // AUDIT-FINDING-006: location is client-reported; hardware attestation
    // is a separate work stream.
    const header = { alg: 'ES256', typ: 'JWT', kid: signingKey.keyId };
    const headerB64 = base64url(JSON.stringify(header));

    const now = Math.floor(Date.now() / 1000);
    const claims = {
      sub: sha3_256hex(`qrauth:proximity-sub:v1:${qrCode.token}`),
      iss: qrCode.organizationId,
      aud: input.rpId,
      device: sha3_256hex(`qrauth:proximity-device:v1:${input.deviceFingerprint}`),
      alg_version: PROXIMITY_ATTESTATION_ALG_VERSION,
      loc: qrCode.geoHash || this.geoService.encodeGeoHash(qrCode.latitude, qrCode.longitude),
      proximity: {
        matched: proximity.matched,
        distanceM: Math.round(proximity.distanceM),
        radiusM: qrCode.radiusM,
      },
      iat: now,
      exp: now + ATTESTATION_TTL_SECONDS,
    };

    // 5. Sign the JWT via the EcdsaSigner backend (AUDIT-FINDING-016).
    const payloadB64 = base64url(JSON.stringify(claims));
    const signingInput = `${headerB64}.${payloadB64}`;

    let signatureB64Der: string;
    try {
      signatureB64Der = await this.signingService.signCanonical(signingKey.keyId, signingInput);
    } catch (err) {
      throw Object.assign(new Error('Signing key not available'), {
        statusCode: 500,
        cause: err instanceof Error ? err.message : String(err),
      });
    }

    // The signer returns a base64 DER signature; the JWT wants
    // base64url. Rewrap the alphabet without re-decoding.
    const signatureB64Url = signatureB64Der
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');

    const jwt = `${signingInput}.${signatureB64Url}`;

    return {
      jwt,
      claims,
      publicKey: signingKey.publicKey,
      keyId: signingKey.keyId,
    };
  }

  /**
   * Verify a ProximityAttestation JWT (AUDIT-FINDING-005/026).
   *
   * External callers get a collapsed `INVALID_ATTESTATION` error string on
   * any post-structural-parse failure so fuzzing captured attestations
   * yields no signal beyond "works / doesn't work". Internal operators
   * still get detail via the `debug` field in the returned object, which
   * the route handler filters out before responding.
   *
   * Public key resolution is by `(iss, kid)` with the `kid` coming from
   * the JWT header. Keys in `ACTIVE` or `ROTATED` status verify; others
   * (including `RETIRED`) do not.
   */
  async verifyAttestation(
    jwt: string,
    publicKeyPem?: string,
  ): Promise<{
    valid: boolean;
    claims?: Record<string, unknown>;
    error?: string;
    /** Server-side detail — never leaked to external callers. */
    debug?: string;
  }> {
    // 1. Structural parse. Malformed JWTs return an opaque error but we
    //    keep the debug message internal.
    const parts = jwt.split('.');
    if (parts.length !== 3) {
      return { valid: false, error: OPAQUE_INVALID_ATTESTATION, debug: 'Malformed JWT: expected 3 parts' };
    }

    const [headerB64, payloadB64, signatureB64] = parts;

    // 2. Decode and validate header
    let header: Record<string, unknown>;
    try {
      header = JSON.parse(base64urlDecode(headerB64));
    } catch {
      return { valid: false, error: OPAQUE_INVALID_ATTESTATION, debug: 'Invalid JWT header' };
    }
    if (header.alg !== 'ES256') {
      return {
        valid: false,
        error: OPAQUE_INVALID_ATTESTATION,
        debug: `Unsupported algorithm: ${header.alg}`,
      };
    }
    if (header.typ !== 'JWT') {
      return {
        valid: false,
        error: OPAQUE_INVALID_ATTESTATION,
        debug: `Unsupported typ: ${header.typ}`,
      };
    }
    const kid = typeof header.kid === 'string' ? header.kid : null;

    // 3. Decode claims
    let claims: Record<string, unknown>;
    try {
      claims = JSON.parse(base64urlDecode(payloadB64));
    } catch {
      return { valid: false, error: OPAQUE_INVALID_ATTESTATION, debug: 'Invalid JWT payload' };
    }

    // 4. Check expiry
    const now = Math.floor(Date.now() / 1000);
    if (typeof claims.exp === 'number' && claims.exp < now) {
      return { valid: false, error: OPAQUE_INVALID_ATTESTATION, debug: 'Attestation has expired' };
    }

    // Audit-3 H-2: validate iat — reject tokens with missing, future, or
    // implausibly old iat values.
    if (typeof claims.iat !== 'number') {
      return {
        valid: false,
        error: OPAQUE_INVALID_ATTESTATION,
        debug: 'Missing iat claim',
      };
    }

    if (claims.iat > now + MAX_CLOCK_SKEW_SECONDS) {
      return {
        valid: false,
        error: OPAQUE_INVALID_ATTESTATION,
        debug: `iat is in the future: ${claims.iat} > ${now} + ${MAX_CLOCK_SKEW_SECONDS}`,
      };
    }

    if (claims.iat < now - ATTESTATION_TTL_SECONDS - MAX_CLOCK_SKEW_SECONDS) {
      return {
        valid: false,
        error: OPAQUE_INVALID_ATTESTATION,
        debug: `iat too old: ${claims.iat} < ${now} - ${ATTESTATION_TTL_SECONDS} - ${MAX_CLOCK_SKEW_SECONDS}`,
      };
    }

    // 5. Check alg_version lock
    if (claims.alg_version !== PROXIMITY_ATTESTATION_ALG_VERSION) {
      return {
        valid: false,
        error: OPAQUE_INVALID_ATTESTATION,
        debug: `alg_version mismatch: ${claims.alg_version}`,
      };
    }

    // 6. Resolve public key — by (iss, kid) when available, else by iss
    //    + ACTIVE signing key as a fallback for in-flight rotations that
    //    issue tokens without a kid header (not expected post-fix, but
    //    harmless to accept).
    let pubKey = publicKeyPem;
    if (!pubKey) {
      const orgId = claims.iss as string;
      if (!orgId) {
        return {
          valid: false,
          error: OPAQUE_INVALID_ATTESTATION,
          debug: 'No issuer in claims and no public key provided',
        };
      }

      const signingKey = kid
        ? await this.prisma.signingKey.findFirst({
            where: {
              organizationId: orgId,
              keyId: kid,
              status: { in: ['ACTIVE', 'ROTATED'] },
            },
            select: { publicKey: true },
          })
        : await this.prisma.signingKey.findFirst({
            where: { organizationId: orgId, status: 'ACTIVE' },
            orderBy: { createdAt: 'desc' },
            select: { publicKey: true },
          });

      if (!signingKey) {
        return {
          valid: false,
          error: OPAQUE_INVALID_ATTESTATION,
          debug: 'No signing key found for issuer/kid',
        };
      }
      pubKey = signingKey.publicKey;
    }

    // 7. Verify signature. AUDIT-2 N-2: the signer prepends the ECDSA
    //    canonical domain prefix before the SHA-256 update, so we do the
    //    same on the verify side — otherwise valid signatures would
    //    spuriously fail and a signature produced over the unprefixed
    //    bytes (pre-N-2 code path) would still verify.
    const signingInput = `${headerB64}.${payloadB64}`;
    try {
      const verifier = createVerify('SHA256');
      verifier.update(ECDSA_CANONICAL_DOMAIN_PREFIX + signingInput, 'utf8');
      verifier.end();

      const valid = verifier.verify(pubKey, signatureB64, 'base64url');
      return valid
        ? { valid: true, claims }
        : { valid: false, error: OPAQUE_INVALID_ATTESTATION, debug: 'Invalid signature' };
    } catch {
      return {
        valid: false,
        error: OPAQUE_INVALID_ATTESTATION,
        debug: 'Signature verification failed',
      };
    }
  }
}
