import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createSign, createVerify } from 'node:crypto';
import type { PrismaClient } from '@prisma/client';
import { config } from '../lib/config.js';
import { hashString } from '../lib/crypto.js';
import { GeoService } from './geo.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Default attestation TTL: 5 minutes. */
const ATTESTATION_TTL_SECONDS = 300;

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

const JWT_HEADER_B64 = base64url(JSON.stringify({ alg: 'ES256', typ: 'JWT' }));

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export class ProximityService {
  private geoService: GeoService;

  constructor(private prisma: PrismaClient) {
    this.geoService = new GeoService(prisma);
  }

  /**
   * Generate a signed ProximityAttestation JWT proving that a device at
   * (clientLat, clientLng) was near the QR code identified by `token`.
   */
  async createAttestation(
    token: string,
    clientLat: number,
    clientLng: number,
  ) {
    // 1. Look up the QR code
    const qrCode = await this.prisma.qRCode.findUnique({
      where: { token },
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
      clientLat,
      clientLng,
    );

    // 4. Build JWT claims
    const now = Math.floor(Date.now() / 1000);
    const claims = {
      sub: hashString(qrCode.token),
      iss: qrCode.organizationId,
      loc: qrCode.geoHash || this.geoService.encodeGeoHash(qrCode.latitude, qrCode.longitude),
      proximity: {
        matched: proximity.matched,
        distanceM: Math.round(proximity.distanceM),
        radiusM: qrCode.radiusM,
      },
      iat: now,
      exp: now + ATTESTATION_TTL_SECONDS,
    };

    // 5. Sign the JWT
    const payloadB64 = base64url(JSON.stringify(claims));
    const signingInput = `${JWT_HEADER_B64}.${payloadB64}`;

    const keyPath = join(config.kms.ecdsaPrivateKeyPath, `${signingKey.keyId}.pem`);
    let privateKey: string;
    try {
      privateKey = await readFile(keyPath, 'utf8');
    } catch {
      throw Object.assign(new Error('Signing key not available'), { statusCode: 500 });
    }

    const signer = createSign('SHA256');
    signer.update(signingInput, 'utf8');
    signer.end();
    const signatureB64 = signer.sign(privateKey, 'base64url');

    const jwt = `${signingInput}.${signatureB64}`;

    return {
      jwt,
      claims,
      publicKey: signingKey.publicKey,
      keyId: signingKey.keyId,
    };
  }

  /**
   * Verify a ProximityAttestation JWT.
   *
   * If `publicKeyPem` is provided, verification is fully offline (no DB lookup).
   * Otherwise the `iss` claim is used to fetch the org's public key from the DB.
   */
  async verifyAttestation(
    jwt: string,
    publicKeyPem?: string,
  ): Promise<{ valid: boolean; claims?: Record<string, unknown>; error?: string }> {
    // 1. Split JWT
    const parts = jwt.split('.');
    if (parts.length !== 3) {
      return { valid: false, error: 'Malformed JWT: expected 3 parts' };
    }

    const [headerB64, payloadB64, signatureB64] = parts;

    // 2. Decode and validate header
    let header: Record<string, unknown>;
    try {
      header = JSON.parse(base64urlDecode(headerB64));
    } catch {
      return { valid: false, error: 'Invalid JWT header' };
    }
    if (header.alg !== 'ES256') {
      return { valid: false, error: `Unsupported algorithm: ${header.alg}` };
    }

    // 3. Decode claims
    let claims: Record<string, unknown>;
    try {
      claims = JSON.parse(base64urlDecode(payloadB64));
    } catch {
      return { valid: false, error: 'Invalid JWT payload' };
    }

    // 4. Check expiry
    const now = Math.floor(Date.now() / 1000);
    if (typeof claims.exp === 'number' && claims.exp < now) {
      return { valid: false, error: 'Attestation has expired', claims };
    }

    // 5. Resolve public key
    let pubKey = publicKeyPem;
    if (!pubKey) {
      const orgId = claims.iss as string;
      if (!orgId) {
        return { valid: false, error: 'No issuer in claims and no public key provided' };
      }

      const signingKey = await this.prisma.signingKey.findFirst({
        where: { organizationId: orgId, status: 'ACTIVE' },
        orderBy: { createdAt: 'desc' },
        select: { publicKey: true },
      });

      if (!signingKey) {
        return { valid: false, error: 'No active signing key found for issuer' };
      }
      pubKey = signingKey.publicKey;
    }

    // 6. Verify signature
    const signingInput = `${headerB64}.${payloadB64}`;
    try {
      const verifier = createVerify('SHA256');
      verifier.update(signingInput, 'utf8');
      verifier.end();

      const valid = verifier.verify(pubKey, signatureB64, 'base64url');
      return valid
        ? { valid: true, claims }
        : { valid: false, error: 'Invalid signature', claims };
    } catch {
      return { valid: false, error: 'Signature verification failed' };
    }
  }
}
