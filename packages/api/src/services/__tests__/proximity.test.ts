import { describe, it, expect, vi } from 'vitest';
import { createSign, generateKeyPairSync } from 'node:crypto';

import {
  ProximityService,
  PROXIMITY_ATTESTATION_ALG_VERSION,
  OPAQUE_INVALID_ATTESTATION,
} from '../proximity.js';

// Byte-identical to the constant in services/proximity.ts (ALGORITHM.md §12).
const ECDSA_CANONICAL_DOMAIN_PREFIX = 'qrauth:ecdsa-canonical:v1:';

const keypair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const PUBLIC_PEM = keypair.publicKey.export({ type: 'spki', format: 'pem' }) as string;

// A signingService stub that signs PREFIX + signingInput with the test EC key
// (exactly what the real EcdsaSigner backend does), returning base64 DER.
function makeSigningService(privateKey = keypair.privateKey) {
  return {
    signCanonical: vi.fn(async (_keyId: string, input: string) =>
      createSign('SHA256').update(ECDSA_CANONICAL_DOMAIN_PREFIX + input).sign(privateKey, 'base64'),
    ),
  } as any;
}

function activeGeoQr(over: Record<string, unknown> = {}) {
  return {
    id: 'qr_1',
    token: 'tok_1',
    latitude: 37.9838,
    longitude: 23.7275,
    radiusM: 50,
    geoHash: 'swbb5p0',
    status: 'ACTIVE',
    organizationId: 'org_1',
    ...over,
  };
}

function prismaWith(qr: any, signingKey: any = { id: 'sk_1', keyId: 'kid-1', publicKey: PUBLIC_PEM }) {
  return {
    qRCode: { findUnique: vi.fn(async () => qr) },
    signingKey: { findFirst: vi.fn(async () => signingKey) },
  } as any;
}

const baseInput = {
  token: 'tok_1',
  clientLat: 37.9838,
  clientLng: 23.7275,
  rpId: 'rp.example.com',
  deviceFingerprint: 'fp-123',
};

// --- manual JWT helpers for verify-only edge cases --------------------------
function b64url(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}
function buildJwt(
  header: Record<string, unknown>,
  claims: Record<string, unknown>,
  privateKey = keypair.privateKey,
): string {
  const signingInput = `${b64url(header)}.${b64url(claims)}`;
  const sig = createSign('SHA256')
    .update(ECDSA_CANONICAL_DOMAIN_PREFIX + signingInput)
    .sign(privateKey)
    .toString('base64url');
  return `${signingInput}.${sig}`;
}
function validHeader() {
  return { alg: 'ES256', typ: 'JWT', kid: 'kid-1' };
}
function validClaims(over: Record<string, unknown> = {}) {
  const now = Math.floor(Date.now() / 1000);
  return {
    sub: 'subhash',
    iss: 'org_1',
    aud: 'rp.example.com',
    device: 'devhash',
    alg_version: PROXIMITY_ATTESTATION_ALG_VERSION,
    loc: 'swbb5p0',
    proximity: { matched: true, distanceM: 0, radiusM: 50 },
    iat: now,
    exp: now + 300,
    ...over,
  };
}

describe('ProximityService.createAttestation', () => {
  it('mints a verifiable JWT for a geo-enabled active QR (round-trip)', async () => {
    const svc = new ProximityService(prismaWith(activeGeoQr()), makeSigningService());

    const att = await svc.createAttestation(baseInput);
    expect(att.jwt.split('.')).toHaveLength(3);
    expect(att.keyId).toBe('kid-1');

    const verified = await svc.verifyAttestation(att.jwt, PUBLIC_PEM);
    expect(verified.valid).toBe(true);
    expect(verified.claims?.iss).toBe('org_1');
    expect(verified.claims?.aud).toBe('rp.example.com');
  });

  it('sets a 300-second TTL (exp = iat + 300)', async () => {
    const svc = new ProximityService(prismaWith(activeGeoQr()), makeSigningService());
    const att = await svc.createAttestation(baseInput);
    expect(att.claims.exp - att.claims.iat).toBe(300);
  });

  it('marks proximity matched within the radius and unmatched far away', async () => {
    const svc = new ProximityService(prismaWith(activeGeoQr()), makeSigningService());

    const near = await svc.createAttestation(baseInput);
    expect(near.claims.proximity.matched).toBe(true);

    const far = await svc.createAttestation({ ...baseInput, clientLat: 40.7128, clientLng: -74.006 });
    expect(far.claims.proximity.matched).toBe(false);
    expect(far.claims.proximity.distanceM).toBeGreaterThan(50);
  });

  it('throws 404 when the QR code does not exist', async () => {
    const svc = new ProximityService(prismaWith(null), makeSigningService());
    await expect(svc.createAttestation(baseInput)).rejects.toMatchObject({ statusCode: 404 });
  });

  it('throws 410 when the QR code is not ACTIVE', async () => {
    const svc = new ProximityService(prismaWith(activeGeoQr({ status: 'REVOKED' })), makeSigningService());
    await expect(svc.createAttestation(baseInput)).rejects.toMatchObject({ statusCode: 410 });
  });

  it('throws 400 when the QR code has no registered location', async () => {
    const svc = new ProximityService(
      prismaWith(activeGeoQr({ latitude: null, longitude: null })),
      makeSigningService(),
    );
    await expect(svc.createAttestation(baseInput)).rejects.toMatchObject({ statusCode: 400 });
  });

  it('throws 500 when the org has no active signing key', async () => {
    const svc = new ProximityService(prismaWith(activeGeoQr(), null), makeSigningService());
    await expect(svc.createAttestation(baseInput)).rejects.toMatchObject({ statusCode: 500 });
  });

  it('throws 500 when the signer is unavailable', async () => {
    const signing = makeSigningService();
    signing.signCanonical.mockRejectedValueOnce(new Error('signer down'));
    const svc = new ProximityService(prismaWith(activeGeoQr()), signing);
    await expect(svc.createAttestation(baseInput)).rejects.toMatchObject({ statusCode: 500 });
  });
});

describe('ProximityService.verifyAttestation', () => {
  const svc = new ProximityService(prismaWith(activeGeoQr()), makeSigningService());

  it('accepts a well-formed token signed by the resolved key', async () => {
    const result = await svc.verifyAttestation(buildJwt(validHeader(), validClaims()), PUBLIC_PEM);
    expect(result.valid).toBe(true);
  });

  it('rejects a structurally malformed JWT', async () => {
    const result = await svc.verifyAttestation('only.two', PUBLIC_PEM);
    expect(result).toMatchObject({ valid: false, error: OPAQUE_INVALID_ATTESTATION });
  });

  it('rejects a non-ES256 algorithm header', async () => {
    const result = await svc.verifyAttestation(
      buildJwt({ ...validHeader(), alg: 'HS256' }, validClaims()),
      PUBLIC_PEM,
    );
    expect(result.valid).toBe(false);
  });

  it('rejects a wrong typ header', async () => {
    const result = await svc.verifyAttestation(
      buildJwt({ ...validHeader(), typ: 'NOTJWT' }, validClaims()),
      PUBLIC_PEM,
    );
    expect(result.valid).toBe(false);
  });

  it('rejects an expired token', async () => {
    const now = Math.floor(Date.now() / 1000);
    const result = await svc.verifyAttestation(
      buildJwt(validHeader(), validClaims({ iat: now - 20, exp: now - 10 })),
      PUBLIC_PEM,
    );
    expect(result.valid).toBe(false);
  });

  it('rejects a missing iat claim', async () => {
    const claims = validClaims();
    delete (claims as Record<string, unknown>).iat;
    const result = await svc.verifyAttestation(buildJwt(validHeader(), claims), PUBLIC_PEM);
    expect(result.valid).toBe(false);
  });

  it('rejects an iat too far in the future', async () => {
    const now = Math.floor(Date.now() / 1000);
    const result = await svc.verifyAttestation(
      buildJwt(validHeader(), validClaims({ iat: now + 120 })),
      PUBLIC_PEM,
    );
    expect(result.valid).toBe(false);
  });

  it('rejects an implausibly old iat', async () => {
    const now = Math.floor(Date.now() / 1000);
    const result = await svc.verifyAttestation(
      buildJwt(validHeader(), validClaims({ iat: now - 1000, exp: now + 300 })),
      PUBLIC_PEM,
    );
    expect(result.valid).toBe(false);
  });

  it('rejects an alg_version mismatch', async () => {
    const result = await svc.verifyAttestation(
      buildJwt(validHeader(), validClaims({ alg_version: 'proximity-mldsa-v9' })),
      PUBLIC_PEM,
    );
    expect(result.valid).toBe(false);
  });

  it('rejects a signature made with a different key', async () => {
    const other = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const forged = buildJwt(validHeader(), validClaims(), other.privateKey);
    const result = await svc.verifyAttestation(forged, PUBLIC_PEM);
    expect(result.valid).toBe(false);
  });

  it('resolves the public key from the DB by (iss, kid) when no PEM is supplied', async () => {
    const result = await svc.verifyAttestation(buildJwt(validHeader(), validClaims()));
    expect(result.valid).toBe(true);
  });

  it('rejects when no PEM is supplied and the token carries no issuer', async () => {
    const claims = validClaims();
    delete (claims as Record<string, unknown>).iss;
    const result = await svc.verifyAttestation(buildJwt(validHeader(), claims));
    expect(result.valid).toBe(false);
  });
});
