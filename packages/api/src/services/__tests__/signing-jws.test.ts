import { describe, it, expect, beforeAll } from 'vitest';
import {
  generateKeyPairSync,
  createSign,
  createPublicKey,
  type KeyObject,
} from 'node:crypto';
import { jwtVerify, exportJWK, importJWK } from 'jose';
import type { EcdsaSigner } from '../ecdsa-signer/index.js';
import type { SigningService as SigningServiceType } from '../signing.js';
import type { PrismaClient } from '@prisma/client';

/**
 * Unit tests for the prefix-free JWS signing path (ADR-0003 Slice 3a):
 * `SigningService.signJws` + `verifyJws`.
 *
 * The load-bearing assertion is the `jose.jwtVerify` round-trip — it
 * proves the signer's output is a JWS that stock OIDC clients verify
 * against the JWKS-published public key. The cross-domain isolation tests
 * pin the cryptographic separation between the prefix-free JWS path and
 * the prefixed `signCanonical` path.
 */

const ECDSA_CANONICAL_DOMAIN_PREFIX = 'qrauth:ecdsa-canonical:v1:';

beforeAll(() => {
  // Mirror hybrid-signing.test.ts: ensure the api config loader doesn't
  // zod-throw during the transitive module import of signing.ts.
  process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
  process.env.REDIS_URL ??= 'redis://localhost:6379';
  process.env.JWT_SECRET ??= 'a'.repeat(32);
  process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);
});

/**
 * A real-crypto fake EcdsaSigner that holds an ephemeral P-256 key and
 * mirrors the two production backends byte-for-byte:
 *   - signCanonical → prefixed message, DER base64 (like LocalEcdsaSigner)
 *   - signJws       → prefix-free, IEEE P1363 raw R||S, base64url
 */
class FakeEcdsaSigner implements EcdsaSigner {
  readonly privateKeyPem: string;
  readonly publicKeyPem: string;
  readonly publicKey: KeyObject;

  constructor() {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    this.privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
    this.publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
    this.publicKey = publicKey;
  }

  async signCanonical(_keyId: string, canonical: string): Promise<string> {
    const s = createSign('SHA256');
    s.update(ECDSA_CANONICAL_DOMAIN_PREFIX + canonical, 'utf8');
    s.end();
    return s.sign(this.privateKeyPem, 'base64'); // DER base64
  }

  async signJws(_keyId: string, canonicalInput: string): Promise<string> {
    const s = createSign('SHA256');
    s.update(canonicalInput, 'utf8');
    s.end();
    return s.sign({ key: this.privateKeyPem, dsaEncoding: 'ieee-p1363' }).toString('base64url');
  }
}

function b64url(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url');
}

const KEY_ID = 'oidc-key-1';

describe('SigningService.signJws / verifyJws (ADR-0003 Slice 3a)', () => {
  let SigningService: typeof SigningServiceType;
  let signer: FakeEcdsaSigner;
  let service: SigningServiceType;

  // A representative JWS canonical input.
  const header = { alg: 'ES256', typ: 'JWT', kid: KEY_ID };
  const payload = { iss: 'https://id.qrauth.io', sub: 'pairwise-abc', aud: 'phase1-test-client' };
  const canonicalInput = `${b64url(header)}.${b64url(payload)}`;

  beforeAll(async () => {
    SigningService = (await import('../signing.js')).SigningService;
    signer = new FakeEcdsaSigner();
    service = new SigningService({} as unknown as PrismaClient, signer);
  });

  it('round-trips: signJws output verifies under verifyJws', async () => {
    const sig = await service.signJws(KEY_ID, canonicalInput);
    expect(sig).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(Buffer.from(sig, 'base64url').length).toBe(64);
    expect(await service.verifyJws(signer.publicKeyPem, canonicalInput, sig)).toBe(true);
  });

  it('verifyJws rejects a tampered payload', async () => {
    const sig = await service.signJws(KEY_ID, canonicalInput);
    const tampered = `${b64url(header)}.${b64url({ ...payload, sub: 'someone-else' })}`;
    expect(await service.verifyJws(signer.publicKeyPem, tampered, sig)).toBe(false);
  });

  it('load-bearing: jose.jwtVerify validates the compact JWS against the derived JWK', async () => {
    const sig = await service.signJws(KEY_ID, canonicalInput);
    const compactJws = `${canonicalInput}.${sig}`;

    // Derive the public JWK exactly as the JWKS endpoint publishes it,
    // then verify the token against it — the stock-OIDC-client path.
    const jwk = await exportJWK(createPublicKey(signer.publicKeyPem));
    const key = await importJWK({ ...jwk, alg: 'ES256' }, 'ES256');

    const { payload: verified, protectedHeader } = await jwtVerify(compactJws, key, {
      issuer: 'https://id.qrauth.io',
      audience: 'phase1-test-client',
    });
    expect(protectedHeader.alg).toBe('ES256');
    expect(protectedHeader.kid).toBe(KEY_ID);
    expect(verified.sub).toBe('pairwise-abc');
  });

  it('cross-domain isolation: a prefixed signCanonical signature does NOT verify under verifyJws', async () => {
    const prefixedSig = await service.signCanonical(KEY_ID, canonicalInput); // DER base64, prefixed
    // Re-encode the alphabet to base64url so the failure is the crypto,
    // not a charset rejection — proving the domain/format mismatch.
    const asB64url = Buffer.from(prefixedSig, 'base64').toString('base64url');
    expect(await service.verifyJws(signer.publicKeyPem, canonicalInput, asB64url)).toBe(false);
  });

  it('cross-domain isolation: a prefix-free signJws signature does NOT verify under verifyCanonical', async () => {
    const jwsSig = await service.signJws(KEY_ID, canonicalInput); // base64url P1363, prefix-free
    // verifyCanonical reconstructs the domain prefix and expects DER base64.
    const asB64 = Buffer.from(jwsSig, 'base64url').toString('base64');
    expect(service.verifyCanonical(signer.publicKeyPem, asB64, canonicalInput)).toBe(false);
  });
});

describe('LocalEcdsaSigner.signJws input guard (ADR-0003 Slice 3a)', () => {
  it('rejects a canonicalInput that is not base64url.base64url', async () => {
    const { LocalEcdsaSigner } = await import('../ecdsa-signer/local.js');
    const local = new LocalEcdsaSigner();
    await expect(local.signJws(KEY_ID, 'qrauth:ecdsa-canonical:v1:eyJhIjoxfQ.eyJiIjoyfQ')).rejects.toThrow(
      /base64url\.base64url/,
    );
    await expect(local.signJws(KEY_ID, 'single-segment')).rejects.toThrow(/base64url\.base64url/);
  });
});
