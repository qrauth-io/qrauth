import { describe, it, expect, beforeAll } from 'vitest';
import {
  generateKeyPairSync,
  createSign,
  createPublicKey,
  type KeyObject,
} from 'node:crypto';
import { jwtVerify, exportJWK, importJWK } from 'jose';
import type { RsaSigner } from '../rsa-signer/index.js';
import type { EcdsaSigner } from '../ecdsa-signer/index.js';
import type { SigningService as SigningServiceType } from '../signing.js';
import type { PrismaClient } from '@prisma/client';

/**
 * Unit tests for the RS256 JWS signing path (ADR-0003 Slice 7a):
 * `SigningService.signRsaJws` + `verifyRsaJws`.
 *
 * The load-bearing assertion is the `jose.jwtVerify` round-trip — it proves
 * the signer's RS256 output is a JWS that stock OIDC clients verify against
 * the JWKS-published RSA public key. RS256 is mandatory-to-implement per OIDC
 * Core §15.1. Cross-alg isolation pins that RS256 and ES256 never cross-verify.
 */

beforeAll(() => {
  process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
  process.env.REDIS_URL ??= 'redis://localhost:6379';
  process.env.JWT_SECRET ??= 'a'.repeat(32);
  process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);
});

/** A real-crypto fake RsaSigner holding an ephemeral RSA-2048 key. */
class FakeRsaSigner implements RsaSigner {
  readonly privateKeyPem: string;
  readonly publicKeyPem: string;
  readonly publicKey: KeyObject;

  constructor() {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    this.privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
    this.publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
    this.publicKey = publicKey;
  }

  async signJws(_keyId: string, canonicalInput: string): Promise<string> {
    const s = createSign('RSA-SHA256');
    s.update(canonicalInput, 'utf8');
    s.end();
    return s.sign(this.privateKeyPem).toString('base64url');
  }
}

/** A real-crypto fake EcdsaSigner for the cross-alg isolation test. */
class FakeEcdsaSigner implements EcdsaSigner {
  readonly privateKeyPem: string;
  constructor() {
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    this.privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
  }
  async signCanonical(_keyId: string, canonical: string): Promise<string> {
    const s = createSign('SHA256');
    s.update('qrauth:ecdsa-canonical:v1:' + canonical, 'utf8');
    s.end();
    return s.sign(this.privateKeyPem, 'base64');
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

const KEY_ID = 'oidc-rsa-key-1';

describe('SigningService.signRsaJws / verifyRsaJws (ADR-0003 Slice 7a)', () => {
  let SigningService: typeof SigningServiceType;
  let rsa: FakeRsaSigner;
  let service: SigningServiceType;

  const header = { alg: 'RS256', typ: 'JWT', kid: KEY_ID };
  const payload = { iss: 'https://id.qrauth.io', sub: 'pairwise-abc', aud: 'phase1-test-client' };
  const canonicalInput = `${b64url(header)}.${b64url(payload)}`;

  beforeAll(async () => {
    SigningService = (await import('../signing.js')).SigningService;
    rsa = new FakeRsaSigner();
    // Inject both signers; ecdsa unused here except in the cross-alg test.
    service = new SigningService({} as unknown as PrismaClient, new FakeEcdsaSigner(), rsa);
  });

  it('round-trips: signRsaJws output verifies under verifyRsaJws', async () => {
    const sig = await service.signRsaJws(KEY_ID, canonicalInput);
    expect(sig).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(Buffer.from(sig, 'base64url').length).toBe(256); // RSA-2048
    expect(await service.verifyRsaJws(rsa.publicKeyPem, canonicalInput, sig)).toBe(true);
  });

  it('verifyRsaJws rejects a tampered payload', async () => {
    const sig = await service.signRsaJws(KEY_ID, canonicalInput);
    const tampered = `${b64url(header)}.${b64url({ ...payload, sub: 'someone-else' })}`;
    expect(await service.verifyRsaJws(rsa.publicKeyPem, tampered, sig)).toBe(false);
  });

  it('load-bearing: jose.jwtVerify validates the compact RS256 JWS against the derived JWK', async () => {
    const sig = await service.signRsaJws(KEY_ID, canonicalInput);
    const compactJws = `${canonicalInput}.${sig}`;

    const jwk = await exportJWK(createPublicKey(rsa.publicKeyPem));
    const key = await importJWK({ ...jwk, alg: 'RS256' }, 'RS256');

    const { payload: verified, protectedHeader } = await jwtVerify(compactJws, key, {
      issuer: 'https://id.qrauth.io',
      audience: 'phase1-test-client',
    });
    expect(protectedHeader.alg).toBe('RS256');
    expect(protectedHeader.kid).toBe(KEY_ID);
    expect(verified.sub).toBe('pairwise-abc');
  });

  it('cross-alg isolation: an RS256 signature does NOT verify under the ES256 verifier', async () => {
    const rsaSig = await service.signRsaJws(KEY_ID, canonicalInput);
    // verifyJws is the ES256 path — an RS256 signature must not satisfy it.
    expect(await service.verifyJws(rsa.publicKeyPem, canonicalInput, rsaSig)).toBe(false);
  });

  it('cross-alg isolation: an ES256 signJws signature does NOT verify under verifyRsaJws', async () => {
    const ecSig = await service.signJws(KEY_ID, canonicalInput); // ES256 P1363
    expect(await service.verifyRsaJws(rsa.publicKeyPem, canonicalInput, ecSig)).toBe(false);
  });
});

describe('LocalRsaSigner.signJws input guard (ADR-0003 Slice 7a)', () => {
  it('rejects a canonicalInput that is not base64url.base64url', async () => {
    const { LocalRsaSigner } = await import('../rsa-signer/local.js');
    const local = new LocalRsaSigner();
    await expect(
      local.signJws(KEY_ID, 'qrauth:ecdsa-canonical:v1:eyJhIjoxfQ.eyJiIjoyfQ'),
    ).rejects.toThrow(/base64url\.base64url/);
    await expect(local.signJws(KEY_ID, 'single-segment')).rejects.toThrow(/base64url\.base64url/);
  });
});
