import { describe, it, expect, beforeAll } from 'vitest';
import { generateKeyPairSync, createSign, createPublicKey } from 'node:crypto';
import { jwtVerify, exportJWK, importJWK } from 'jose';
import { buildIdToken } from '../oidc-id-token.js';

/**
 * Load-bearing test: an ID token built by buildIdToken (signed through the
 * signer's prefix-free JWS path) must verify with stock jose.jwtVerify
 * against the JWK derived from the signing key — the exact RP path.
 */

const KEY_ID = 'oidc-key-1';

// A real-crypto fake signer mirroring HttpEcdsaSigner.signJws / the live
// /v1/sign-ecdsa-jws endpoint: signs canonicalInput prefix-free, returns
// base64url IEEE P1363.
function makeSigner() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return {
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }) as string,
    signingService: {
      async signJws(_keyId: string, canonicalInput: string): Promise<string> {
        const s = createSign('SHA256');
        s.update(canonicalInput, 'utf8');
        s.end();
        return s.sign({ key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
      },
    },
  };
}

describe('buildIdToken (ADR-0003 Slice 3b)', () => {
  let signer: ReturnType<typeof makeSigner>;
  let key: Awaited<ReturnType<typeof importJWK>>;

  beforeAll(async () => {
    signer = makeSigner();
    const jwk = await exportJWK(createPublicKey(signer.publicKeyPem));
    key = await importJWK({ ...jwk, alg: 'ES256' }, 'ES256');
  });

  it('round-trips through jose.jwtVerify against the derived JWK', async () => {
    const authTime = new Date('2026-05-31T10:00:00Z');
    const token = await buildIdToken({
      issuer: 'https://id.qrauth.io',
      audience: 'phase1-test-client',
      subject: 'pairwise-sub-abc',
      nonce: 'n-123',
      authTime,
      signingKey: { keyId: KEY_ID },
      signingService: signer.signingService,
    });

    const { payload, protectedHeader } = await jwtVerify(token, key, {
      issuer: 'https://id.qrauth.io',
      audience: 'phase1-test-client',
    });

    expect(protectedHeader.alg).toBe('ES256');
    expect(protectedHeader.kid).toBe(KEY_ID);
    expect(protectedHeader.typ).toBe('JWT');
    expect(payload.sub).toBe('pairwise-sub-abc');
    expect(payload.nonce).toBe('n-123');
    expect(payload.auth_time).toBe(Math.floor(authTime.getTime() / 1000));
    expect(payload.acr).toBe('qrauth:living-code');
    expect(payload.amr).toEqual(['qrauth-living-code']);
    expect(typeof payload.iat).toBe('number');
    expect(payload.exp! - payload.iat!).toBe(3600);
  });

  it('omits the nonce claim entirely when none was supplied', async () => {
    const token = await buildIdToken({
      issuer: 'https://id.qrauth.io',
      audience: 'phase1-test-client',
      subject: 'pairwise-sub-abc',
      nonce: null,
      authTime: new Date(),
      signingKey: { keyId: KEY_ID },
      signingService: signer.signingService,
    });
    const { payload } = await jwtVerify(token, key, { issuer: 'https://id.qrauth.io', audience: 'phase1-test-client' });
    expect('nonce' in payload).toBe(false);
  });

  it('honors a custom expiresInSeconds', async () => {
    const token = await buildIdToken({
      issuer: 'https://id.qrauth.io',
      audience: 'phase1-test-client',
      subject: 's',
      nonce: null,
      authTime: new Date(),
      signingKey: { keyId: KEY_ID },
      signingService: signer.signingService,
      expiresInSeconds: 600,
    });
    const { payload } = await jwtVerify(token, key, { issuer: 'https://id.qrauth.io', audience: 'phase1-test-client' });
    expect(payload.exp! - payload.iat!).toBe(600);
  });
});
