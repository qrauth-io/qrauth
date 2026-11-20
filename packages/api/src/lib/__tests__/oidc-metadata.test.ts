import { describe, it, expect } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { signingKeyToJwk, buildDiscoveryDocument } from '../oidc-metadata.js';

/**
 * Unit tests for the JWKS JWK conversion (ADR-0003 Slice 7b multi-alg) and the
 * discovery doc's advertised signing algs.
 */

function ecSpki(): string {
  const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return publicKey.export({ type: 'spki', format: 'pem' }) as string;
}

function rsaSpki(): string {
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return publicKey.export({ type: 'spki', format: 'pem' }) as string;
}

describe('signingKeyToJwk', () => {
  it('produces an ES256 EC JWK for an EC P-256 key (default alg)', async () => {
    const jwk = await signingKeyToJwk(ecSpki(), 'kid-ec');
    expect(jwk.kty).toBe('EC');
    expect(jwk.crv).toBe('P-256');
    expect(jwk.alg).toBe('ES256');
    expect(jwk.use).toBe('sig');
    expect(jwk.kid).toBe('kid-ec');
    expect(typeof jwk.x).toBe('string');
    expect(typeof jwk.y).toBe('string');
    expect('d' in jwk).toBe(false); // no private component
  });

  it('produces an ES256 EC JWK when ES256 is passed explicitly', async () => {
    const jwk = await signingKeyToJwk(ecSpki(), 'kid-ec2', 'ES256');
    expect(jwk.kty).toBe('EC');
    expect(jwk.alg).toBe('ES256');
  });

  it('produces an RS256 RSA JWK for an RSA key', async () => {
    const jwk = await signingKeyToJwk(rsaSpki(), 'kid-rsa', 'RS256');
    expect(jwk.kty).toBe('RSA');
    expect(jwk.alg).toBe('RS256');
    expect(jwk.use).toBe('sig');
    expect(jwk.kid).toBe('kid-rsa');
    expect(typeof jwk.n).toBe('string'); // modulus
    expect(typeof jwk.e).toBe('string'); // exponent
    expect('d' in jwk).toBe(false); // no private component
  });

  it('throws on an unsupported algorithm', async () => {
    await expect(signingKeyToJwk(ecSpki(), 'kid', 'HS256')).rejects.toThrow(/unsupported algorithm/);
  });
});

describe('buildDiscoveryDocument', () => {
  it('advertises both RS256 and ES256 (RS256 first), no registration_endpoint', () => {
    const doc = buildDiscoveryDocument('https://id.qrauth.io');
    expect(doc.id_token_signing_alg_values_supported).toEqual(['RS256', 'ES256']);
    expect('registration_endpoint' in doc).toBe(false);
  });

  it('advertises logout and revocation, authenticated like the token endpoint', () => {
    const doc = buildDiscoveryDocument('https://id.qrauth.io');
    expect(doc.end_session_endpoint).toBe('https://id.qrauth.io/logout');
    expect(doc.revocation_endpoint).toBe('https://id.qrauth.io/revoke');
    expect(doc.revocation_endpoint_auth_methods_supported).toEqual(doc.token_endpoint_auth_methods_supported);
  });

  it('advertises only scopes a client can be granted and claims that are returned (FINDING-030)', () => {
    const doc = buildDiscoveryDocument('https://id.qrauth.io');
    expect(doc.scopes_supported).toEqual(['openid', 'profile', 'email', 'offline_access', 'qrauth:auth_method']);
    expect(doc.claims_supported).toEqual([
      'sub', 'iss', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'acr', 'amr',
      'name', 'picture', 'email', 'email_verified', 'qrauth:auth_method',
    ]);
  });

  it('keeps every field the certified Basic OP and Config OP profiles rely on', () => {
    const doc = buildDiscoveryDocument('https://id.qrauth.io');
    expect(doc).toMatchObject({
      issuer: 'https://id.qrauth.io',
      authorization_endpoint: 'https://id.qrauth.io/authorize',
      token_endpoint: 'https://id.qrauth.io/token',
      userinfo_endpoint: 'https://id.qrauth.io/userinfo',
      jwks_uri: 'https://id.qrauth.io/.well-known/jwks.json',
      response_types_supported: ['code'],
      subject_types_supported: ['pairwise'],
      id_token_signing_alg_values_supported: ['RS256', 'ES256'],
    });
  });
});
