import { importSPKI, exportJWK, type JWK } from 'jose';

/**
 * OIDC Provider metadata helpers (ADR-0003, Phase 1 Slice 2).
 *
 * Pure functions that build the discovery document and convert stored
 * ES256 public keys to JWKs. Kept out of the route handler so the JWK
 * conversion can be unit-tested / round-tripped against the stored PEM.
 */

/**
 * Stable slug of the QRAuth Platform system org (provisioned by migration
 * 20260521120100_provision_qrauth_cli_app). The OP signs every ID token
 * with this org's ES256 SigningKey, and JWKS publishes only its keys —
 * one issuer, one key set (ADR-0003).
 */
export const QRAUTH_PLATFORM_ORG_SLUG = 'qrauth-platform';

/**
 * OIDC Discovery 1.0 §3 metadata document. Advertises the full Phase 1
 * endpoint surface even though /authorize, /token, /userinfo, /register are
 * not implemented until later slices — Discovery requires these fields, and
 * an RP fetching this sees the complete picture (it just can't complete a
 * flow yet). Field values are pinned by ADR-0003:
 *   - ES256 only (RS256 deferred)
 *   - pairwise subject identifiers
 *   - S256 PKCE only (plain rejected)
 */
export function buildDiscoveryDocument(issuer: string) {
  return {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    userinfo_endpoint: `${issuer}/userinfo`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    registration_endpoint: `${issuer}/register`,
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    subject_types_supported: ['pairwise'],
    id_token_signing_alg_values_supported: ['ES256'],
    token_endpoint_auth_methods_supported: [
      'client_secret_basic',
      'client_secret_post',
      'none',
    ],
    code_challenge_methods_supported: ['S256'],
    scopes_supported: [
      'openid',
      'profile',
      'email',
      'offline_access',
      'qrauth:device_trust',
      'qrauth:proximity',
      'qrauth:fraud_signals',
      'qrauth:auth_method',
    ],
    claims_supported: [
      'sub',
      'iss',
      'aud',
      'exp',
      'iat',
      'auth_time',
      'nonce',
      'acr',
      'amr',
      'email',
      'email_verified',
      'qrauth:device_trust',
      'qrauth:proximity_attested',
      'qrauth:proximity_geohash',
      'qrauth:proximity_distance_m',
      'qrauth:fraud_score',
      'qrauth:auth_method',
    ],
  } as const;
}

export type OidcDiscoveryDocument = ReturnType<typeof buildDiscoveryDocument>;

/**
 * Convert an EC P-256 public key (SPKI PEM, as stored in SigningKey.publicKey)
 * to a JWKS entry. Uses `jose` for the PEM→JWK conversion — never hand-rolled.
 * `kid` is the SigningKey row's keyId, which Slice 3 will set in the ID token
 * header so RPs select the matching JWK.
 */
export async function signingKeyToJwk(
  publicKeyPem: string,
  kid: string,
): Promise<JWK> {
  const key = await importSPKI(publicKeyPem, 'ES256');
  const jwk = await exportJWK(key);
  return {
    ...jwk,
    use: 'sig',
    alg: 'ES256',
    kid,
  };
}
