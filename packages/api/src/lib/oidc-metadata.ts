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
 * OIDC Discovery 1.0 §3 metadata document. Advertises the implemented Phase 1
 * endpoint surface (/authorize, /token, /userinfo + discovery/JWKS).
 * `registration_endpoint` is deliberately NOT advertised — DCR is Phase 2 and
 * /register is unimplemented; advertising it would imply support we lack.
 * Re-add it when DCR ships. Field values are pinned by ADR-0003:
 *   - RS256 (default) + ES256 (opt-in) — Slice 7b; RS256 is OIDC Core §15.1 mandatory
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
    // registration_endpoint is intentionally omitted: Dynamic Client
    // Registration (DCR) is Phase 2 work and /register is not implemented.
    // Advertising it before then would imply support we don't have (Config OP
    // warns, Dynamic OP hard-fails). Re-add this line when DCR ships in Phase 2.
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    subject_types_supported: ['pairwise'],
    // ADR-0003 Slice 7b: RS256 first (now the default, OIDC Core §15.1
    // mandatory baseline); ES256 remains for opt-in clients.
    id_token_signing_alg_values_supported: ['RS256', 'ES256'],
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
  algorithm: string = 'ES256',
): Promise<JWK> {
  // ADR-0003 Slice 7b: route by the SigningKey's algorithm. importSPKI parses
  // the SPKI PEM under the named alg and exportJWK emits the right key type —
  // EC (kty=EC, crv=P-256, x/y) for ES256, RSA (kty=RSA, n/e) for RS256 — so
  // the JWK shape follows automatically. Default 'ES256' preserves Slice 2
  // callers that passed only (pem, kid).
  if (algorithm !== 'ES256' && algorithm !== 'RS256') {
    throw new Error(`signingKeyToJwk: unsupported algorithm "${algorithm}"`);
  }
  const key = await importSPKI(publicKeyPem, algorithm);
  const jwk = await exportJWK(key);
  return {
    ...jwk,
    use: 'sig',
    alg: algorithm,
    kid,
  };
}
