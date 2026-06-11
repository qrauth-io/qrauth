import type { SigningService } from '../services/signing.js';

/**
 * OIDC ID token builder (ADR-0003 Slice 3b).
 *
 * Builds and signs a compact-serialized ES256 JWS ID token via the signer's
 * prefix-free JWS path (`SigningService.signJws`, Slice 3a) — never a local
 * PEM read. The signer returns the base64url IEEE P1363 signature; we
 * concatenate it as the third compact-JWS segment, yielding a token a stock
 * OIDC client verifies against the published JWKS by `kid`.
 *
 * Pure except for the single signer call: no DB, no clock reads beyond the
 * `now` injected by the caller's `Date` (passed implicitly via `Date.now()`
 * here is avoided — the caller controls time only through `authTime`; `iat`/
 * `exp` use the wall clock at build time, which is correct for issuance).
 */

const DEFAULT_EXPIRES_IN_SECONDS = 3600;

export interface BuildIdTokenArgs {
  issuer: string;
  audience: string; // OidcClient.clientId
  subject: string; // pairwise sub from computePairwiseSub
  nonce: string | null; // from OidcAuthCode.nonce — echoed only when present
  authTime: Date; // when the user actually authenticated (OP session start)
  signingKey: { keyId: string };
  /**
   * Signer wrapper. `signJws` (ES256) is always required; `signRsaJws` (RS256)
   * is only needed when `alg: 'RS256'` — hence Partial, so ES256-only callers
   * and test fakes still satisfy the type. ADR-0003 Slice 7b.
   */
  signingService: Pick<SigningService, 'signJws'> & Partial<Pick<SigningService, 'signRsaJws'>>;
  expiresInSeconds?: number;
  /**
   * ID-token JWS algorithm (OIDC Core §2 `id_token_signed_response_alg`).
   * Default 'ES256' preserves Slice 3b callers; 'RS256' (Slice 7b — now the
   * default for new clients) requires `signingService.signRsaJws`.
   */
  alg?: 'ES256' | 'RS256';
  /**
   * Authentication context class (OIDC Core §2). Slice 4 passes the value
   * derived from the real auth method (lib/oidc-auth-method.ts). Defaults to
   * the Phase-1 placeholder when omitted, so the Slice 3b builder behaviour is
   * preserved for callers that don't supply it.
   */
  acr?: string;
  /** Authentication methods reference (OIDC Core §2 / RFC 8176). See `acr`. */
  amr?: string[];
}

/** Phase-1 default authentication context — used when the caller omits acr/amr. */
const DEFAULT_ACR = 'qrauth:living-code';
const DEFAULT_AMR = ['qrauth-living-code'];

function base64urlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

/**
 * Build a signed compact-JWS ID token. Claims follow OIDC Core 1.0 §2:
 * `iss, aud, sub, exp, iat, auth_time` always; `nonce` only when the client
 * sent one. `acr`/`amr` come from the caller (Slice 4 derives them from the
 * real auth method); both fall back to Phase-1 placeholders when omitted.
 */
export async function buildIdToken(args: BuildIdTokenArgs): Promise<string> {
  const {
    issuer,
    audience,
    subject,
    nonce,
    authTime,
    signingKey,
    signingService,
    expiresInSeconds = DEFAULT_EXPIRES_IN_SECONDS,
    acr = DEFAULT_ACR,
    amr = DEFAULT_AMR,
    alg = 'ES256',
  } = args;

  const now = Math.floor(Date.now() / 1000);

  const header = { alg, typ: 'JWT', kid: signingKey.keyId };

  const payload: Record<string, unknown> = {
    iss: issuer,
    aud: audience,
    sub: subject,
    exp: now + expiresInSeconds,
    iat: now,
    auth_time: Math.floor(authTime.getTime() / 1000),
    // Slice 4: real authentication context / methods derived from the user's
    // auth method (lib/oidc-auth-method.ts), passed in by /token. Falls back to
    // the Phase-1 placeholder defaults when the caller omits them.
    acr,
    amr,
  };

  // Echo `nonce` only when the client supplied one (OIDC Core §3.1.3.6).
  if (nonce !== null) {
    payload.nonce = nonce;
  }

  const canonicalInput = `${base64urlJson(header)}.${base64urlJson(payload)}`;
  let signature: string;
  if (alg === 'RS256') {
    if (!signingService.signRsaJws) {
      throw new Error('buildIdToken: alg=RS256 requires a signingService with signRsaJws');
    }
    signature = await signingService.signRsaJws(signingKey.keyId, canonicalInput);
  } else {
    signature = await signingService.signJws(signingKey.keyId, canonicalInput);
  }
  return `${canonicalInput}.${signature}`;
}
