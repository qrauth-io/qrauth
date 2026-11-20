import { compactVerify, decodeProtectedHeader, importSPKI } from 'jose';
import type { PrismaClient } from '@prisma/client';
import { OIDC_ID_TOKEN_SIGNING_ALGS, platformJwksKeyWhere } from './oidc-signing-keys.js';

/**
 * Verify an `id_token_hint` (RP-Initiated Logout 1.0 §2) against this OP's
 * own keys. Returns the token's `sub` and audience when the signature is
 * ours and the issuer matches; null otherwise.
 *
 * Expiry is deliberately NOT checked: the spec asks OPs to accept an expired
 * ID token as a hint, because sign-out normally happens long after sign-in.
 * The hint only names the session to end; it grants nothing.
 *
 * The key is looked up by `kid` among the keys JWKS currently publishes, and
 * the algorithm is pinned to the key row's, never read from the token alone.
 */
export interface IdTokenHint {
  sub: string;
  /** The client_id the token was issued to. */
  aud: string;
}

export async function verifyIdTokenHint(
  prisma: Pick<PrismaClient, 'signingKey'>,
  token: string,
  issuer: string,
): Promise<IdTokenHint | null> {
  try {
    const header = decodeProtectedHeader(token);
    const kid = header.kid;
    if (typeof kid !== 'string' || !kid) return null;

    const key = await prisma.signingKey.findFirst({
      where: { AND: [platformJwksKeyWhere(), { keyId: kid }] },
      select: { publicKey: true, algorithm: true },
    });
    if (!key) return null;
    const algorithm = OIDC_ID_TOKEN_SIGNING_ALGS.find((alg) => alg === key.algorithm);
    if (!algorithm || header.alg !== algorithm) return null;

    const publicKey = await importSPKI(key.publicKey, algorithm);
    const { payload } = await compactVerify(token, publicKey, { algorithms: [algorithm] });
    const claims = JSON.parse(new TextDecoder().decode(payload)) as Record<string, unknown>;

    if (claims.iss !== issuer) return null;
    if (typeof claims.sub !== 'string' || !claims.sub) return null;
    const aud = Array.isArray(claims.aud) ? claims.aud[0] : claims.aud;
    if (typeof aud !== 'string' || !aud) return null;

    return { sub: claims.sub, aud };
  } catch {
    // Malformed token, bad signature, unparseable payload: not a usable hint.
    return null;
  }
}
