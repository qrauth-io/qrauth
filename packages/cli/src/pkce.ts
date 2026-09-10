import { createHash, randomBytes } from 'node:crypto';

export interface Pkce {
  codeVerifier: string;
  codeChallenge: string;
}

/**
 * Generate a PKCE pair (RFC 7636, S256). The verifier is 32 random bytes
 * base64url-encoded (43 ASCII chars); the challenge is the base64url SHA-256 of
 * the verifier. The server recomputes the challenge identically in
 * `verifyCodeChallenge` (sha256 of the verifier as ASCII → base64url).
 */
export function generatePkce(): Pkce {
  const codeVerifier = randomBytes(32).toString('base64url');
  const codeChallenge = createHash('sha256').update(codeVerifier, 'ascii').digest('base64url');
  return { codeVerifier, codeChallenge };
}
