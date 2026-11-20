import type { OidcClient, PrismaClient } from '@prisma/client';
import { hashString } from './crypto.js';
import { constantTimeEqualString } from './constant-time.js';

/**
 * OIDC client authentication (client_secret_basic / client_secret_post /
 * none), shared by /token and /revoke so the two endpoints cannot drift.
 *
 * A confidential client must present its secret; a public client must not
 * present one. The secret is compared as SHA-256 hashes in constant time.
 */
export type ClientAuthResult =
  | { ok: true; client: OidcClient }
  | { ok: false; description: string };

/** What the request presented, before anything is checked. */
export type PresentedCredentials =
  | { ok: true; clientId: string | undefined; clientSecret: string | undefined }
  | { ok: false; description: string };

/** Read client credentials from the Basic header (preferred) or the body. */
export function readClientCredentials(
  authorizationHeader: string | undefined,
  body: Record<string, unknown>,
): PresentedCredentials {
  // A JSON body can carry non-string values; only strings are credentials.
  let clientId = typeof body.client_id === 'string' ? body.client_id : undefined;
  let clientSecret = typeof body.client_secret === 'string' ? body.client_secret : undefined;
  if (authorizationHeader?.startsWith('Basic ')) {
    const decoded = Buffer.from(authorizationHeader.slice(6), 'base64').toString('utf-8');
    const idx = decoded.indexOf(':');
    if (idx > 0) {
      try {
        clientId = decodeURIComponent(decoded.slice(0, idx));
        clientSecret = decodeURIComponent(decoded.slice(idx + 1));
      } catch {
        // Malformed percent-encoding (RFC 6749 §2.3.1 requires it be valid).
        return { ok: false, description: 'malformed client credentials' };
      }
    }
  }
  return { ok: true, clientId, clientSecret };
}

export async function authenticateOidcClient(
  prisma: Pick<PrismaClient, 'oidcClient'>,
  authorizationHeader: string | undefined,
  body: Record<string, unknown>,
): Promise<ClientAuthResult> {
  const presented = readClientCredentials(authorizationHeader, body);
  if (!presented.ok) return presented;
  const { clientId, clientSecret } = presented;
  if (!clientId) return { ok: false, description: 'client authentication required' };

  const client = await prisma.oidcClient.findUnique({ where: { clientId } });
  if (!client) return { ok: false, description: 'unknown client' };

  if (client.clientSecretHash) {
    // Confidential client — a secret is required and must match.
    if (!clientSecret) return { ok: false, description: 'client secret required' };
    if (!constantTimeEqualString(hashString(clientSecret), client.clientSecretHash)) {
      return { ok: false, description: 'invalid client credentials' };
    }
  } else if (clientSecret) {
    // Public client must not present a secret.
    return { ok: false, description: 'this client is public; do not send a secret' };
  }

  return { ok: true, client };
}
