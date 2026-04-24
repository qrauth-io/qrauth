import type { SlhDsaSigner } from './index.js';

/**
 * Remote SLH-DSA signer over HTTP.
 *
 * Talks to a `packages/signer-service/` instance running on a separate
 * host. The signer service holds the private key bytes; the API server
 * only ever sees signatures and public keys. A compromise of the API
 * server box yields zero key material — that's the point.
 *
 * Wire protocol:
 *
 *   POST {baseUrl}/v1/sign
 *     Headers: Authorization: Bearer {token}
 *     Body:    { "keyId": "<uuid>", "message": "<base64>" }
 *     200:     { "signature": "<base64>" }
 *     401:     { "error": "unauthorized" }
 *     404:     { "error": "key_not_found" }
 *
 *   GET  {baseUrl}/v1/keys/{keyId}/public
 *     Headers: Authorization: Bearer {token}
 *     200:     { "publicKey": "<base64>", "algorithm": "slh-dsa-sha2-128s" }
 *     404:     { "error": "key_not_found" }
 *
 * The bearer token is a shared secret pinned in env on both sides.
 * mTLS is the right answer for production hardening but adds operational
 * complexity (cert rotation, CA management) that isn't worth shipping in
 * the same patch as the signer split. Treat the shared-secret variant
 * as MVP and upgrade to mTLS once the topology is bedded in.
 *
 * Error semantics: this client throws on any non-200 response so the
 * caller (BatchSigner) treats signing failures uniformly. The error
 * message includes the HTTP status and any `error` string from the
 * response body so operators have something to grep for in logs.
 */
export class HttpSlhDsaSigner implements SlhDsaSigner {
  constructor(
    private baseUrl: string,
    private token: string,
    /** Optional request timeout in milliseconds. Default 30s — the
     *  signer service is on a private network so timeouts here mean
     *  something is genuinely wrong, not a slow user link. */
    private timeoutMs: number = 30_000,
  ) {
    if (!baseUrl) throw new Error('HttpSlhDsaSigner: baseUrl is required');
    if (!token) throw new Error('HttpSlhDsaSigner: bearer token is required');
    // Normalize trailing slash so the URL builder below is unambiguous.
    this.baseUrl = baseUrl.replace(/\/+$/, '');
  }

  async signRoot(keyId: string, message: Buffer): Promise<Buffer> {
    const res = await this.fetch(`/v1/sign`, {
      method: 'POST',
      body: JSON.stringify({
        keyId,
        message: message.toString('base64'),
      }),
    });
    const data = (await res.json()) as { signature: string };
    if (typeof data.signature !== 'string') {
      throw new Error('HttpSlhDsaSigner: malformed sign response (missing signature)');
    }
    return Buffer.from(data.signature, 'base64');
  }

  async getPublicKey(keyId: string): Promise<Buffer> {
    const res = await this.fetch(`/v1/keys/${encodeURIComponent(keyId)}/public`, {
      method: 'GET',
    });
    const data = (await res.json()) as { publicKey: string };
    if (typeof data.publicKey !== 'string') {
      throw new Error('HttpSlhDsaSigner: malformed pubkey response');
    }
    return Buffer.from(data.publicKey, 'base64');
  }

  private async fetch(path: string, init: RequestInit): Promise<Response> {
    const url = `${this.baseUrl}${path}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await fetch(url, {
        ...init,
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${this.token}`,
        },
      });
      if (!res.ok) {
        let detail = `${res.status} ${res.statusText}`;
        try {
          const body = (await res.json()) as { error?: string };
          if (body.error) detail = `${detail} (${body.error})`;
        } catch {
          // body wasn't JSON — fall through with the status line alone
        }
        throw new Error(`HttpSlhDsaSigner: ${path} failed: ${detail}`);
      }
      return res;
    } finally {
      clearTimeout(timer);
    }
  }
}
