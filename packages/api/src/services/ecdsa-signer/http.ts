import type { EcdsaSigner } from './index.js';

/**
 * Remote ECDSA signer over HTTP (AUDIT-FINDING-016).
 *
 * Mirrors `HttpSlhDsaSigner` but talks to the signer service's
 * `/v1/sign-ecdsa` endpoint. The signer holds the encrypted PEM
 * envelopes; the API server holds nothing. A compromise of the API box
 * yields zero private-key material.
 *
 * Wire protocol:
 *
 *   POST {baseUrl}/v1/sign-ecdsa
 *     Headers: Authorization: Bearer {token}
 *     Body:    { "keyId": "<uuid>", "message": "<utf-8 canonical>" }
 *     200:     { "signature": "<base64 DER>" }
 *     401:     { "error": "unauthorized" }
 *     404:     { "error": "key_not_found" }
 */
export class HttpEcdsaSigner implements EcdsaSigner {
  constructor(
    private baseUrl: string,
    private token: string,
    private timeoutMs: number = 30_000,
  ) {
    if (!baseUrl) throw new Error('HttpEcdsaSigner: baseUrl is required');
    if (!token) throw new Error('HttpEcdsaSigner: bearer token is required');
    this.baseUrl = baseUrl.replace(/\/+$/, '');
  }

  async signCanonical(keyId: string, canonical: string): Promise<string> {
    const res = await this.fetch(`/v1/sign-ecdsa`, {
      method: 'POST',
      body: JSON.stringify({ keyId, message: canonical }),
    });
    const data = (await res.json()) as { signature: string };
    if (typeof data.signature !== 'string') {
      throw new Error('HttpEcdsaSigner: malformed sign response');
    }
    return data.signature;
  }

  /**
   * ADR-0003 Slice 3a: prefix-free JWS signing via the signer's
   * `/v1/sign-ecdsa-jws` endpoint. The canonical input travels as a plain
   * string — it is inherently `base64url.base64url`, which the signer
   * re-validates server-side before signing. Returns the base64url raw
   * `R||S` signature for direct use as a compact-JWS segment.
   */
  async signJws(keyId: string, canonicalInput: string): Promise<string> {
    const res = await this.fetch(`/v1/sign-ecdsa-jws`, {
      method: 'POST',
      body: JSON.stringify({ keyId, canonicalInput }),
    });
    const data = (await res.json()) as { signature: string };
    if (typeof data.signature !== 'string') {
      throw new Error('HttpEcdsaSigner: malformed sign-jws response');
    }
    return data.signature;
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
          // body wasn't JSON
        }
        throw new Error(`HttpEcdsaSigner: ${path} failed: ${detail}`);
      }
      return res;
    } finally {
      clearTimeout(timer);
    }
  }
}
