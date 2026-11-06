import type { RsaSigner } from './index.js';

/**
 * Remote RSA signer over HTTP (ADR-0003 Slice 7a).
 *
 * Mirrors `HttpEcdsaSigner` but talks to the signer service's
 * `/v1/sign-rsa-jws` endpoint. The signer holds the encrypted PEM envelopes;
 * the API server holds nothing. A compromise of the API box yields zero
 * RSA private-key material.
 *
 * Wire protocol:
 *
 *   POST {baseUrl}/v1/sign-rsa-jws
 *     Headers: Authorization: Bearer {token}
 *     Body:    { "keyId": "<uuid>", "canonicalInput": "<base64url.base64url>" }
 *     200:     { "signature": "<base64url>", "kid": "...", "alg": "RS256" }
 *     400:     { "error": "invalid_canonical_input" | "malformed_request" }
 *     401:     { "error": "unauthorized" }
 *     404:     { "error": "key_not_found" }
 */
export class HttpRsaSigner implements RsaSigner {
  constructor(
    private baseUrl: string,
    private token: string,
    private timeoutMs: number = 30_000,
  ) {
    if (!baseUrl) throw new Error('HttpRsaSigner: baseUrl is required');
    if (!token) throw new Error('HttpRsaSigner: bearer token is required');
    this.baseUrl = baseUrl.replace(/\/+$/, '');
  }

  async signJws(keyId: string, canonicalInput: string): Promise<string> {
    const res = await this.fetch(`/v1/sign-rsa-jws`, {
      method: 'POST',
      body: JSON.stringify({ keyId, canonicalInput }),
    });
    const data = (await res.json()) as { signature: string };
    if (typeof data.signature !== 'string') {
      throw new Error('HttpRsaSigner: malformed sign-rsa-jws response');
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
        throw new Error(`HttpRsaSigner: ${path} failed: ${detail}`);
      }
      return res;
    } finally {
      clearTimeout(timer);
    }
  }
}
