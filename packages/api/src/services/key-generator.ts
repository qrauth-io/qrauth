import { createPublicKey, type KeyObject } from 'node:crypto';

/**
 * Signer-side key generation (SIGNER_KEYGEN=signer).
 *
 * The signer generates the key pair, encrypts it under its own master key,
 * stores the envelope(s) and returns public material only. The API never
 * sees private key bytes and needs no SIGNER_MASTER_KEY on this path.
 */

export type KeyKind = 'es256-slhdsa' | 'rs256';

export interface GeneratedPublicKey {
  keyId: string;
  /** SPKI PEM of the ECDSA P-256 (es256-slhdsa) or RSA-2048 (rs256) key. */
  publicKey: string;
  /** Base64 of the 32-byte SLH-DSA-SHA2-128s public key (es256-slhdsa only). */
  slhdsaPublicKey?: string;
}

export interface KeyGenerator {
  generate(kind: KeyKind): Promise<GeneratedPublicKey>;
}

const KEY_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * Validate a signer response. A response that does not carry exactly the
 * expected public material is rejected, so no key row is ever written for
 * a key the signer did not produce in the expected form.
 */
export function parseGeneratedKey(kind: KeyKind, body: unknown): GeneratedPublicKey {
  if (!body || typeof body !== 'object') throw new Error('key generation: malformed response');
  const { keyId, publicKey, slhdsaPublicKey } = body as Record<string, unknown>;
  if (typeof keyId !== 'string' || !KEY_ID_RE.test(keyId)) {
    throw new Error('key generation: malformed keyId');
  }
  if (typeof publicKey !== 'string' || !publicKey.startsWith('-----BEGIN PUBLIC KEY-----')) {
    throw new Error('key generation: malformed publicKey');
  }
  let key;
  try {
    key = createPublicKey(publicKey);
  } catch {
    throw new Error('key generation: publicKey does not parse');
  }
  if (kind === 'es256-slhdsa') {
    if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
      throw new Error('key generation: expected an EC P-256 public key');
    }
    if (
      typeof slhdsaPublicKey !== 'string' ||
      Buffer.from(slhdsaPublicKey, 'base64').length !== 32 ||
      Buffer.from(slhdsaPublicKey, 'base64').toString('base64') !== slhdsaPublicKey
    ) {
      throw new Error('key generation: expected a canonical base64 32-byte SLH-DSA public key');
    }
    return { keyId, publicKey: canonicalPem(key), slhdsaPublicKey };
  }
  if (key.asymmetricKeyType !== 'rsa' || key.asymmetricKeyDetails?.modulusLength !== 2048) {
    throw new Error('key generation: expected an RSA-2048 public key');
  }
  if (slhdsaPublicKey !== undefined) {
    throw new Error('key generation: unexpected SLH-DSA key for rs256');
  }
  return { keyId, publicKey: canonicalPem(key) };
}

/** Re-export the parsed key, so only the SPKI PEM itself is ever stored. */
function canonicalPem(key: KeyObject): string {
  return key.export({ type: 'spki', format: 'pem' }).toString();
}

export class HttpKeyGenerator implements KeyGenerator {
  private baseUrl: string;

  constructor(
    baseUrl: string,
    private token: string,
    private timeoutMs: number = 30_000,
  ) {
    if (!baseUrl) throw new Error('HttpKeyGenerator: baseUrl is required');
    if (!token) throw new Error('HttpKeyGenerator: bearer token is required');
    this.baseUrl = baseUrl.replace(/\/+$/, '');
  }

  async generate(kind: KeyKind): Promise<GeneratedPublicKey> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await fetch(`${this.baseUrl}/v1/keys/generate`, {
        method: 'POST',
        signal: controller.signal,
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${this.token}` },
        body: JSON.stringify({ kind }),
      });
      if (!res.ok) {
        let detail = `${res.status} ${res.statusText}`;
        try {
          const body = (await res.json()) as { error?: string };
          if (body.error) detail = `${detail} (${body.error})`;
        } catch {
          // body was not JSON
        }
        throw new Error(`HttpKeyGenerator: /v1/keys/generate failed: ${detail}`);
      }
      return parseGeneratedKey(kind, await res.json());
    } finally {
      clearTimeout(timer);
    }
  }
}
