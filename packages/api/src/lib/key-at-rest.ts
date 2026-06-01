/**
 * At-rest encryption for on-disk key material (AUDIT-FINDING-016).
 *
 * Byte-identical to `packages/signer-service/src/key-at-rest.ts`. The
 * API server writes encrypted envelopes at key-generation time; the
 * signer service reads the same envelopes at sign time. Both processes
 * share the same master key via the `SIGNER_MASTER_KEY` env var.
 *
 * Envelope format:
 *   envelope = `qrauth-kek-v1\0${base64(iv)}\0${base64(ct)}\0${base64(tag)}`
 *
 * The tag prefix locks the format version. A future KMS-backed upgrade
 * is a clean cutover: replace the `loadMasterKey` body with an AWS KMS
 * `Decrypt` / Vault `transit/decrypt` call and bump the tag.
 */
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const FORMAT_TAG = 'qrauth-kek-v1';
const ALG = 'aes-256-gcm' as const;
const IV_BYTES = 12;
const KEY_BYTES = 32;

let cachedMasterKey: Buffer | null = null;

export function loadMasterKey(): Buffer {
  if (cachedMasterKey) return cachedMasterKey;
  const raw = process.env.SIGNER_MASTER_KEY;
  if (raw) {
    const bytes = Buffer.from(raw, 'base64');
    if (bytes.length !== KEY_BYTES) {
      throw new Error(
        `SIGNER_MASTER_KEY must decode to ${KEY_BYTES} bytes (base64 of 32 random bytes). Got ${bytes.length}.`,
      );
    }
    cachedMasterKey = bytes;
    return bytes;
  }
  if (process.env.NODE_ENV === 'production') {
    throw new Error(
      'SIGNER_MASTER_KEY is required in production (AUDIT-FINDING-016). ' +
        'Generate with `openssl rand -base64 32` and mount via the same secret-management path as JWT_SECRET.',
    );
  }
  // Dev/test fallback. We warn so anyone accidentally hitting this
  // branch in a prod-shaped environment sees the signal.
  // eslint-disable-next-line no-console
  console.warn(
    '[api] SIGNER_MASTER_KEY not set; using per-process random key. ' +
      'Dev/test only — set SIGNER_MASTER_KEY in production (AUDIT-FINDING-016).',
  );
  cachedMasterKey = randomBytes(KEY_BYTES);
  return cachedMasterKey;
}

export function encryptAtRest(plaintext: Buffer): string {
  const key = loadMasterKey();
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALG, key, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [FORMAT_TAG, iv.toString('base64'), ct.toString('base64'), tag.toString('base64')].join('\0');
}

export function decryptAtRest(envelope: string): Buffer {
  if (!envelope.startsWith(FORMAT_TAG + '\0')) {
    throw new Error('Malformed at-rest envelope: missing format tag');
  }
  const parts = envelope.split('\0');
  if (parts.length !== 4) {
    throw new Error('Malformed at-rest envelope');
  }
  const [, ivB64, ctB64, tagB64] = parts;
  const iv = Buffer.from(ivB64, 'base64');
  const ct = Buffer.from(ctB64, 'base64');
  const tag = Buffer.from(tagB64, 'base64');
  const key = loadMasterKey();
  const decipher = createDecipheriv(ALG, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

/** Test-only helper. */
export function __resetMasterKeyCache(): void {
  cachedMasterKey = null;
}
